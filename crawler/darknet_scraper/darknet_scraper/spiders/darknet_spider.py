# crawler/darknet_scraper/darknet_scraper/spiders/darknet_spider.py

import scrapy
import hashlib
import re
from datetime import datetime
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup

from ..items import CtiItem

class DarknetSpider(scrapy.Spider):
    """
    A config-driven spider that crawls darknet sites for CTI.
    Its behavior is controlled by the 'target_sites' list in the project settings.
    """
    name = 'darknet'

    @classmethod
    def from_crawler(cls, crawler, *args, **kwargs):
        spider = super(DarknetSpider, cls).from_crawler(crawler, *args, **kwargs)
        # Load the structured list of site objects from settings
        spider.target_sites = crawler.settings.getlist('TARGET_SITES')
        # Dynamically build the list of allowed domains from the config
        spider.allowed_domains = []
        from urllib.parse import urlparse
        for site in spider.target_sites:
            domain = urlparse(site['url']).netloc
            if domain and domain not in spider.allowed_domains:
                spider.allowed_domains.append(domain)
        spider.logger.info(f"Spider initialized for {len(spider.target_sites)} sites.")
        spider.logger.info(f"Allowed domains: {spider.allowed_domains}")
        return spider

    def start_requests(self):
        self.logger.info("Starting requests based on target_sites configuration...")
        for site_config in self.target_sites:
            self.logger.info(f"Generating initial request for: {site_config['name']}")
            meta = {'site_config': site_config}

            # Flag selenium usage per-site
            if site_config.get('use_selenium', False):
                self.logger.info(f"'{site_config['name']}' requires Selenium. Setting flag.")
                meta['use_selenium'] = True

            yield scrapy.Request(
                url=site_config['url'],
                callback=self.parse_list_page,
                errback=self.handle_error,
                meta=meta,
                dont_filter=True  # allow revisits if same URL appears in list
            )

    def parse_list_page(self, response):
        """Parses pages that contain lists of links (e.g., a forum's thread list).
        Its job is to find content links and pagination links and follow them."""
        site_config = response.meta['site_config']
        rules = site_config.get('rules', {})

        # --- Helper utilities (kept inside method to avoid polluting class scope) ---
        def split_selectors(sel: str):
            """Split a comma-delimited CSS selector string into clean individual selectors.
            Handles embedded commas by simple split – acceptable for current config usage."""
            return [s.strip() for s in sel.split(',') if s.strip()]

        def clean_links(raw_list):
            cleaned = []
            for href in raw_list:
                if not href:
                    continue
                link = href.strip()
                if not link:
                    continue
                # Detect cases where the entire <a ...> tag or its percent-encoded form slipped in
                if link.startswith('<'):
                    continue
                if '%3Ca%20href' in link.lower():  # encoded "<a href"
                    # Try to recover the actual URL from the encoded anchor fragment
                    decoded = unquote(link)
                    # Extract href value if present
                    m = re.search(r'href=["\']([^"\']+)["\']', decoded)
                    if m:
                        link = m.group(1)
                    else:
                        # Skip if we can't recover
                        continue
                # Discard javascript/mail/etc schemes or intra-page anchors
                low = link.lower()
                if low.startswith(('#', 'javascript:', 'mailto:', 'xmpp:', 'tel:', 'data:')):
                    continue
                scheme = urlparse(link).scheme
                if scheme and scheme not in ('http', 'https'):
                    continue
                cleaned.append(link)
            # Dedupe preserving order
            seen = set()
            ordered = []
            for l in cleaned:
                if l not in seen:
                    seen.add(l)
                    ordered.append(l)
            return ordered

        # 1. Find and follow links to the actual content pages
        follow_selector = rules.get('follow_links')
        if follow_selector:
            raw_links = []
            for sel in split_selectors(follow_selector):
                raw_links.extend(response.css(f"{sel}::attr(href)").getall())
            filtered_links = clean_links(raw_links)
            self.logger.info(f"Found {len(raw_links)} content link candidates on {response.url}")
            self.logger.info(f"Following {len(filtered_links)} cleaned content links on {response.url}")
            for link in filtered_links:
                child_meta = {'site_config': site_config}
                if 'use_selenium' in response.meta:
                    child_meta['use_selenium'] = response.meta['use_selenium']
                yield response.follow(
                    link,
                    callback=self.parse_item_page,
                    meta=child_meta
                )

        # 2. Find and follow the "next page" link for pagination
        pagination_selector = rules.get('pagination')
        if pagination_selector:
            candidates = []
            for sel in split_selectors(pagination_selector):
                candidates.extend(response.css(f"{sel}::attr(href)").getall())
            candidates.extend(response.css("a[rel='next']::attr(href)").getall())
            paginated = clean_links(candidates)
            next_page_link = paginated[0] if paginated else None
            if next_page_link:
                child_meta = {'site_config': site_config}
                if 'use_selenium' in response.meta:
                    child_meta['use_selenium'] = response.meta['use_selenium']
                self.logger.info(f"Following pagination link to next page from {response.url}")
                yield response.follow(
                    next_page_link,
                    callback=self.parse_list_page,
                    meta=child_meta
                )
            else:
                self.logger.debug(f"No valid pagination link found on {response.url} using selector(s): {pagination_selector}")


    def parse_item_page(self, response):
        """Parses a thread page and yields one item per individual post/comment."""
        site_config = response.meta['site_config']
        rules = site_config.get('rules', {})
        self.logger.info(f"Parsing thread page (per-post extraction): {response.url}")

        # Heuristic + config-based detection: if this is actually a forum index / list page, reroute.
        thread_url_markers = rules.get('thread_url_contains', [])  # list of substrings that indicate a thread
        if isinstance(thread_url_markers, str):
            thread_url_markers = [thread_url_markers]
        url_lower = response.url.lower()

        is_likely_thread = False
        if thread_url_markers:
            is_likely_thread = any(m.lower() in url_lower for m in thread_url_markers)
        else:
            # fallback heuristic: many XenForo thread pages contain 'threads/' or '.topic' etc.
            is_likely_thread = any(seg in url_lower for seg in ['threads/', 'thread/', 'topic/', '.topic'])

        # If URL path ends with pattern like '/forums/<slug>.<number>/' it's probably a forum node, not a thread
        path = urlparse(response.url).path
        forum_node_pattern = re.compile(r'/forums/[^/]+\.\d+/?$')
        if forum_node_pattern.match(path) and not is_likely_thread:
            self.logger.debug(f"Detected forum node page (not a thread): {response.url}. Re-routing to parse_list_page.")
            # Re-use same response content by scheduling a new parse_list_page call
            yield scrapy.Request(
                url=response.url,
                callback=self.parse_list_page,
                meta={'site_config': site_config, **{k: v for k, v in response.meta.items() if k != 'download_slot'}},
                dont_filter=True
            )
            return

        # Thread-level title (used for all posts) – try specific then fallbacks
        thread_title = ''
        title_sel = rules.get('thread_title') or rules.get('post_title')
        if title_sel:
            raw_title_bits = response.css(title_sel + "::text, " + title_sel + " ::text").getall()
            thread_title = (" ".join(t.strip() for t in raw_title_bits if t and t.strip()) or "").strip()
        if not thread_title:
            thread_title = (response.css('h1::text, h1 ::text, h2::text').get(default="") or response.css('title::text').get(default="")).strip()

        # Container selector for posts
        post_container_sel = rules.get('post_container') or '.message, .post'
        post_nodes = response.css(post_container_sel)
        if not post_nodes:
            self.logger.warning(f"No post containers found with selector '{post_container_sel}' on {response.url}. Falling back to whole page as one item.")
            # Instead of passing HtmlResponse directly (which lacks attrib/css expectations in loop)
            # create a lightweight wrapper list using the body selection to mimic an element.
            body_selection = response.css('body')
            if body_selection:
                post_nodes = body_selection
            else:
                # Final fallback: create a dummy object with required interface
                class DummyNode:
                    def __init__(self, html):
                        self._html = html
                        self.attrib = {}
                    def css(self, sel):
                        return []
                    def get(self):
                        return self._html
                post_nodes = [DummyNode(response.text)]

        # Optional sub-selectors inside each post
        author_sel = rules.get('post_author')
        content_sel = rules.get('post_content')
        date_sel = rules.get('post_date')
        post_id_sel = rules.get('post_id_attr')  # attribute-only extraction, e.g., 'data-content' or 'id'
        post_id_css = rules.get('post_id')       # css to extract id text if needed

        # Derive thread id from URL (simple heuristic) or config-specified selector
        thread_id = ''
        thread_id_sel = rules.get('thread_id')
        if thread_id_sel:
            thread_id = response.css(thread_id_sel + '::attr(id), ' + thread_id_sel + '::text').get(default='').strip()
        if not thread_id:
            # fallback: hash of base URL path (stable identifier)
            parsed_path = urlparse(response.url).path.rstrip('/')
            thread_id = hashlib.sha1(parsed_path.encode('utf-8')).hexdigest()[:16]

        for idx, node in enumerate(post_nodes, start=1):
            item = CtiItem()
            item['url'] = response.url
            item['site_category'] = site_config.get('category', 'unknown')
            item['crawled_at'] = datetime.now().isoformat()
            item['thread_id'] = thread_id
            item['title'] = thread_title

            # Extract per-post id
            post_id = ''
            if post_id_css:
                try:
                    post_id = node.css(post_id_css + '::attr(id), ' + post_id_css + '::text').get(default='').strip()
                except Exception:
                    post_id = ''
            if not post_id and post_id_sel and hasattr(node, 'attrib'):
                # if we have an attribute name, attempt to get it from container
                post_id = node.attrib.get(post_id_sel, '').strip()
            if not post_id:
                # fallback sequential
                post_id = f"{thread_id}-{idx}"  # stable within thread
            item['post_id'] = post_id

            # Author
            author_text = ''
            if author_sel:
                author_bits = node.css(author_sel + '::text, ' + author_sel + ' ::text').getall()
                author_text = (" ".join(a.strip() for a in author_bits if a and a.strip()) or '').strip()
            item['author'] = author_text

            # Date/time
            post_date = ''
            if date_sel:
                post_date = node.css(date_sel + '::attr(datetime), ' + date_sel + '::text').get(default='').strip()
            item['post_date'] = post_date

            # Content HTML extraction
            content_html = ''
            if content_sel:
                # If selector refers to nested element inside node
                inner = node.css(content_sel)
                if inner:
                    content_html = ''.join(inner.getall())
            if not content_html:
                # Heuristic fallback: capture full node HTML
                content_html = node.get() if hasattr(node, 'get') else ''

            # Parse text, extract links & images
            soup = BeautifulSoup(content_html or '', 'html.parser')
            # Remove quotes/blockquote if config wants (future enhancement)
            text_content = soup.get_text(separator=' ', strip=True)
            item['content'] = text_content
            item['raw_html'] = content_html

            # Links/images
            links = []
            images = []
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                if href and not href.startswith(('javascript:', 'mailto:')):
                    links.append(href)
            for img in soup.find_all('img', src=True):
                src = img['src'].strip()
                if src:
                    images.append(src)
            # Deduplicate
            item['links'] = list(dict.fromkeys(links))
            item['images'] = list(dict.fromkeys(images))

            # Content hash per post
            content_hash = hashlib.sha256(text_content.encode('utf-8')).hexdigest()
            item['content_hash'] = content_hash

            # Only yield meaningful posts
            if text_content:
                yield item
            else:
                self.logger.debug(f"Skipping empty post {post_id} on {response.url}")

    def handle_error(self, failure):
        """
        Handles request errors.
        """
        self.logger.error(f"Request failed: {failure.request.url} - {failure.value}")
