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

        # --- Helper: date pattern extraction (basic, no external deps) ---
        def extract_date_from_text(text: str):
            """Attempt to find a plausible date string in free text and return ISO format if parsed.
            Supports formats like:
              2023-10-27, 2023/10/27
              27-10-2023, 27/10/2023
              October 27 2023, Oct 27, 2023, 27 October 2023
            Returns first successfully parsed date as string; else ''."""
            if not text:
                return ''
            month_names = (
                'January','February','March','April','May','June',
                'July','August','September','October','November','December'
            )
            month_abbr = tuple(m[:3] for m in month_names)
            patterns = [
                # ISO / Y-m-d
                (r'(20\d{2})[/-](0?[1-9]|1[0-2])[/-](0?[1-9]|[12]\d|3[01])', ['%Y-%m-%d','%Y-%m-%d']),
                # d-m-Y
                (r'(0?[1-9]|[12]\d|3[01])[/-](0?[1-9]|1[0-2])[/-](20\d{2})', ['%d-%m-%Y','%d-%m-%Y']),
                # Month d, Y  (October 7, 2023)
                (r'(' + '|'.join(month_names) + r'|' + '|'.join(month_abbr) + r')\s+(0?[1-9]|[12]\d|3[01]),?\s+(20\d{2})', []),
                # d Month Y  (7 October 2023)
                (r'(0?[1-9]|[12]\d|3[01])\s+(' + '|'.join(month_names) + r'|' + '|'.join(month_abbr) + r')\s+(20\d{2})', []),
            ]
            # Normalize whitespace
            snippet = ' '.join(text.split())[:1000]  # limit scan length
            for regex, fmts in patterns:
                m = re.search(regex, snippet, flags=re.IGNORECASE)
                if not m:
                    continue
                candidate = m.group(0)
                # Try dynamic format guesses
                trial_formats = []
                if fmts:
                    trial_formats.extend(fmts)
                # Add additional dynamic guesses
                trial_formats.extend([
                    '%Y-%m-%d','%Y/%m/%d','%d-%m-%Y','%d/%m/%Y',
                    '%B %d %Y','%b %d %Y','%B %d, %Y','%b %d, %Y',
                    '%d %B %Y','%d %b %Y'
                ])
                for fmt in trial_formats:
                    try:
                        dt = datetime.strptime(candidate.replace('/', '-').replace(',', ''), fmt)
                        return dt.date().isoformat()
                    except Exception:
                        continue
            return ''

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

        # Thread-level title (used for all posts) – try specific then fallbacks including meta og:title
        thread_title = ''
        title_sel = rules.get('thread_title') or rules.get('post_title')
        if title_sel:
            try:
                raw_title_bits = response.css(title_sel + "::text, " + title_sel + " ::text").getall()
                thread_title = (" ".join(t.strip() for t in raw_title_bits if t and t.strip()) or "").strip()
            except Exception:
                thread_title = ''
        if not thread_title:
            og_title = response.css("meta[property='og:title']::attr(content), meta[name='og:title']::attr(content)").get()
            if og_title:
                thread_title = og_title.strip()
        if not thread_title:
            thread_title = (response.css('h1::text, h1 ::text, h2::text').get(default="") or response.css('title::text').get(default="")).strip()
        if not thread_title:
            # As a last resort, derive from URL slug
            slug = urlparse(response.url).path.rstrip('/').split('/')[-1]
            thread_title = slug.replace('-', ' ').replace('_', ' ').title()

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
                # primary extraction
                post_date = node.css(date_sel + '::attr(datetime), ' + date_sel + '::text').get(default='').strip()
                # If we only captured a label like 'Date:' or very short token, attempt heuristic search
                if post_date.lower().rstrip(':').strip() in ('date', 'posted', '') or post_date.endswith(':'):
                    # Search inside node then entire page for a date pattern
                    search_scope = node.get() if hasattr(node, 'get') else ''
                    derived = extract_date_from_text(search_scope)
                    if not derived:
                        derived = extract_date_from_text(response.text)
                    if derived:
                        post_date = derived
                    else:
                        post_date = ''  # discard label
            if not post_date:
                # global heuristic fallback (single date per page) – acceptable for leak sites
                inferred_page_date = extract_date_from_text(response.text)
                if inferred_page_date:
                    post_date = inferred_page_date
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
                    # Convert relative links to absolute for downstream clarity
                    try:
                        href_full = response.urljoin(href)
                    except Exception:
                        href_full = href
                    links.append(href_full)
            for img in soup.find_all('img', src=True):
                src = img['src'].strip()
                if src:
                    try:
                        src_full = response.urljoin(src)
                    except Exception:
                        src_full = src
                    images.append(src_full)
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
