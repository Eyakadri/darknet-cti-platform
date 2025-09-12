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

    def start_requests(self ):
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
        """
        Router: finds links to threads (item pages) and handles pagination.
        """
        site_config = response.meta['site_config']
        rules = site_config.get('rules', {})

        # 1. Find and follow links to thread/item pages
        follow_selector = rules.get('follow_links')
        if follow_selector:
            content_links = response.css(follow_selector + "::attr(href)").getall()
            self.logger.info(f"Found {len(content_links)} content links on {response.url}")
            for link in self.clean_links(content_links):
                yield response.follow(
                    link,
                    callback=self.parse_item_page,
                    meta={'site_config': site_config}
                )

        # 2. Handle pagination
        pagination_selector = rules.get('pagination')
        if pagination_selector:
            next_page_link = response.css(pagination_selector + "::attr(href)").get()
            if next_page_link:
                self.logger.info(f"Following pagination link to next page from {response.url}")
                yield response.follow(
                    next_page_link,
                    callback=self.parse_list_page,
                    meta={'site_config': site_config}
                )

    def parse_item_page(self, response):
        """
        Parses a thread/item page, extracting posts and comments.
        """
        site_config = response.meta['site_config']
        rules = site_config.get('rules', {})
        self.logger.info(f"Parsing item page: {response.url}")

        # Container selector
        post_container_selector = rules.get('post_container')
        if not post_container_selector:
            self.logger.error(f"No 'post_container' rule defined for {site_config['name']}")
            return

        posts = response.css(post_container_selector)
        if not posts:
            self.logger.warning(f"No posts found at {response.url}")
            return

        for post in posts:
            item = CtiItem()
            item['url'] = response.url
            item['site_category'] = site_config.get('category', 'unknown')
            item['crawled_at'] = datetime.now(timezone.utc).isoformat()

            # Author (safe lookup)
            author_selector = rules.get('post_author')
            author = post.css(author_selector + " ::text").get(default="").strip() if author_selector else ""
            item['author'] = author

            # Content (safe lookup)
            content_selector = rules.get('post_content')
            content_html = post.css(content_selector).get(default="") if content_selector else ""
            soup = BeautifulSoup(content_html, 'html.parser')
            text_content = soup.get_text(separator=' ', strip=True)
            item['content'] = text_content

            # Title: prefer thread title rule, fallback to <title>
            title_selector = rules.get('post_title')
            page_title = response.css(title_selector + " ::text").get(default="").strip() if title_selector else ""
            item['title'] = page_title or response.css('title::text').get(default="").strip()

            # Hash & raw HTML snippet
            item['content_hash'] = hashlib.sha256(text_content.encode('utf-8')).hexdigest() if text_content else ""
            item['raw_html'] = content_html

            if text_content:
                yield item

    def clean_links(self, raw_list):
        """
        Cleans and deduplicates a list of raw links.
        """
        cleaned = []
        for href in raw_list:
            if not href:
                continue
            link = href.strip()
            if not link or link.startswith('<'):
                continue

            # Handle encoded <a href=...> artifacts
            if '%3Ca%20href' in link.lower():
                decoded = unquote(link)
                m = re.search(r'href=["\']([^"\']+)["\']', decoded)
                if m:
                    link = m.group(1)
                else:
                    continue

            low = link.lower()
            if low.startswith(('#', 'javascript:', 'mailto:', 'xmpp:', 'tel:', 'data:')):
                continue

            scheme = urlparse(link).scheme
            if scheme and scheme not in ('http', 'https', ''):
                continue

            cleaned.append(link)

        # Deduplicate while preserving order
        seen = set()
        ordered = []
        for l in cleaned:
            if l not in seen:
                seen.add(l)
                ordered.append(l)
        return ordered

    def handle_error(self, failure):
        """
        Handles request errors.
        """
        self.logger.error(f"Request failed: {failure.request.url} - {failure.value}")
