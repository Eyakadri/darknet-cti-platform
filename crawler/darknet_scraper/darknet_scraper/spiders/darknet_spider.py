# crawler/darknet_scraper/darknet_scraper/spiders/darknet_spider.py

import scrapy
import hashlib
from datetime import datetime
from urllib.parse import urlparse
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
        Parses pages that contain lists of links (e.g., a forum's thread list).
        Its job is to find content links and pagination links and follow them.
        """
        site_config = response.meta['site_config']
        rules = site_config.get('rules', {})

        # 1. Find and follow links to the actual content pages
        follow_selector = rules.get('follow_links')
        if follow_selector:
            content_links = response.css(follow_selector + "::attr(href)").getall()
            self.logger.info(f"Found {len(content_links)} content links on {response.url}")
            for link in content_links:
                yield response.follow(
                    link, 
                    callback=self.parse_item_page,  # Use the item parser for these links
                    meta={'site_config': site_config}
                )

        # 2. Find and follow the "next page" link for pagination
        pagination_selector = rules.get('pagination')
        if pagination_selector:
            next_page_link = response.css(pagination_selector + "::attr(href)").get()
            if next_page_link:
                self.logger.info(f"Following pagination link to next page from {response.url}")
                yield response.follow(
                    next_page_link, 
                    callback=self.parse_list_page,  # The next page is also a list page
                    meta={'site_config': site_config}
                )

    def parse_item_page(self, response):
        """
        Parses the final content page, extracts data into a CtiItem, and yields it.
        """
        site_config = response.meta['site_config']
        rules = site_config.get('rules', {})
        self.logger.info(f"Parsing item page: {response.url}")

        item = CtiItem()
        item['url'] = response.url
        item['site_category'] = site_config.get('category', 'unknown')
        item['crawled_at'] = datetime.now().isoformat()
        item['raw_html'] = response.text
        
        # Use precise CSS selectors from rules, with fallbacks
        item['title'] = response.css(rules.get('post_title', 'title') + " ::text").get(default="").strip()
        item['author'] = response.css(rules.get('post_author', '') + " ::text").get(default="").strip()
        
        # For content, get the HTML block and clean it with BeautifulSoup
        content_html = response.css(rules.get('post_content', 'body')).get(default="")
        soup = BeautifulSoup(content_html, 'html.parser')
        text_content = soup.get_text(separator=' ', strip=True)
        item['content'] = text_content
        
        # Calculate hash and add it to both the item and the response meta
        content_hash = hashlib.sha256(text_content.encode('utf-8')).hexdigest()
        item['content_hash'] = content_hash
        response.meta['content_hash'] = content_hash  # For the StateCheckMiddleware

        # Only yield the item if it has some actual text content
        if text_content:
            yield item
        else:
            self.logger.warning(f"No text content found for item at {response.url}")

    def handle_error(self, failure):
        """
        Handles request errors.
        """
        self.logger.error(f"Request failed: {failure.request.url} - {failure.value}")

