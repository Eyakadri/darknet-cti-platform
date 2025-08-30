"""
Main spider for crawling darknet sites for CTI intelligence.
"""

import scrapy
import hashlib
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Add parent directory to path to import our modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))

from config.settings import TARGET_SITES
from producer.scrapy_project.cti_crawler.items import CtiItem


class DarknetSpider(scrapy.Spider):
    """Spider for crawling darknet forums and marketplaces."""
    
    name = 'darknet'
    allowed_domains = []
    start_urls = TARGET_SITES
    
    # Custom settings
    custom_settings = {
        'DOWNLOAD_DELAY': 5,
        'RANDOMIZE_DOWNLOAD_DELAY': 0.5,
        'CONCURRENT_REQUESTS': 1,
        'CONCURRENT_REQUESTS_PER_DOMAIN': 1,
        'AUTOTHROTTLE_ENABLED': True,
        'AUTOTHROTTLE_START_DELAY': 3,
        'AUTOTHROTTLE_MAX_DELAY': 15,
        'AUTOTHROTTLE_TARGET_CONCURRENCY': 1.0,
    }
    
    def __init__(self, *args, **kwargs):
        super(DarknetSpider, self).__init__(*args, **kwargs)
        
        # Extract domains from start URLs for allowed_domains
        for url in self.start_urls:
            domain = urlparse(url).netloc
            if domain and domain not in self.allowed_domains:
                self.allowed_domains.append(domain)
        
        self.logger.info(f"Spider initialized with {len(self.start_urls)} start URLs")
        self.logger.info(f"Allowed domains: {self.allowed_domains}")
    
    def start_requests(self):
        """Generate initial requests."""
        for url in self.start_urls:
            yield scrapy.Request(
                url=url,
                callback=self.parse,
                errback=self.handle_error,
                meta={
                    'site_category': self.categorize_site(url),
                    'depth': 0
                }
            )
    
    def parse(self, response):
        """Parse main page and extract content."""
        try:
            # Extract basic information
            item = self.extract_basic_info(response)
            
            if item:
                yield item
            
            # Follow links to other pages (limited depth)
            depth = response.meta.get('depth', 0)
            if depth < 3:  # Limit crawling depth
                for link in self.extract_links(response):
                    yield scrapy.Request(
                        url=link,
                        callback=self.parse,
                        errback=self.handle_error,
                        meta={
                            'site_category': response.meta.get('site_category'),
                            'depth': depth + 1
                        }
                    )
        
        except Exception as e:
            self.logger.error(f"Error parsing {response.url}: {e}")
    
    def extract_basic_info(self, response):
        """Extract basic information from the page."""
        try:
            # Parse HTML with BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Extract text content
            text_content = soup.get_text()
            
            # Clean up text
            lines = (line.strip() for line in text_content.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text_content = ' '.join(chunk for chunk in chunks if chunk)
            
            # Skip if content is too short (likely error page or empty)
            if len(text_content) < 100:
                self.logger.info(f"Skipping short content: {response.url}")
                return None
            
            # Calculate content hash
            content_hash = hashlib.sha256(text_content.encode('utf-8')).hexdigest()
            
            # Create item
            item = CtiItem()
            item['url'] = response.url
            item['title'] = self.extract_title(soup)
            item['content'] = text_content
            item['raw_html'] = response.text
            item['crawled_at'] = datetime.now().isoformat()
            item['content_hash'] = content_hash
            item['site_category'] = response.meta.get('site_category', 'unknown')
            item['response_time'] = response.meta.get('download_latency', 0)
            item['content_length'] = len(text_content)
            
            # Extract additional metadata
            item['author'] = self.extract_author(soup)
            item['post_date'] = self.extract_post_date(soup)
            item['thread_id'] = self.extract_thread_id(response.url)
            item['post_id'] = self.extract_post_id(response.url)
            item['links'] = self.extract_internal_links(soup, response.url)
            item['images'] = self.extract_images(soup, response.url)
            
            self.logger.info(f"Extracted item from {response.url} ({len(text_content)} chars)")
            return item
            
        except Exception as e:
            self.logger.error(f"Error extracting info from {response.url}: {e}")
            return None
    
    def extract_title(self, soup):
        """Extract page title."""
        title_tag = soup.find('title')
        if title_tag:
            return title_tag.get_text().strip()
        
        # Try h1 tag
        h1_tag = soup.find('h1')
        if h1_tag:
            return h1_tag.get_text().strip()
        
        return "No title"
    
    def extract_author(self, soup):
        """Extract author information."""
        # Common patterns for author extraction
        author_patterns = [
            {'class': re.compile(r'.*author.*', re.I)},
            {'class': re.compile(r'.*user.*', re.I)},
            {'class': re.compile(r'.*poster.*', re.I)},
        ]
        
        for pattern in author_patterns:
            author_elem = soup.find(['div', 'span', 'p'], pattern)
            if author_elem:
                return author_elem.get_text().strip()
        
        return None
    
    def extract_post_date(self, soup):
        """Extract post date."""
        # Common patterns for date extraction
        date_patterns = [
            {'class': re.compile(r'.*date.*', re.I)},
            {'class': re.compile(r'.*time.*', re.I)},
            {'class': re.compile(r'.*posted.*', re.I)},
        ]
        
        for pattern in date_patterns:
            date_elem = soup.find(['div', 'span', 'time'], pattern)
            if date_elem:
                return date_elem.get_text().strip()
        
        return None
    
    def extract_thread_id(self, url):
        """Extract thread ID from URL."""
        # Common patterns for thread IDs
        patterns = [
            r'thread[_-]?(\d+)',
            r't[_-]?(\d+)',
            r'topic[_-]?(\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url, re.I)
            if match:
                return match.group(1)
        
        return None
    
    def extract_post_id(self, url):
        """Extract post ID from URL."""
        # Common patterns for post IDs
        patterns = [
            r'post[_-]?(\d+)',
            r'p[_-]?(\d+)',
            r'msg[_-]?(\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url, re.I)
            if match:
                return match.group(1)
        
        return None
    
    def extract_links(self, response):
        """Extract links for further crawling."""
        links = []
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(response.url, href)
            
            # Only follow links within allowed domains
            if self.is_allowed_domain(full_url):
                # Filter out common non-content links
                if not self.is_excluded_link(href):
                    links.append(full_url)
        
        # Limit number of links to prevent explosion
        return links[:20]
    
    def extract_internal_links(self, soup, base_url):
        """Extract internal links for metadata."""
        links = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            links.append({
                'url': full_url,
                'text': link.get_text().strip()
            })
        return links[:10]  # Limit for storage
    
    def extract_images(self, soup, base_url):
        """Extract image URLs."""
        images = []
        for img in soup.find_all('img', src=True):
            src = img['src']
            full_url = urljoin(base_url, src)
            images.append({
                'url': full_url,
                'alt': img.get('alt', ''),
                'title': img.get('title', '')
            })
        return images[:5]  # Limit for storage
    
    def is_allowed_domain(self, url):
        """Check if URL domain is allowed."""
        domain = urlparse(url).netloc
        return domain in self.allowed_domains
    
    def is_excluded_link(self, href):
        """Check if link should be excluded from crawling."""
        excluded_patterns = [
            r'logout',
            r'login',
            r'register',
            r'search',
            r'rss',
            r'feed',
            r'\.css$',
            r'\.js$',
            r'\.jpg$',
            r'\.png$',
            r'\.gif$',
            r'\.pdf$',
        ]
        
        for pattern in excluded_patterns:
            if re.search(pattern, href, re.I):
                return True
        
        return False
    
    def categorize_site(self, url):
        """Categorize site based on URL patterns."""
        url_lower = url.lower()
        
        if 'forum' in url_lower or 'dread' in url_lower:
            return 'forum'
        elif 'market' in url_lower or 'shop' in url_lower:
            return 'marketplace'
        elif 'leak' in url_lower or 'dump' in url_lower:
            return 'data_leak'
        else:
            return 'unknown'
    
    def handle_error(self, failure):
        """Handle request errors."""
        self.logger.error(f"Request failed: {failure.request.url} - {failure.value}")
        
        # You could implement additional error handling here
        # such as notifying the Tor manager about failures

