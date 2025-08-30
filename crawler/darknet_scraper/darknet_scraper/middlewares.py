# Scrapy middlewares for CTI crawler

import logging
import time
from scrapy.http import HtmlResponse
from scrapy.downloadermiddlewares.retry import RetryMiddleware
from twisted.internet.error import TimeoutError, DNSLookupError, ConnectionRefusedError
from urllib.parse import urlparse

# Import our modules
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from crawler.tor_manager import tor_manager
from crawler.state_manager import StateManager
from producer.session_manager import get_session_for_request

logger = logging.getLogger(__name__)


class TorProxyMiddleware:
    """Routes requests through Tor proxy and adds session cookies."""
    
    def __init__(self, tor_host='127.0.0.1', tor_port=9050):
        self.proxy_url = f'socks5://{tor_host}:{tor_port}'
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            tor_host=crawler.settings.get('TOR_PROXY_HOST', '127.0.0.1'),
            tor_port=crawler.settings.get('TOR_PROXY_PORT', 9050)
        )
    
    def process_request(self, request, spider):
        """Set proxy and session data for requests."""
        request.meta['proxy'] = self.proxy_url
        
        # Add session cookies and headers if available
        session_data = get_session_for_request(request.url)
        if session_data['cookies']:
            request.cookies.update(session_data['cookies'])
        if session_data['headers']:
            request.headers.update(session_data['headers'])
        
        return None


class StateCheckMiddleware:
    """Checks crawl state before processing requests."""
    
    def __init__(self, state_db_path):
        self.state_manager = StateManager(state_db_path)
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(crawler.settings.get('STATE_DB_PATH', 'data/crawler_state.db'))
    
    def process_request(self, request, spider):
        if not self.state_manager.should_crawl(request.url):
            logger.info(f"Skipping URL: {request.url}")
            return HtmlResponse(url=request.url, status=200, body=b'', encoding='utf-8')
        return None


class TorRetryMiddleware(RetryMiddleware):
    """Custom retry middleware for Tor-specific failures."""
    
    EXCEPTIONS_TO_RETRY = (TimeoutError, DNSLookupError, ConnectionRefusedError)
    
    def __init__(self, settings):
        super().__init__(settings)
        self.failure_count = 0
    
    def process_response(self, request, response, spider):
        if response.status in self.retry_http_codes:
            self.failure_count += 1
            if self.failure_count >= 3:
                tor_manager.get_new_circuit()
                self.failure_count = 0
                time.sleep(5)
            return self._retry(request, f"HTTP {response.status}", spider) or response
        
        if response.status == 200:
            self.failure_count = 0
        return response
    
    def process_exception(self, request, exception, spider):
        if isinstance(exception, self.EXCEPTIONS_TO_RETRY):
            self.failure_count += 1
            if self.failure_count >= 3:
                tor_manager.get_new_circuit()
                self.failure_count = 0
            return self._retry(request, exception, spider)
        return None

