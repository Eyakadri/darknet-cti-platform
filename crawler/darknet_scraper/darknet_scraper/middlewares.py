import logging
import time
from typing import Optional, Deque
from collections import deque

# Scrapy and Twisted imports
from scrapy.downloadermiddlewares.retry import RetryMiddleware
from twisted.internet.error import TimeoutError, DNSLookupError, ConnectionRefusedError
from scrapy.exceptions import IgnoreRequest
from scrapy.http import HtmlResponse

# Selenium imports (for the new middleware )
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import WebDriverException, TimeoutException

# Project's custom module imports
from .state_manager import StateManager
from .session_manager import SessionManager
from .tor_manager import TorManager

logger = logging.getLogger(__name__)

class CustomTorProxyMiddleware:
    """
    Forces all outgoing HTTP(S) requests through the configured Privoxy/Tor proxy.

    Settings (with defaults in parentheses):
      TOR_PROXY_HOST (127.0.0.1)
      TOR_PROXY_PORT (8118)
      TOR_PROXY_ENABLED (True)
    """
    def __init__(self, proxy_host: str = '127.0.0.1', proxy_port: int = 8118, enabled: bool = True):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.enabled = enabled
        logger.info(
            f"CustomTorProxyMiddleware initialized (enabled={self.enabled}) -> http://{self.proxy_host}:{self.proxy_port}" )

    @classmethod
    def from_crawler(cls, crawler):  # type: ignore
        settings = crawler.settings
        return cls(
            proxy_host=settings.get('TOR_PROXY_HOST', '127.0.0.1'),
            proxy_port=settings.getint('TOR_PROXY_PORT', 8118),
            enabled=settings.getbool('TOR_PROXY_ENABLED', True)
        )

    def process_request(self, request, spider):  # type: ignore
        if not self.enabled:
            return None
        request.meta['proxy'] = f"http://{self.proxy_host}:{self.proxy_port}"
        return None

class SeleniumMiddleware:
    """
    Downloader middleware leveraging Selenium (Firefox) to render JavaScript-heavy
    pages. Activated via request.meta['use_selenium'].

    Improvements over previous version:
      * Driver reuse pool (reduces startup overhead).
      * Configurable headless mode & proxy via Scrapy settings.
      * Graceful error handling with selective retry allowance.
      * Site-specific wait strategies pluggable via registry.
      * Optional max render wait & post-load settle delay.

    Settings (names + defaults):
      SELENIUM_ENABLED (True)
      SELENIUM_HEADLESS (True)
      SELENIUM_MAX_DRIVERS (2)
      SELENIUM_RENDER_TIMEOUT (60)
      SELENIUM_POST_LOAD_SLEEP (3)
      TOR_PROXY_HOST (127.0.0.1)
      TOR_PROXY_PORT (8118)
    """

    def __init__(self,
                 enabled: bool = True,
                 headless: bool = True,
                 max_drivers: int = 2,
                 render_timeout: int = 60,
                 post_load_sleep: float = 3.0,
                 proxy_host: str = '127.0.0.1',
                 proxy_port: int = 8118):
        self.enabled = enabled
        self.headless = headless
        self.max_drivers = max_drivers
        self.render_timeout = render_timeout
        self.post_load_sleep = post_load_sleep
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self._driver_pool: Deque[webdriver.Firefox] = deque()
        self._in_use = 0
        # Domain-specific custom wait registry (domain substring -> callable)
        self.custom_wait_strategies = {
            'santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion': self._wait_cl0p_queue
        }
        logger.info(
            f"SeleniumMiddleware initialized enabled={self.enabled} headless={self.headless} max_drivers={self.max_drivers}")

    @classmethod
    def from_crawler(cls, crawler):  # type: ignore
        settings = crawler.settings
        return cls(
            enabled=settings.getbool('SELENIUM_ENABLED', True),
            headless=settings.getbool('SELENIUM_HEADLESS', True),
            max_drivers=settings.getint('SELENIUM_MAX_DRIVERS', 2),
            render_timeout=settings.getint('SELENIUM_RENDER_TIMEOUT', 60),
            post_load_sleep=settings.getfloat('SELENIUM_POST_LOAD_SLEEP', 3.0),
            proxy_host=settings.get('TOR_PROXY_HOST', '127.0.0.1'),
            proxy_port=settings.getint('TOR_PROXY_PORT', 8118)
        )

    # -------------------- Driver Management -------------------- #
    def _build_driver(self) -> webdriver.Firefox:
        opts = FirefoxOptions()
        if self.headless:
            opts.add_argument('--headless')
        # Proxy prefs (Privoxy + Tor)
        opts.set_preference('network.proxy.type', 1)
        opts.set_preference('network.proxy.http', self.proxy_host)
        opts.set_preference('network.proxy.http_port', self.proxy_port)
        opts.set_preference('network.proxy.ssl', self.proxy_host)
        opts.set_preference('network.proxy.ssl_port', self.proxy_port)
        opts.set_preference('network.proxy.socks_remote_dns', True)
        # Lighter footprint
        opts.set_preference('browser.cache.disk.enable', False)
        opts.set_preference('browser.cache.memory.enable', False)
        opts.set_preference('privacy.trackingprotection.enabled', True)
        try:
            driver = webdriver.Firefox(options=opts)
            driver.set_page_load_timeout(self.render_timeout)
            return driver
        except WebDriverException as e:
            logger.error(f"Failed to start Firefox driver: {e}")
            raise

    def _acquire_driver(self) -> webdriver.Firefox:
        if self._driver_pool:
            driver = self._driver_pool.popleft()
            self._in_use += 1
            return driver
        if self._in_use < self.max_drivers:
            driver = self._build_driver()
            self._in_use += 1
            return driver
        # If all drivers busy & pool empty, build a temporary one (will be closed after use)
        logger.debug("Driver pool exhausted; creating temporary driver")
        return self._build_driver()

    def _release_driver(self, driver: webdriver.Firefox, reusable: bool = True):
        try:
            if reusable and self._in_use <= self.max_drivers:
                self._driver_pool.append(driver)
            else:
                driver.quit()
        except Exception:
            pass
        finally:
            if self._in_use > 0:
                self._in_use -= 1

    def close_all(self):
        while self._driver_pool:
            try:
                self._driver_pool.popleft().quit()
            except Exception:
                pass

    # -------------------- Custom Wait Strategies -------------------- #
    def _wait_cl0p_queue(self, driver: webdriver.Firefox):
        logger.info("CL0P site detected, waiting for queue redirect...")
        try:
            WebDriverWait(driver, self.render_timeout).until_not(EC.title_contains("Access Queue"))
            logger.info("Queue passed. Content loaded.")
        except TimeoutException:
            logger.warning("Timeout while waiting for CL0P queue redirect; proceeding anyway.")

    def _apply_custom_wait(self, url: str, driver: webdriver.Firefox):
        for key, func in self.custom_wait_strategies.items():
            if key in url:
                func(driver)
                break

    # -------------------- Scrapy Hooks -------------------- #
    def process_request(self, request, spider):  # type: ignore
        if not self.enabled or not request.meta.get('use_selenium'):
            return None

        driver: Optional[webdriver.Firefox] = None
        temp_driver = False
        try:
            driver = self._acquire_driver()
            temp_driver = driver not in self._driver_pool and self._in_use > self.max_drivers
            logger.info(f"[Selenium] Fetching {request.url}")
            driver.get(request.url)

            # Domain-specific waits
            self._apply_custom_wait(request.url, driver)

            # Allow dynamic JS content to settle
            if self.post_load_sleep > 0:
                time.sleep(self.post_load_sleep)

            body = driver.page_source
            final_url = driver.current_url
            return HtmlResponse(final_url, body=body, encoding='utf-8', request=request)
        except TimeoutException as e:
            logger.warning(f"Timeout loading {request.url}: {e}")
            return None
        except WebDriverException as e:
            logger.error(f"WebDriver error for {request.url}: {e}")
            # Invalidate this driver instance
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass
            return None
        except Exception as e:
            logger.error(f"Unexpected Selenium failure {request.url}: {e}")
            return None
        finally:
            if driver:
                # Release driver back to pool unless temp or fatal error occurred
                try:
                    self._release_driver(driver, reusable=not temp_driver)
                except Exception:
                    pass

    def spider_closed(self, spider):  # type: ignore
        self.close_all()


class StateCheckMiddleware:
    """
    Delta-crawl middleware: skips further processing if fetched content hasn't changed.

    Workflow:
      1. Spider (or other component) computes content hash & stores in request.meta['content_hash'].
      2. After response download, we compare with persisted hash in Redis.
      3. If identical, raise IgnoreRequest to stop pipelines/parsers.
    """
    def __init__(self, settings):
        self.state_manager = StateManager(settings)
        self.enabled = settings.getbool('DELTA_CRAWL_ENABLED', True)
        self.update_on_unchanged = settings.getbool('DELTA_UPDATE_ON_EQUAL', False)
        if self.enabled:
            logger.info("StateCheckMiddleware active (delta crawl ON)")

    @classmethod
    def from_crawler(cls, crawler):  # type: ignore
        return cls(crawler.settings)

    def process_response(self, request, response, spider):  # type: ignore
        if not self.enabled:
            return response
        if response.status != 200 or not response.body:
            return response

        new_hash = response.meta.get('content_hash')
        if not new_hash:
            return response

        stored_hash = self.state_manager.get_stored_hash(response.url)
        if stored_hash == new_hash:
            if self.update_on_unchanged:
                # Touch state to refresh TTL (if TTL added later)
                self.state_manager.update_crawl_state(response.url, new_hash)
            logger.info(f"Δ Unchanged -> skip: {response.url}")
            raise IgnoreRequest(f"Unchanged: {response.url}")

        # Store new hash for future comparisons
        self.state_manager.update_crawl_state(response.url, new_hash)
        return response


class TorRetryMiddleware(RetryMiddleware):
    """
    Custom retry middleware for Tor-specific failures.
    If a request fails multiple times, it asks the TorManager extension
    to request a new circuit (IP address).
    """
    MAX_FAILURES_PER_REQUEST = 3

    def _get_tor_manager(self, crawler):
        # This is the correct syntax.
        return crawler.extensions[TorManager]

    def _retry(self, request, reason, spider):
        """Overridden retry method to include circuit refresh logic."""
        retry_request = super()._retry(request, reason, spider)
        if not retry_request:
            return None

        failure_count = retry_request.meta.get('failure_count', 0) + 1
        retry_request.meta['failure_count'] = failure_count
        logger.info(f"Failure #{failure_count} for <{request.url}> (Reason: {reason}).")

        if failure_count >= self.MAX_FAILURES_PER_REQUEST:
            logger.warning(f"Reached {self.MAX_FAILURES_PER_REQUEST} failures for <{request.url}>. Requesting new Tor circuit.")
            tor_manager = self._get_tor_manager(spider.crawler)
            if tor_manager:
                tor_manager.get_new_circuit()
            retry_request.meta['failure_count'] = 0
        
        return retry_request
