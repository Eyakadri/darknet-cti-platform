# Scrapy settings for darknet_scraper project

# ==============================================================================
#  START: LOAD CONFIG FROM YAML
# ==============================================================================
import yaml
import os

# This block reads your central config file and loads its values into Scrapy settings.
try:
    # Build the absolute path to the project's root directory
    # This assumes settings.py is at crawler/darknet_scraper/darknet_scraper/settings.py
    _project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
    _config_path = os.path.join(_project_root, 'config', 'crawler_config.yaml')

    with open(_config_path, 'r') as f:
        config = yaml.safe_load(f)

    # --- Load Scrapy Settings ---
    BOT_NAME = 'darknet_scraper' # Corrected bot name
    USER_AGENT = config['scrapy'].get('user_agent', BOT_NAME)
    DOWNLOAD_DELAY = config['scrapy'].get('download_delay', 3)
    RANDOMIZE_DOWNLOAD_DELAY = config['scrapy'].get('randomize_download_delay', True)
    CONCURRENT_REQUESTS = config['scrapy'].get('concurrent_requests', 1)
    CONCURRENT_REQUESTS_PER_DOMAIN = config['scrapy'].get('concurrent_requests', 1)
    RETRY_TIMES = config['scrapy'].get('retry_times', 3)
    RETRY_HTTP_CODES = config['scrapy'].get('retry_http_codes', [500, 502, 503, 504, 408, 429] )

    # --- Load Custom Application Settings ---
    TARGET_SITES = config.get('target_sites', [])

    # --- Selenium (optional block) ---
    _selenium_cfg = config.get('selenium', {})
    SELENIUM_ENABLED = _selenium_cfg.get('enabled', True)
    SELENIUM_HEADLESS = _selenium_cfg.get('headless', True)
    SELENIUM_MAX_DRIVERS = _selenium_cfg.get('max_drivers', 2)
    SELENIUM_RENDER_TIMEOUT = _selenium_cfg.get('render_timeout', 60)
    SELENIUM_POST_LOAD_SLEEP = _selenium_cfg.get('post_load_sleep', 3.0)

    # Tor settings
    TOR_PROXY_HOST = config['tor'].get('proxy_host', '127.0.0.1')
    TOR_PROXY_PORT = config['tor'].get('proxy_port', 9050)
    TOR_CONTROL_PORT = config['tor'].get('control_port', 9051)
    TOR_CONTROL_PASSWORD = config['tor'].get('control_password', None)

    # Redis settings for State Manager
    REDIS_HOST = config['redis'].get('host', '127.0.0.1')
    REDIS_PORT = config['redis'].get('port', 6379)
    REDIS_DB = config['redis'].get('db', 0)

    print("✅ Successfully loaded configuration from crawler_config.yaml")

except FileNotFoundError:
    print(f"❌ ERROR: Configuration file not found at '{_config_path}'. Using default Scrapy settings.")
    # Define fallback defaults if config is missing
    BOT_NAME = 'darknet_scraper'
    TARGET_SITES = []
    TOR_PROXY_HOST = '127.0.0.1'
    TOR_PROXY_PORT = 9050
except Exception as e:
    print(f"❌ ERROR: Could not load or parse configuration file. Error: {e}")

# ==============================================================================
#  END: LOAD CONFIG FROM YAML
# ==============================================================================


# --- Static Scrapy Settings ---

SPIDER_MODULES = ['darknet_scraper.spiders']
NEWSPIDER_MODULE = 'darknet_scraper.spiders'

# Obey robots.txt rules
ROBOTSTXT_OBEY = False

# Disable cookies (enabled by default)
COOKIES_ENABLED = False

# Disable Telnet Console (enabled by default)
TELNETCONSOLE_ENABLED = False

# Default request headers can remain, but User-Agent will be overridden by the config
DEFAULT_REQUEST_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
}

# Spider Middlewares
SPIDER_MIDDLEWARES = {
   'darknet_scraper.middlewares.StateCheckMiddleware': 400,
}

DOWNLOADER_MIDDLEWARES = {
   # This is our simple proxy middleware
   'darknet_scraper.middlewares.CustomTorProxyMiddleware': 100,
   
   # This is our NEW Selenium middleware
   'darknet_scraper.middlewares.SeleniumMiddleware': 543,
   
   # This is our existing retry middleware
   'scrapy.downloadermiddlewares.retry.RetryMiddleware': None,
   'darknet_scraper.middlewares.TorRetryMiddleware': 560,
}
# Extensions
EXTENSIONS = {
   'scrapy.extensions.telnet.TelnetConsole': None,
   'darknet_scraper.tor_manager.TorManager': 500,
}


# Item Pipelines
ITEM_PIPELINES = {
   'darknet_scraper.pipelines.DuplicatesPipeline': 100,
   'darknet_scraper.pipelines.StateUpdatePipeline': 200,
   'darknet_scraper.pipelines.RawDataStoragePipeline': 300,
}

RETRY_ENABLED = True
RETRY_TIMES = 3
RETRY_EXCEPTIONS = (
    TimeoutError,
    ConnectionRefusedError,
    IOError,
)

# AutoThrottle extension
AUTOTHROTTLE_ENABLED = True
AUTOTHROTTLE_START_DELAY = 1
AUTOTHROTTLE_MAX_DELAY = 10
AUTOTHROTTLE_TARGET_CONCURRENCY = 1.0
AUTOTHROTTLE_DEBUG = False

# HTTP caching
HTTPCACHE_ENABLED = False

# Logging
LOG_LEVEL = 'INFO'
