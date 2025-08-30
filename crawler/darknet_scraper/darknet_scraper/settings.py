# Scrapy settings for cti_crawler project

BOT_NAME = 'cti_crawler'

SPIDER_MODULES = ['cti_crawler.spiders']
NEWSPIDER_MODULE = 'cti_crawler.spiders'

# Obey robots.txt rules
ROBOTSTXT_OBEY = False

# Configure a delay for requests for the same website (default: 0)
DOWNLOAD_DELAY = 3
RANDOMIZE_DOWNLOAD_DELAY = 0.5

# The download delay setting will honor only one of:
CONCURRENT_REQUESTS_PER_DOMAIN = 1
CONCURRENT_REQUESTS = 1

# Disable cookies (enabled by default)
COOKIES_ENABLED = False

# Disable Telnet Console (enabled by default)
TELNETCONSOLE_ENABLED = False

# Override the default request headers:
DEFAULT_REQUEST_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
}

# Enable or disable spider middlewares
SPIDER_MIDDLEWARES = {
    'cti_crawler.middlewares.TorProxyMiddleware': 350,
    'cti_crawler.middlewares.StateCheckMiddleware': 400,
}

# Enable or disable downloader middlewares
DOWNLOADER_MIDDLEWARES = {
    'cti_crawler.middlewares.TorProxyMiddleware': 350,
    'scrapy.downloadermiddlewares.retry.RetryMiddleware': 550,
    'cti_crawler.middlewares.TorRetryMiddleware': 560,
}

# Enable or disable extensions
EXTENSIONS = {
    'scrapy.extensions.telnet.TelnetConsole': None,
}

# Configure item pipelines
ITEM_PIPELINES = {
    'cti_crawler.pipelines.StateUpdatePipeline': 300,
    'cti_crawler.pipelines.RawDataStoragePipeline': 400,
}

# Enable and configure the AutoThrottle extension (disabled by default)
AUTOTHROTTLE_ENABLED = True
AUTOTHROTTLE_START_DELAY = 1
AUTOTHROTTLE_MAX_DELAY = 10
AUTOTHROTTLE_TARGET_CONCURRENCY = 1.0
AUTOTHROTTLE_DEBUG = False

# Enable and configure HTTP caching
HTTPCACHE_ENABLED = False

# Retry settings
RETRY_TIMES = 3
RETRY_HTTP_CODES = [500, 502, 503, 504, 408, 429, 403]

# Logging
LOG_LEVEL = 'INFO'

# Custom settings



# Tor proxy settings
TOR_PROXY_HOST = '127.0.0.1'
TOR_PROXY_PORT = 9050
