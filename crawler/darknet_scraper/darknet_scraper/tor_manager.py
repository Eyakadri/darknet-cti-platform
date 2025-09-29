import logging
import time
from stem import Signal
from stem.control import Controller
from scrapy import signals
from scrapy.exceptions import NotConfigured

logger = logging.getLogger(__name__)

class TorManager:
    """Scrapy extension wrapping Tor control port operations (NEWNYM, connect)."""
    def __init__(self, settings):
        if not settings.getbool('TOR_MANAGER_ENABLED', True):
            raise NotConfigured

        self.control_port = settings.getint('TOR_CONTROL_PORT')
        self.controller = None
        logger.info("TorManager extension initialized.")

    @classmethod
    def from_crawler(cls, crawler):
        manager = cls(crawler.settings)
        crawler.signals.connect(manager.spider_opened, signal=signals.spider_opened)
        crawler.signals.connect(manager.spider_closed, signal=signals.spider_closed)
        
        # This makes the manager instance available to other components (like middlewares)
        crawler.tor_manager = manager
        
        return manager

    def spider_opened(self, spider):
        logger.info("Spider opened, connecting to Tor controller...")
        self.connect_controller()

    def spider_closed(self, spider):
        logger.info("Spider closed, disconnecting from Tor controller.")
        if self.controller and self.controller.is_alive():
            self.controller.close()

    def connect_controller(self):
        if self.controller and self.controller.is_alive():
            logger.debug("Controller is already connected.")
            return True
        try:
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate()
            logger.info("✅ Successfully connected and authenticated with Tor controller.")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to connect to Tor control port: {e}")
            self.controller = None
            return False

    def get_new_circuit(self):
        if not self.controller or not self.controller.is_alive():
            logger.warning("Controller not connected. Attempting to reconnect...")
            if not self.connect_controller():
                logger.error("Cannot get new circuit: Controller connection failed.")
                return False
        try:
            self.controller.signal(Signal.NEWNYM)
            time.sleep(self.controller.get_newnym_wait())
            logger.info("✅ Successfully signaled NEWNYM and waited for new circuit.")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to signal NEWNYM: {e}")
            return False
