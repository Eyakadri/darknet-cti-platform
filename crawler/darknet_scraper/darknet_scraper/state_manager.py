# crawler/state_manager.py
from typing import Optional
import redis # type: ignore
import hashlib
import logging

logger = logging.getLogger(__name__)

class StateManager:
    """
    Manages crawling state using Redis for high-performance delta crawling.
    An instance of this class is created by middlewares or pipelines that need it,
    and it gets its configuration from the Scrapy settings object.
    """
    # Use a prefix for all keys to avoid collisions if Redis is used for other purposes.
    REDIS_KEY_PREFIX = "darknet_crawler:state:"

    def __init__(self, settings):
        """
        Initializes the StateManager by connecting to Redis using configuration
        from the Scrapy settings object.
        """
        try:
            self.redis_client = redis.Redis(
                host=settings.get('REDIS_HOST'),
                port=settings.getint('REDIS_PORT'),
                db=settings.getint('REDIS_DB'),
                decode_responses=True  # Automatically decode responses from bytes to strings
            )
            # Test the connection to ensure Redis is available on startup.
            self.redis_client.ping()
            logger.info(f"✅ StateManager connected to Redis at {settings.get('REDIS_HOST')}:{settings.get('REDIS_PORT')}")
        except redis.exceptions.ConnectionError as e:
            logger.error(f"❌ StateManager could not connect to Redis: {e}")
            # This is a critical failure. The crawl cannot proceed without the state manager.
            raise

    def _get_key(self, url: str) -> str:
        """Generates the Redis key for a given URL."""
        return f"{self.REDIS_KEY_PREFIX}{url}"

    def get_stored_hash(self, url: str) -> Optional[str]:
        """
        Retrieves the last known content hash for a given URL from Redis.

        Returns:
            The stored hash as a string, or None if the URL is not in the state.
        """
        return self.redis_client.get(self._get_key(url))

    def update_crawl_state(self, url: str, new_content_hash: str):
        """
        Updates the state for a URL in Redis by storing its latest content hash.
        """
        try:
            self.redis_client.set(self._get_key(url), new_content_hash)
            logger.debug(f"Updated state for {url} with hash {new_content_hash[:8]}...")
        except Exception as e:
            logger.error(f"Failed to update state for {url} in Redis: {e}")

