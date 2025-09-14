# pipelines.py for the darknet_scraper project

import json
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from scrapy.exceptions import DropItem
from .state_manager import StateManager

logger = logging.getLogger(__name__)


class DuplicatesPipeline:
    """
    Filters out items that have already been processed in this crawl session
    by tracking their content hash. This prevents processing the same content
    twice if it appears on multiple pages within a single run.
    """
    def __init__(self):
        self.hashes_seen_this_run = set()

    def process_item(self, item, spider):
        content_hash = item.get('content_hash')
        if not content_hash:
            return item # Cannot check for duplicates without a hash

        if content_hash in self.hashes_seen_this_run:
            raise DropItem(f"Duplicate item found in this crawl run: {item.get('url')}")
        else:
            self.hashes_seen_this_run.add(content_hash)
            return item


class StateUpdatePipeline:
    """
    This pipeline updates the persistent crawl state in Redis after an item
    has been successfully scraped and processed.
    """
    def __init__(self, settings):
        # Initialize our new Redis-based StateManager
        self.state_manager = StateManager(settings)
        self.enabled = settings.getbool('DELTA_CRAWL_ENABLED', True)
        if self.enabled:
            logger.info("StateUpdatePipeline is enabled (Redis).")

    @classmethod
    def from_crawler(cls, crawler):
        return cls(crawler.settings)

    def process_item(self, item, spider):
        if not self.enabled:
            return item

        url = item.get('url')
        content_hash = item.get('content_hash')

        if not url or not content_hash:
            logger.warning("Item is missing 'url' or 'content_hash'. Cannot update state.")
            return item

        # Tell the Redis state manager to save the new hash for this URL.
        self.state_manager.update_crawl_state(url, content_hash)
        
        return item


class RawDataStoragePipeline:
    """
    This pipeline saves the final, processed item as a structured JSON file.
    This file acts as a message in a queue for the downstream 'Consumer' process.
    """
    def __init__(self, settings):
        # Align default with Config._set_paths() using 'data/raw'
        raw_data_dir = settings.get('RAW_DATA_DIR', 'data/raw')
        self.raw_data_dir = Path(raw_data_dir)
        self.raw_data_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Raw data will be stored in: {self.raw_data_dir.resolve()}")

    @classmethod
    def from_crawler(cls, crawler):
        return cls(crawler.settings)

    def process_item(self, item, spider):
        """Store the complete item as a JSON file."""
        try:
            content_hash = item.get('content_hash')
            if not content_hash:
                raise DropItem("Cannot save item without a content_hash.")

            # Create a unique, descriptive filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            filename = f"{timestamp}_{content_hash[:16]}.json"
            file_path = self.raw_data_dir / filename

            # The 'item' is already a dictionary-like object, perfect for JSON.
            with open(file_path, 'w', encoding='utf-8') as f:
                # Scrapy items are dict-like, so we convert to a standard dict for json.dump
                json.dump(dict(item), f, ensure_ascii=False, indent=4)
            
            logger.info(f"Successfully stored item in file: {filename}")

        except Exception as e:
            logger.error(f"Error in RawDataStoragePipeline for item {item.get('url')}: {e}")
        
        return item
