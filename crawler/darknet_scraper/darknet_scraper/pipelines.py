# Define your item pipelines here

import os
import json
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from scrapy.exceptions import DropItem

# Add parent directory to path to import our modules
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from crawler.state_manager import StateManager

logger = logging.getLogger(__name__)


class StateUpdatePipeline:
    """Pipeline to update crawl state."""
    
    def __init__(self, state_db_path):
        self.state_manager = StateManager(state_db_path)
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            state_db_path=crawler.settings.get('STATE_DB_PATH', 'data/crawler_state.db')
        )
    
    def process_item(self, item, spider):
        """Update state for crawled item."""
        try:
            url = item.get('url')
            content = item.get('content', '')
            
            metadata = {
                'title': item.get('title'),
                'content_length': len(content),
                'crawled_at': item.get('crawled_at'),
                'site_category': item.get('site_category')
            }
            
            self.state_manager.update_crawl_state(
                url=url,
                content=content,
                status='completed',
                metadata=metadata
            )
            
            logger.debug(f"Updated state for {url}")
            
        except Exception as e:
            logger.error(f"Error updating state for item: {e}")
        
        return item


class RawDataStoragePipeline:
    """Pipeline to store raw HTML data."""
    
    def __init__(self, raw_data_dir):
        self.raw_data_dir = Path(raw_data_dir)
        self.raw_data_dir.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            raw_data_dir=crawler.settings.get('RAW_DATA_DIR', 'data/raw_html')
        )
    
    def process_item(self, item, spider):
        """Store raw HTML data to file."""
        try:
            url = item.get('url', '')
            raw_html = item.get('raw_html', '')
            content_hash = item.get('content_hash', '')
            
            if not raw_html:
                logger.warning(f"No raw HTML for {url}")
                return item
            
            # Create filename based on hash and timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            filename = f"{timestamp}_{url_hash}_{content_hash[:8]}.json"
            
            # Prepare data for storage
            data = {
                'url': url,
                'title': item.get('title', ''),
                'content': item.get('content', ''),
                'raw_html': raw_html,
                'crawled_at': item.get('crawled_at'),
                'content_hash': content_hash,
                'metadata': {
                    'site_category': item.get('site_category'),
                    'author': item.get('author'),
                    'post_date': item.get('post_date'),
                    'thread_id': item.get('thread_id'),
                    'post_id': item.get('post_id'),
                    'response_time': item.get('response_time'),
                    'content_length': item.get('content_length'),
                    'links': item.get('links', []),
                    'images': item.get('images', [])
                }
            }
            
            # Write to file
            file_path = self.raw_data_dir / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Stored raw data: {filename}")
            
        except Exception as e:
            logger.error(f"Error storing raw data for item: {e}")
        
        return item


class DuplicatesPipeline:
    """Pipeline to filter duplicate items."""
    
    def __init__(self):
        self.ids_seen = set()

    def process_item(self, item, spider):
        """Filter duplicate items based on content hash."""
        content_hash = item.get('content_hash')
        
        if content_hash in self.ids_seen:
            logger.info(f"Duplicate item found: {item.get('url')}")
            raise DropItem(f"Duplicate item found: {item.get('url')}")
        else:
            self.ids_seen.add(content_hash)
            return item

