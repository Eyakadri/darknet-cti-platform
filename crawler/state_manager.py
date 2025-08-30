"""
State Manager for handling persistent crawling state and delta detection.
"""

import sqlite3
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from config.config_loader import config

logger = logging.getLogger(__name__)


class StateManager:
    """Manages crawling state for delta crawling functionality."""
    def __init__(self):
        self.db_path = config.STATE_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    def init_database(self):
        """Initialize the state database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS crawl_state (
                        url TEXT PRIMARY KEY,
                        last_crawled TIMESTAMP,
                        content_hash TEXT,
                        status TEXT DEFAULT 'pending',
                        metadata TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_last_crawled 
                    ON crawl_state(last_crawled)
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_status 
                    ON crawl_state(status)
                ''')
                
                conn.commit()
                logger.info("State database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def calculate_content_hash(self, content):
        """Calculate SHA256 hash of content."""
        if isinstance(content, str):
            content = content.encode('utf-8')
        return hashlib.sha256(content).hexdigest()
    
    def should_crawl(self, url, current_content_hash=None, min_interval_hours=1):
        """
        Determine if a URL should be crawled based on state.
        
        Args:
            url: URL to check
            current_content_hash: Hash of current content (if available)
            min_interval_hours: Minimum hours between crawls
            
        Returns:
            bool: True if should crawl, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT last_crawled, content_hash, status 
                    FROM crawl_state 
                    WHERE url = ?
                ''', (url,))
                
                result = cursor.fetchone()
                
                if not result:
                    # New URL, should crawl
                    logger.debug(f"New URL, should crawl: {url}")
                    return True
                
                last_crawled, stored_hash, status = result
                
                # Check if content hash has changed
                if current_content_hash and stored_hash:
                    if current_content_hash != stored_hash:
                        logger.debug(f"Content changed, should crawl: {url}")
                        return True
                
                # Check time interval
                if last_crawled:
                    last_crawled_dt = datetime.fromisoformat(last_crawled)
                    hours_since = (datetime.now() - last_crawled_dt).total_seconds() / 3600
                    
                    if hours_since >= min_interval_hours:
                        logger.debug(f"Time interval passed, should crawl: {url}")
                        return True
                
                logger.debug(f"Should not crawl: {url}")
                return False
                
        except Exception as e:
            logger.error(f"Error checking crawl state for {url}: {e}")
            # If error, err on the side of crawling
            return True
    
    def update_crawl_state(self, url, content=None, status='completed', metadata=None):
        """
        Update crawl state for a URL.
        
        Args:
            url: URL that was crawled
            content: Content that was crawled (for hash calculation)
            status: Status of the crawl ('completed', 'failed', 'pending')
            metadata: Additional metadata as dict
        """
        try:
            content_hash = None
            if content:
                content_hash = self.calculate_content_hash(content)
            
            metadata_json = None
            if metadata:
                metadata_json = json.dumps(metadata)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO crawl_state 
                    (url, last_crawled, content_hash, status, metadata, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    url,
                    datetime.now().isoformat(),
                    content_hash,
                    status,
                    metadata_json,
                    datetime.now().isoformat()
                ))
                conn.commit()
                
                logger.debug(f"Updated crawl state for {url}: {status}")
                
        except Exception as e:
            logger.error(f"Error updating crawl state for {url}: {e}")
    
    def get_crawl_stats(self):
        """Get crawling statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total URLs
                cursor.execute('SELECT COUNT(*) FROM crawl_state')
                total_urls = cursor.fetchone()[0]
                
                # Status breakdown
                cursor.execute('''
                    SELECT status, COUNT(*) 
                    FROM crawl_state 
                    GROUP BY status
                ''')
                status_counts = dict(cursor.fetchall())
                
                # Recent activity (last 24 hours)
                cursor.execute('''
                    SELECT COUNT(*) 
                    FROM crawl_state 
                    WHERE last_crawled > datetime('now', '-1 day')
                ''')
                recent_crawls = cursor.fetchone()[0]
                
                return {
                    'total_urls': total_urls,
                    'status_counts': status_counts,
                    'recent_crawls_24h': recent_crawls
                }
                
        except Exception as e:
            logger.error(f"Error getting crawl stats: {e}")
            return {}
    
    def cleanup_old_entries(self, days_old=30):
        """Clean up old entries from the state database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM crawl_state 
                    WHERE last_crawled < datetime('now', '-{} days')
                    AND status != 'pending'
                '''.format(days_old))
                
                deleted_count = cursor.rowcount
                conn.commit()
                
                logger.info(f"Cleaned up {deleted_count} old entries")
                return deleted_count
                
        except Exception as e:
            logger.error(f"Error cleaning up old entries: {e}")
            return 0