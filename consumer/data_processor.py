"""
Data Processor - Main consumer component for processing raw HTML data.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
import time

from nlp_processor import CTINLPProcessor
from elasticsearch_client import CTIElasticsearchClient
from config.config_loader import config

logger = logging.getLogger(__name__)


class DataProcessor:
    """Main processor for consuming and processing raw HTML data."""
    def __init__(self):
        self.raw_data_dir = config.RAW_DATA_DIR
        self.processed_dir = config.PROCESSED_DATA_DIR
        self.processed_dir.mkdir(parents=True, exist_ok=True)

        
        # Initialize NLP processor and Elasticsearch client
        self.nlp_processor = CTINLPProcessor()
        self.es_client = CTIElasticsearchClient()
        
        logger.info("Data processor initialized")
    
    def process_file(self, file_path: Path) -> bool:
        """Process a single raw data file."""
        try:
            # Load raw data
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract text content
            content = data.get('content', '')
            if len(content) < 50:  # Skip very short content
                return False
            
            # Process with NLP
            threat_summary = self.nlp_processor.get_threat_intelligence_summary(content)
            
            # Prepare document for Elasticsearch
            doc = {
                'url': data.get('url'),
                'title': data.get('title'),
                'content': content,
                'content_hash': data.get('content_hash'),
                'crawled_at': data.get('crawled_at'),
                'site_category': data.get('metadata', {}).get('site_category'),
                'author': data.get('metadata', {}).get('author'),
                'post_date': data.get('metadata', {}).get('post_date'),
                'thread_id': data.get('metadata', {}).get('thread_id'),
                'post_id': data.get('metadata', {}).get('post_id'),
                'content_length': len(content),
                
                # NLP results
                'threat_score': threat_summary['threat_score'],
                'total_entities': threat_summary['processing_stats'].get('total_entities', 0),
                'entity_types_count': threat_summary['processing_stats'].get('entity_types', 0),
                'iocs': threat_summary['iocs'],
                'entities': threat_summary['entities'],
                
                # Extract specific threat indicators
                'malware_families': [e['text'] for e in threat_summary['entities'] if e['label'] == 'MALWARE_FAMILY'],
                'threat_actors': [e['text'] for e in threat_summary['entities'] if e['label'] == 'THREAT_ACTOR'],
                
                'raw_data_file': str(file_path.name)
            }
            
            # Index to Elasticsearch
            success = self.es_client.index_document(doc)
            
            if success:
                # Move processed file
                processed_file = self.processed_dir / file_path.name
                file_path.rename(processed_file)
                logger.info(f"Processed: {file_path.name}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            return False
    
    def run_continuous(self, check_interval=10):
        """Run processor continuously, checking for new files."""
        logger.info("Starting continuous processing...")
        
        while True:
            try:
                # Find new files to process
                raw_files = list(self.raw_data_dir.glob('*.json'))
                
                if raw_files:
                    logger.info(f"Found {len(raw_files)} files to process")
                    
                    for file_path in raw_files:
                        self.process_file(file_path)
                        time.sleep(1)  # Small delay between files
                
                # Wait before next check
                time.sleep(check_interval)
                
            except KeyboardInterrupt:
                logger.info("Stopping processor...")
                break
            except Exception as e:
                logger.error(f"Error in continuous processing: {e}")
                time.sleep(check_interval)
    
    def process_batch(self):
        """Process all files in raw data directory once."""
        raw_files = list(self.raw_data_dir.glob('*.json'))
        
        if not raw_files:
            logger.info("No files to process")
            return
        
        logger.info(f"Processing {len(raw_files)} files...")
        
        processed_count = 0
        for file_path in raw_files:
            if self.process_file(file_path):
                processed_count += 1
        
        logger.info(f"Processed {processed_count}/{len(raw_files)} files")


if __name__ == '__main__':
    import sys
    
    processor = DataProcessor()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'batch':
        processor.process_batch()
    else:
        processor.run_continuous()
