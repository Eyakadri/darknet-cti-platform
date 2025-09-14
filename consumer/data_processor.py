"""Data Processor - Main consumer component for processing raw HTML data.

This file is usually run via:
    python -m consumer.data_processor [batch]
or:
    python scripts/run_processor.py [batch]

When executed directly (python consumer/data_processor.py), Python's sys.path
won't include the project root; we patch it below for convenience.
"""

import sys
from pathlib import Path as _PathForImport
import argparse
if __name__ == '__main__' and str(_PathForImport(__file__).resolve().parent.parent) not in sys.path:
    # Prepend project root so 'config' and other top-level packages resolve
    sys.path.insert(0, str(_PathForImport(__file__).resolve().parent.parent))

import json
import logging
from pathlib import Path
from datetime import datetime
import time

try:
    from .nlp_processor import CTINLPProcessor
    from .elasticsearch_client import CTIElasticsearchClient
    from config.config_loader import config
except ModuleNotFoundError as e:
    missing = str(e)
    msg = (
        f"Import error: {missing}\n"
        "Run this module using one of:\n"
        "  python -m consumer.data_processor batch\n"
        "  python scripts/run_processor.py batch\n"
        "Or ensure project root is on PYTHONPATH."
    )
    raise SystemExit(msg)

logger = logging.getLogger(__name__)

# Basic logging configuration if the root logger has no handlers (when run as module)
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s [%(name)s] %(message)s'
    )


class DataProcessor:
    """Main processor for consuming and processing raw HTML data.

    Parameters
    ----------
    min_content_length : int, default=50
        Minimum length of the `content` field required to run NLP + indexing. Files
        with shorter content are skipped (they remain in the raw directory).
    """
    def __init__(self, min_content_length: int = 50, raw_dir: str = None, processed_dir: str = None):
        # Allow CLI overrides for directories
        self.raw_data_dir = Path(raw_dir).resolve() if raw_dir else config.RAW_DATA_DIR
        self.processed_dir = Path(processed_dir).resolve() if processed_dir else config.PROCESSED_DATA_DIR
        self.processed_dir.mkdir(parents=True, exist_ok=True)

        self.min_content_length = int(min_content_length)

        # Initialize NLP processor and Elasticsearch client
        self.nlp_processor = CTINLPProcessor()
        # Client now auto-loads configuration when no explicit dict passed
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
            if len(content) < self.min_content_length:
                logger.info(
                    f"Skipping {file_path.name}: content length {len(content)} < min_content_length {self.min_content_length}"
                )
                return False
            
            # Process with NLP
            threat_summary = self.nlp_processor.get_threat_intelligence_summary(content)
            
            # Prepare document for Elasticsearch
            meta = data.get('metadata', {})  # old schema fallback
            doc = {
                'url': data.get('url'),
                'title': data.get('title'),
                'content': content,
                'content_hash': data.get('content_hash'),
                'crawled_at': data.get('crawled_at'),
                'site_category': data.get('site_category') or meta.get('site_category'),
                'author': data.get('author') or meta.get('author'),
                'post_date': data.get('post_date') or meta.get('post_date'),
                'thread_id': data.get('thread_id') or meta.get('thread_id'),
                'post_id': data.get('post_id') or meta.get('post_id'),
                'content_length': len(content),
                # NLP results
                'threat_score': threat_summary['threat_score'],
                'total_entities': threat_summary['processing_stats'].get('total_entities', 0),
                'entity_types_count': threat_summary['processing_stats'].get('entity_types', 0),
                'iocs': threat_summary['iocs'],
                'entities': threat_summary['entities'],
                'normalized_text': threat_summary.get('normalized_text'),
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
        """Process all files in raw data directory once.

        Returns
        -------
        dict
            Summary statistics of the batch run.
        """
        raw_files = list(self.raw_data_dir.glob('*.json'))
        summary = {
            'total': len(raw_files),
            'processed': 0,
            'skipped_short': 0,
            'errors': 0
        }

        if not raw_files:
            logger.info("No files to process")
            return summary

        logger.info(f"Processing {len(raw_files)} files...")

        for file_path in raw_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                content = data.get('content', '')
                if len(content) < self.min_content_length:
                    summary['skipped_short'] += 1
                    logger.debug(f"(skip short) {file_path.name}")
                    continue
            except Exception as e:
                summary['errors'] += 1
                logger.error(f"Pre-check failure {file_path.name}: {e}")
                continue

            if self.process_file(file_path):
                summary['processed'] += 1
            else:
                # process_file already logged; treat as error if not short
                pass

        logger.info(
            "Batch summary: processed=%d skipped_short=%d errors=%d total=%d (min_content_length=%d)",
            summary['processed'], summary['skipped_short'], summary['errors'], summary['total'], self.min_content_length
        )

        # Refresh index (best-effort) so results become searchable quickly
        if self.es_client.connected:
            self.es_client.refresh_index()
        else:
            logger.warning("Elasticsearch not connected; processed data (if any) not indexed.")
        return summary


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Darknet CTI Data Processor")
    parser.add_argument('mode', nargs='?', choices=['batch', 'continuous'], default='batch', help='Processing mode (default: batch)')
    parser.add_argument('--min-length', type=int, default=50, help='Minimum content length to process (default: 50)')
    parser.add_argument('--interval', type=int, default=10, help='Polling interval seconds for continuous mode (default: 10)')
    parser.add_argument('--raw-dir', type=str, help='Override raw data directory (default from config)')
    parser.add_argument('--processed-dir', type=str, help='Override processed data directory (default from config)')
    parser.add_argument('--require-es', action='store_true', help='Fail if Elasticsearch is not connected')
    parser.add_argument('--verbose', '-v', action='count', default=0, help='Increase logging verbosity (repeatable)')
    return parser


def main(argv=None):
    argv = argv or sys.argv[1:]
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Adjust logging level
    if args.verbose >= 2:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logging.getLogger().setLevel(logging.INFO)

    processor = DataProcessor(
        min_content_length=args.min_length,
        raw_dir=args.raw_dir,
        processed_dir=args.processed_dir
    )
    logger.info(f"Using raw_dir={processor.raw_data_dir} processed_dir={processor.processed_dir}")
    if args.require_es and not processor.es_client.connected:
        logger.error("Elasticsearch connection required but not established. Exiting.")
        return 2

    if args.mode == 'continuous':
        logger.info("Starting continuous mode (interval=%ds)" % args.interval)
        processor.run_continuous(check_interval=args.interval)
        return 0
    else:
        summary = processor.process_batch()
        # Provide immediate stdout feedback for scripts
        print(json.dumps({'status': 'ok', 'summary': summary}, indent=2))
        return 0


if __name__ == '__main__':
    sys.exit(main())