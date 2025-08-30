#!/usr/bin/env python3
"""
Main processor runner script.
"""

import sys
import os
from pathlib import Path

# Add consumer directory to path
consumer_dir = Path(__file__).parent / 'consumer'
sys.path.insert(0, str(consumer_dir))

from consumer.data_processor import DataProcessor

def main():
    """Main function."""
    processor = DataProcessor()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'batch':
        print("Running batch processing...")
        processor.process_batch()
    else:
        print("Running continuous processing... (Press Ctrl+C to stop)")
        processor.run_continuous()

if __name__ == '__main__':
    main()

