#!/usr/bin/env python3
"""
Main crawler runner script.
"""

import os
import sys
import subprocess
import logging
from pathlib import Path
from config.config_loader import config

# Setup logging
logging.basicConfig(
    level=config.LOG_LEVEL,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename=config.LOG_FILE,
    filemode='a'
)


def run_crawler():
    """Run the Scrapy crawler."""
    try:
        # Change to scrapy project directory
        scrapy_dir = Path(__file__).parent / 'producer' / 'scrapy_project'
        os.chdir(scrapy_dir)
        
        # Run scrapy spider
        cmd = ['scrapy', 'crawl', 'darknet', '-L', 'INFO']
        
        print("Starting CTI crawler...")
        print(f"Command: {' '.join(cmd)}")
        print(f"Working directory: {scrapy_dir}")
        
        result = subprocess.run(cmd, capture_output=False)
        
        if result.returncode == 0:
            print("Crawler completed successfully")
        else:
            print(f"Crawler failed with return code: {result.returncode}")
            
        return result.returncode
        
    except Exception as e:
        print(f"Error running crawler: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(run_crawler())
