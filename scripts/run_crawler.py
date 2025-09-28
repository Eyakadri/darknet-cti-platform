#!/usr/bin/env python3
"""
Main crawler runner script.
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

# Ensure project root on path (mirrors run_processor.py)
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from dotenv import load_dotenv  # optional
    load_dotenv(dotenv_path=project_root / '.env')
except Exception:
    pass

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
        # Determine actual Scrapy project directory (adjusted to current repo layout)
    # (paths already set globally, keep local vars for clarity if needed)
        scrapy_dir = project_root / 'crawler' / 'darknet_scraper'
        if not scrapy_dir.exists():
            raise FileNotFoundError(f"Scrapy project directory not found at {scrapy_dir}")
        os.chdir(scrapy_dir)
        
        # Run scrapy spider
        # Spider name comes from DarknetSpider.name in spiders/darknet_spider.py
        # Use the current python interpreter to ensure correct environment
        cmd = [sys.executable, '-m', 'scrapy', 'crawl', 'darknet', '-L', 'INFO']
        
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
