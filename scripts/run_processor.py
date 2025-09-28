#!/usr/bin/env python3
"""
Main processor runner script.
"""

import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure project root is on sys.path so standard package imports work
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
sys.path.insert(0, str(project_root))

load_dotenv(dotenv_path=project_root / ".env")

from consumer.data_processor import DataProcessor

def main():
    """Main function."""

    # --- Normal modes ---
    processor = DataProcessor()

    if len(sys.argv) > 1 and sys.argv[1] == "batch":
        print("Running batch processing...")
        processor.process_batch()
    else:
        print("Running continuous processing... (Press Ctrl+C to stop)")
        processor.run_continuous()


if __name__ == "__main__":
    main()
