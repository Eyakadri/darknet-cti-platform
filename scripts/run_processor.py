#!/usr/bin/env python3
"""Launcher for the data processor.

Convenience wrapper so you can just:
    ./scripts/run_processor.py [batch]
instead of remembering the python -m path. Adds project root to sys.path and loads
environment variables early.
"""

import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure project root is on sys.path so standard package imports work
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
sys.path.insert(0, str(project_root))

load_dotenv(dotenv_path=project_root / ".env")

from consumer.data_processor import DataProcessor  # core processing pipeline

def main():
    """Entry point. Chooses continuous vs batch based on first arg.

    batch  -> one pass over current raw files
    (none) -> continuous watcher loop
    """
    processor = DataProcessor()
    if len(sys.argv) > 1 and sys.argv[1] == "batch":
        print("Running batch processing...")
        processor.process_batch()
    else:
        print("Running continuous processing... (Ctrl+C to exit)")
        processor.run_continuous()


if __name__ == "__main__":
    main()
