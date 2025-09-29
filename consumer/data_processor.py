"""Data Processor - Main consumer component for processing raw HTML data.

This file is usually run via:
    python -m consumer.data_processor [batch]
or:
    python scripts/run_processor.py [batch]

When executed directly (python consumer/data_processor.py), Python's sys.path
won't include the project root; we patch it below for convenience.
"""

import sys
import os  # used only for possible future env/path tweaks
from pathlib import Path as _PathForImport
import argparse

if (
    __name__ == "__main__"
    and str(_PathForImport(__file__).resolve().parent.parent) not in sys.path
):
    # Prepend project root so 'config' and other top-level packages resolve
    sys.path.insert(0, str(_PathForImport(__file__).resolve().parent.parent))

import json
import logging
from pathlib import Path
from datetime import datetime
import time
import re
from typing import List, Dict, Any, Optional

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

# Set up a default logging config ONLY if caller hasn't already done so.
# This way library usage (importing this module) won't spam or override app logging.
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )

# ---------------------------------------------------------------------------
# Lightweight country normalization (no external deps to keep requirements stable)
# ---------------------------------------------------------------------------
# Synonyms / variants -> canonical country names (lowercase keys / values)
_COUNTRY_SYNONYMS = {
    "usa": "united states",
    "u.s.a": "united states",
    "u.s.": "united states",
    "us": "united states",
    "uk": "united kingdom",
    "uae": "united arab emirates",
    "korea": "south korea",  # heuristic
    "south korea": "south korea",
    "hong kong": "hong kong",
    "peoples republic of china": "china",
}

# Seed canonical list (lowercase) – extendable
_COUNTRY_CANONICAL = set(
    [
        "united states",
        "united kingdom",
        "italy",
        "taiwan",
        "brazil",
        "germany",
        "india",
        "united arab emirates",
        "france",
        "indonesia",
        "spain",
        "canada",
        "venezuela",
        "mexico",
        "peru",
        "kenya",
        "qatar",
        "trinidad and tobago",
        "portugal",
        "colombia",
        "slovenia",
        "malaysia",
        "jamaica",
        "saudi arabia",
        "ecuador",
        "argentina",
        "chile",
        "hong kong",
        "australia",
        "china",
        "south korea",
    ]
)

# ---------------------------------------------------------------------------
# Simple hard-coded country -> (lat, lon) mapping for demo geocoding
# NOTE: Keys must stay lowercase and aligned with canonical country names.
# This avoids adding an external dependency just for basic map plotting.
# For production use, replace with a proper geocoding service.
# ---------------------------------------------------------------------------
_COUNTRY_COORDINATES = {
    "united states": {"lat": 39.8283, "lon": -98.5795},
    "germany": {"lat": 51.1657, "lon": 10.4515},
    "italy": {"lat": 41.8719, "lon": 12.5674},
    "india": {"lat": 20.5937, "lon": 78.9629},
    "france": {"lat": 46.6034, "lon": 1.8883},
    "united kingdom": {"lat": 55.3781, "lon": -3.4360},
    "brazil": {"lat": -14.2350, "lon": -51.9253},
    "taiwan": {"lat": 23.6978, "lon": 120.9605},
    "spain": {"lat": 40.4637, "lon": -3.7492},
    "canada": {"lat": 56.1304, "lon": -106.3468},
    "hong kong": {"lat": 22.3193, "lon": 114.1694},
    "australia": {"lat": -25.2744, "lon": 133.7751},
    "china": {"lat": 35.8617, "lon": 104.1954},
    "south korea": {"lat": 35.9078, "lon": 127.7669},
    "argentina": {"lat": -38.4161, "lon": -63.6167},
    "chile": {"lat": -35.6751, "lon": -71.5430},
    "mexico": {"lat": 23.6345, "lon": -102.5528},
    "colombia": {"lat": 4.5709, "lon": -74.2973},
    "ecuador": {"lat": -1.8312, "lon": -78.1834},
    "venezuela": {"lat": 6.4238, "lon": -66.5897},
    "peru": {"lat": -9.1900, "lon": -75.0152},
    "portugal": {"lat": 39.3999, "lon": -8.2245},
    "saudi arabia": {"lat": 23.8859, "lon": 45.0792},
    "qatar": {"lat": 25.3548, "lon": 51.1839},
    "united arab emirates": {"lat": 23.4241, "lon": 53.8478},
    # Newly added canonical countries for completeness
    "indonesia": {"lat": -0.7893, "lon": 113.9213},
    "kenya": {"lat": -0.0236, "lon": 37.9062},
    "trinidad and tobago": {"lat": 10.6918, "lon": -61.2225},
    "slovenia": {"lat": 46.1512, "lon": 14.9955},
    "malaysia": {"lat": 4.2105, "lon": 101.9758},
    "jamaica": {"lat": 18.1096, "lon": -77.2975},
}

def _normalize_country(raw: str) -> str:
    # Convert a raw GPE/entity string into a canonical country name.
    # Returns None if it isn't something we recognize.
    if not raw:
        return None
    t = raw.strip().lower()
    # remove trailing punctuation / commas
    t = re.sub(r"[.,;:_]+$", "", t)
    # map synonyms
    if t in _COUNTRY_SYNONYMS:
        t = _COUNTRY_SYNONYMS[t]
    # accept only if canonical
    return t if t in _COUNTRY_CANONICAL else None

def _extract_countries(entities):
    # Pull out unique canonical countries from an entities list produced by NLP.
    if not entities:
        return []
    found = []
    seen = set()
    for e in entities:
        if e.get('label') != 'GPE':
            continue
        norm = _normalize_country(e.get('text'))
        if norm and norm not in seen:
            seen.add(norm)
            found.append(norm)
    return found

_DATE_PATTERNS = [
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%d-%m-%Y",
    "%d/%m/%Y",
    "%d %b %Y",
    "%b %d %Y",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
]

def _normalize_date(raw: str) -> (str, str):
    """Return (iso_date, original) where iso_date is YYYY-MM-DD if parsed else None."""
    if not raw or not isinstance(raw, str):
        return None, raw
    raw_stripped = raw.strip()
    for fmt in _DATE_PATTERNS:
        try:
            dt = datetime.strptime(raw_stripped, fmt)
            return dt.date().isoformat(), raw
        except ValueError:
            continue
    # Heuristic: if looks like just year-month
    m = re.match(r"^(\d{4})-(\d{2})$", raw_stripped)
    if m:
        try:
            dt = datetime.strptime(raw_stripped + "-01", "%Y-%m-%d")
            return dt.date().isoformat(), raw
        except ValueError:
            pass
    return None, raw

class DataProcessor:
    """Main processor for consuming and processing raw HTML data.

    Parameters
    ----------
    min_content_length : int, default=50
        Minimum length of the `content` field required to run NLP + indexing. Files
        with shorter content are skipped (they remain in the raw directory).
    """

    def __init__(
        self,
        min_content_length: int = 50,
        raw_dir: str = None,
        processed_dir: str = None,
    ):
        # Allow CLI overrides for directories
        self.raw_data_dir = Path(raw_dir).resolve() if raw_dir else config.RAW_DATA_DIR
        self.processed_dir = (
            Path(processed_dir).resolve()
            if processed_dir
            else config.PROCESSED_DATA_DIR
        )
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
            # 1. Load and Validate Data
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            content = data.get("content", "")
            if len(content) < self.min_content_length:
                logger.info(
                    f"Skipping {file_path.name}: content length {len(content)} < min_content_length {self.min_content_length}"
                )
                # We successfully processed this file by deciding to skip it.
                # Move it to 'processed' so we don't see it again.
                processed_file = self.processed_dir / file_path.name
                file_path.rename(processed_file)
                return True # Return True because we handled it.

            # Extract + strip out structured "breach artifact" chunks (hash lines etc.)
            cleaned_content, breach_artifacts = self.nlp_processor.extract_and_clean_breach_artifacts(content)

            # 2. Run NLP on cleaned text (keeps noise down while staying reproducible)
            threat_summary = self.nlp_processor.get_threat_intelligence_summary(cleaned_content)
            victim_profile = self.nlp_processor.extract_victim_profile(data) # Pass the full data object
            # 3. Build the ES document (add geo + victim structure + artifact metadata)
            countries_norm = _extract_countries(threat_summary.get('entities'))
            primary_country = countries_norm[0] if countries_norm else None

            # Date normalization
            normalized_date, original_date = _normalize_date(data.get("post_date"))

            # Distinct length metrics (raw vs cleaned)
            raw_content_length = len(content)
            cleaned_content_length = len(cleaned_content)

            iocs = threat_summary["iocs"]
            ioc_counts = {k: len(v) for k, v in iocs.items()}

            doc = {
                "url": data.get("url"),
                "title": data.get("title"),
                "victim_profile": victim_profile,
                # Store original content and cleaned variant (cleaned aids reproducibility)
                "content": content,
                "cleaned_content": cleaned_content,
                "raw_content_length": raw_content_length,
                "cleaned_content_length": cleaned_content_length,
                # Backward compatible field 'content_length' (use cleaned length as before)
                "content_length": cleaned_content_length,
                "content_hash": data.get("content_hash"),
                "crawled_at": data.get("crawled_at"),
                "site_category": data.get("site_category"),
                "author": data.get("author"),
                "post_date": normalized_date if normalized_date else (data.get("post_date") or None),
                "post_date_original": original_date if normalized_date else original_date,
                "thread_id": data.get("thread_id"),
                "post_id": data.get("post_id"),
                "threat_score": threat_summary["threat_score"],
                "threat_indicators": threat_summary.get("threat_indicators"),
                "iocs": iocs,
                "ioc_counts": ioc_counts,
                "entities": threat_summary["entities"],
                "malware_families": [e['text'] for e in threat_summary['entities'] if e['label'] == 'MALWARE_FAMILY'],
                "threat_actors": [e['text'] for e in threat_summary['entities'] if e['label'] == 'THREAT_ACTOR'],
                "geo_location": {
                    "country_primary": primary_country,
                    "countries_all": countries_norm if countries_norm else None,
                    # Also index a generic 'country' field to align with existing mapping expectations
                    "country": primary_country,
                    # Provide coordinates if we have them; ES geo_point expects {lat, lon}
                    "coordinates": _COUNTRY_COORDINATES.get(primary_country),
                },
                "image_urls": data.get("images", []),
                "breach_artifacts": breach_artifacts,
                "breach_artifact_count": len(breach_artifacts) if breach_artifacts else 0,
                "raw_data_file": str(file_path.name),
                "processing_meta": {
                    "min_content_length": self.min_content_length,
                    "nlp_text_length": threat_summary.get("text_length"),
                    "nlp_processed": True,
                },
            }

            # 4. Ship to Elasticsearch (or log failure). Keep logs terse unless debug.
            if logger.isEnabledFor(logging.DEBUG):
                preview_keys = [
                    "url",
                    "content_hash",
                    "content_length",
                    "threat_score",
                    "threat_actors",
                    "malware_families",
                ]
                preview = {k: doc.get(k) for k in preview_keys if k in doc}
                logger.debug("Prepared document preview for indexing: %s", preview)
            success = self.es_client.index_document(doc)

            if not success:
                logger.error(f"Failed to index document {file_path.name}. It will remain in the raw folder.")
                return False # The indexing failed, so we report failure.

            # 5. Success: archive/move the raw file so we don't reprocess.
            processed_file = self.processed_dir / file_path.name
            file_path.rename(processed_file)
            logger.info(f"Successfully processed and indexed: {file_path.name}")
            return True

        except Exception as e:
            logger.error(f"A critical error occurred while processing {file_path.name}: {e}", exc_info=True)
            return False

    def run_continuous(self, check_interval: int = 10) -> None:
        """Run processor continuously, checking for new files."""
        logger.info("Starting continuous processing...")

        while True:
            try:
                # Find new files to process
                raw_files = list(self.raw_data_dir.glob("*.json"))  # cheap directory scan

                if raw_files:
                    logger.info(f"Found {len(raw_files)} files to process")

                    for file_path in raw_files:
                        self.process_file(file_path)
                        time.sleep(1)  # tiny pause to avoid hammering resources

                # Wait before next check
                time.sleep(check_interval)

            except KeyboardInterrupt:
                logger.info("Stopping processor...")
                break
            except Exception as e:
                logger.error(f"Error in continuous processing: {e}")
                time.sleep(check_interval)

    def process_batch(self) -> Dict[str, int]:
        """Process all files in raw data directory once.

        Returns
        -------
        dict
            Summary statistics of the batch run.
        """
        raw_files = list(self.raw_data_dir.glob("*.json"))
        summary = {
            "total": len(raw_files),
            "processed": 0,
            "skipped_short": 0,
            "errors": 0,
        }

        if not raw_files:
            logger.info("No files to process")
            return summary

        logger.info(f"Processing {len(raw_files)} files...")
    docs_to_index = []  # staged docs for bulk indexing
    processed_files_paths = [] # raw file handles that correspond to docs_to_index

        for file_path in raw_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                content = data.get("content", "")
                if len(content) < self.min_content_length:
                    summary["skipped_short"] += 1
                    # Move the file so we don't process it again
                    file_path.rename(self.processed_dir / file_path.name)
                    continue

                # Same logic as process_file, except we defer indexing until we collect all docs
                cleaned_content, breach_artifacts = self.nlp_processor.extract_and_clean_breach_artifacts(content)
                threat_summary = self.nlp_processor.get_threat_intelligence_summary(cleaned_content)
                victim_profile = self.nlp_processor.extract_victim_profile(data)
                entities: List[Dict[str, Any]] = threat_summary.get('entities') or []
                countries_norm = _extract_countries(entities)
                primary_country = countries_norm[0] if countries_norm else None
                normalized_date, original_date = _normalize_date(data.get("post_date"))
                iocs = threat_summary["iocs"]
                ioc_counts = {k: len(v) for k, v in iocs.items()}

                doc: Dict[str, Any] = {
                    "url": data.get("url"),
                    "title": data.get("title"),
                    "victim_profile": victim_profile,
                    "content": content,
                    "cleaned_content": cleaned_content,
                    "raw_content_length": len(content),
                    "cleaned_content_length": len(cleaned_content),
                    "content_length": len(cleaned_content),
                    "content_hash": data.get("content_hash"),
                    "crawled_at": data.get("crawled_at"),
                    "site_category": data.get("site_category"),
                    "author": data.get("author"),
                    "post_date": normalized_date if normalized_date else (data.get("post_date") or None),
                    "post_date_original": original_date if normalized_date else original_date,
                    "thread_id": data.get("thread_id"),
                    "post_id": data.get("post_id"),
                    "threat_score": threat_summary["threat_score"],
                    "threat_indicators": threat_summary.get("threat_indicators"),
                    "iocs": iocs,
                    "ioc_counts": ioc_counts,
                    "entities": entities,
                    "malware_families": [e['text'] for e in entities if e.get('label') == 'MALWARE_FAMILY'],
                    "threat_actors": [e['text'] for e in entities if e.get('label') == 'THREAT_ACTOR'],
                    "geo_location": {
                        "country_primary": primary_country,
                        "countries_all": countries_norm if countries_norm else None,
                        "country": primary_country,
                        "coordinates": _COUNTRY_COORDINATES.get(primary_country),
                    },
                    "image_urls": data.get("images", []),
                    "breach_artifacts": breach_artifacts,
                    "breach_artifact_count": len(breach_artifacts) if breach_artifacts else 0,
                    "raw_data_file": str(file_path.name),
                    "processing_meta": {
                        "min_content_length": self.min_content_length,
                        "nlp_text_length": threat_summary.get("text_length"),
                        "nlp_processed": True,
                    },
                }
                docs_to_index.append(doc)
                processed_files_paths.append(file_path)
                summary["processed"] += 1
            except Exception as e:
                summary["errors"] += 1
                logger.error(f"Error processing {file_path.name}: {e}", exc_info=True)
                continue

        if docs_to_index:
            logger.info(f"Attempting bulk index of {len(docs_to_index)} documents...")
            if self.es_client.connected:
                result = self.es_client.bulk_index_documents(docs_to_index)
                logger.info(
                    "Bulk indexing complete. Success: %d, Errors: %d",
                    result.get('success', 0),
                    result.get('errors', 0),
                )
                # Move all processed files regardless of partial failures (so we don't loop forever)
                moved = 0
                for file_path in processed_files_paths:
                    try:
                        file_path.rename(self.processed_dir / file_path.name)
                        moved += 1
                    except Exception as move_exc:
                        logger.error("Failed to move processed file %s: %s", file_path.name, move_exc)
                logger.info("Moved %d/%d processed files.", moved, len(processed_files_paths))
            else:
                logger.error("Elasticsearch not connected. Cannot bulk index documents.")
                summary["errors"] += len(docs_to_index)

        logger.info(
            "Batch summary: processed=%d skipped_short=%d errors=%d total=%d",
            summary["processed"],
            summary["skipped_short"],
            summary["errors"],
            summary["total"],
        )

        # Light refresh so results are queryable immediately (no-op if disconnected)
        if self.es_client.connected:
            self.es_client.refresh_index()

        return summary


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Darknet CTI Data Processor")
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["batch", "continuous"],
        default="batch",
        help="Processing mode (default: batch)",
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=50,
        help="Minimum content length to process (default: 50)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Polling interval seconds for continuous mode (default: 10)",
    )
    parser.add_argument(
        "--raw-dir", type=str, help="Override raw data directory (default from config)"
    )
    parser.add_argument(
        "--processed-dir",
        type=str,
        help="Override processed data directory (default from config)",
    )
    parser.add_argument(
        "--require-es",
        action="store_true",
        help="Fail if Elasticsearch is not connected",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Increase logging verbosity (repeatable)",
    )
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
        processed_dir=args.processed_dir,
    )
    logger.info(
        f"Using raw_dir={processor.raw_data_dir} processed_dir={processor.processed_dir}"
    )
    if args.require_es and not processor.es_client.connected:
        logger.error("Elasticsearch connection required but not established. Exiting.")
        return 2

    if args.mode == "continuous":
        logger.info("Starting continuous mode (interval=%ds)" % args.interval)
        processor.run_continuous(check_interval=args.interval)
        return 0
    else:
        summary = processor.process_batch()
        # Provide immediate stdout feedback for scripts
        print(json.dumps({"status": "ok", "summary": summary}, indent=2))
        return 0


if __name__ == "__main__":
    sys.exit(main())
