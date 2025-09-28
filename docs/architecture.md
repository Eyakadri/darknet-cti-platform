# Darknet CTI Platform – Minimal Overview

A lightweight view of only the core moving parts and how they connect.

## 1. Big Picture
```mermaid
graph LR
    A[Darknet / Deep Web Sources] -->|HTML pages| B[Scrapy Crawler]
    B -->|Raw JSON posts| C[(data/raw)]
    C --> D[Data Processor]
    D -->|Text| E[NLP (spaCy + regex)]
    E --> D
    D -->|Enriched docs| F[(Elasticsearch)]
    F --> G[Kibana]
    F --> H[Grafana]
```

## 2. Core Components (Just the Essentials)
| Component | Tech / Tool | What It Does (1 line) |
|-----------|-------------|------------------------|
| Sources | Hidden services / forums | Provide unstructured content |
| Crawler | Scrapy + (Tor/Selenium opt) | Fetch pages & extract per‑post JSON |
| Raw Storage | Filesystem (`data/raw`) | Simple handoff / buffer |
| Processor | Python (`data_processor.py`) | Validates + enriches + prepares documents |
| NLP | spaCy + regex | Finds entities, IOCs, scores text |
| Index | Elasticsearch | Stores searchable enriched documents |
| Visualization | Kibana / Grafana | Dashboards, pivots, geo & trends |

## 3. Simplified Flow
1. Crawler requests pages through Tor (if configured).
2. Extracted posts are written as JSON files.
3. Processor reads each file, cleans text, calls NLP once.
4. NLP returns entities + IOCs + threat score.
5. Processor assembles a single enriched document and indexes it.
6. Dashboards query Elasticsearch for analysis.

## 4. Minimal Data Contract (Key Fields Only)
| Field | Purpose |
|-------|---------|
| url | Trace back to source |
| content | Original text |
| iocs.* | Extracted indicators |
| threat_score | Prioritization number |
| threat_actors / malware_families | Pivot dimensions |
| geo_location.country | Basic geographic context |
| processed_at | Processing timestamp |

## 5. Retry / Failure Simplicity
- If Elasticsearch is down: file remains in `data/raw` for a later retry.
- If content too short: skipped and moved to `data/processed` (no enrichment).

## 6. Only 3 Operational Actions
| Action | Command |
|--------|---------|
| Crawl | `python scripts/run_crawler.py` |
| Process batch | `python scripts/run_processor.py batch` |
| View intelligence | Open Kibana (index pattern: `cti_intelligence`) |

---
Ultra‑condensed version. See `docs/architecture_diagrams.md` for full detail if needed.
