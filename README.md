<div align="center">

# Darknet CTI Platform

Intelligence-grade crawling + NLP enrichment pipeline for extracting Cyber Threat Intelligence (CTI) from darknet / deep web forums and marketplaces, normalizing it, and indexing enriched indicators into Elasticsearch for analysis (Kibana, dashboards, geo/context pivots).

</div>

## 1. Why This Project Matters
Security analysts waste hours manually browsing hidden services, copying indicators, and losing context. This platform automates:

* Ethical collection of forum / thread content (config-driven Scrapy spider, Tor / Selenium capable)
* Structured per-post extraction (author, time, content, links, images)
* NLP-based enrichment (malware families, threat actors, CVEs, IOCs, leak artifacts)
* Threat scoring + geo/context inference
* Normalized indexing into Elasticsearch (ready for Kibana visualizations)

Outcome: Faster attribution, quicker pivoting across indicators, and repeatable intelligence production.

## 2. High-Level Architecture

```
	  +------------------+        +--------------------+        +---------------------+
	  |  Target Sites    |  Tor   |  Scrapy Crawler    | JSON   |  Data Processor     |
	  | (.onion/forums)  |<------>|  (DarknetSpider)   |------->|  (NLP + Enrichment) |
	  +------------------+        +--------------------+        +----------+----------+
										| Threat summary
										v
								    +---------------------+
								    | Elasticsearch Index |
								    |  cti_intelligence   |
								    +----------+----------+
										 |
										 v
									 Kibana Dashboards
```

Core components:

| Layer | Purpose | Key Features |
|-------|---------|--------------|
| Crawler (`crawler/darknet_scraper`) | Site acquisition | Config-driven rules, pagination, per-post extraction, Selenium option, Tor-ready middleware |
| Consumer (`consumer/data_processor.py`) | Batch / streaming enrichment | File ingestion, NLP enrichment, IOC consolidation, scoring, geo heuristics |
| NLP (`consumer/nlp_processor.py`) | Entity + IOC extraction | spaCy model + custom entity ruler + regex patterns (IPs, CVEs, crypto, hashes, etc.) |
| Storage (`consumer/elasticsearch_client.py`) | Indexing abstraction | Auto index creation (template-based), resilient when ES is down |
| Config (`config/*.yaml`) | Behavior control | Target sites, NLP patterns, index + storage settings |

## 3. Key Capabilities

* Per-post granularity: Each forum post becomes a structured JSON unit (not just thread-level blobs)
* IOC extraction: IPs, domains, onion domains, URLs, emails, hashes (MD5/SHA1/SHA256), CVEs, crypto wallets, ports
* Threat actor & malware family tagging (YAML-driven patterns)
* Leak artifact extraction (e.g., file part hashes) with content cleanup
<div align="center">

# Darknet CTI Platform
Automated acquisition + enrichment pipeline turning unstructured darknet forum content into structured Cyber Threat Intelligence, ready for search, scoring, and analyst pivoting.

</div>

## 1. Executive Snapshot
| Dimension | Value |
|----------|-------|
| Focus | Darknet forum post harvesting & CTI enrichment |
| Core Stack | Scrapy, Tor, Selenium (optional), Redis (state), spaCy NLP, Elasticsearch, Kibana |
| Outputs | Normalized per‑post JSON + enriched ES index (`cti_intelligence`) |
| Intelligence | IOCs, CVEs, malware families, threat actors, leak artifacts, geo inference, threat scoring |
| Mode | Batch (files) – easily extendable to streaming |

## 2. Architecture (Logical & Data Flow)
```
	    ┌───────────────────────── Target Hidden / Deep Web Sites ─────────────────────────┐
	    |                                                                                  |
	    |  (Forums / Market threads)                                                       |
	    └──────────────────────────────────────────────────────────────────────────────────┘
					   │
					   ▼
			  (Tor / Proxy Middleware + Optional Selenium Rendering)
					   │
					   ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
|  Scrapy Crawler (DarknetSpider)                                                              |
|  • Config-driven selectors (YAML)                                                            |
|  • Pagination, per-post extraction                                                           |
|  • Duplicate filtering (session-level)                                                       |
|  • Redis-backed delta crawl state (content hash memory)                                      |
|  • Pipelines → JSON drop to raw storage                                                      |
└──────────────┬──────────────────────────────────────────────────────────────────────────────┘
	       │  Raw post JSON files (queue-like handoff: data/raw)
	       ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
|  Data Processor (consumer/data_processor.py)                                                 |
|  • Validates & length filters                                                                |
|  • Cleans leak artifact patterns                                                             |
|  • Single-pass spaCy + regex hybrid extraction                                               |
|  • IOC consolidation + scoring + geo heuristics                                              |
|  • Document assembly                                                                          |
└──────────────┬──────────────────────────────────────────────────────────────────────────────┘
	       │  Enriched documents
	       ▼
┌──────────────────────────────┐      Kibana / Dashboards / Alerting
| Elasticsearch (cti_intelligence) | ◀────────────────────────────────────┐
|  • Time-series (@timestamp)     |                                      |
|  • IOC fields (structured)      |   Pivoting: Malware ↔ Actor ↔ CVE    |
|  • Geo / scoring facets         |   Correlation & triage               |
└────────────────────────────────┘                                      │
									│
			(Future: Stream bus / API / Export feeds) ──────┘
```

### Component Roles
| Component | Responsibilities | Resilience / Notes |
|-----------|------------------|--------------------|
| DarknetSpider | Acquisition, pagination, per-post parsing | Tor-aware; Selenium opt-in per site |
| Redis (StateManager) | Persistent delta crawl memory (URL → last content hash) | Skips unchanged content across runs |
| Pipelines | Dedup (run scope), state update, raw JSON persistence | Backpressure via filesystem |
| DataProcessor | NLP enrichment, artifact cleanup, scoring, indexing | Skips too-short noise, isolates failures per file |
| NLP Processor | Hybrid entity + IOC extraction | Single pass; chunking for large texts |
| ES Client | Minimal abstraction (index + optional mapping) | Degrades gracefully if ES unavailable |

## 3. Distinguishing Features
* Dual-layer de-duplication (session + historical via Redis state)
* Per-post intelligence (granularity beats coarse thread dumps)
* Hybrid extraction: spaCy EntityRuler + curated regex, with conflict resolution
* Structured leak artifact harvesting (hash patterns removed from content)
* Geo inference without external API (deterministic + reproducible)
* Threat scoring blending CVE / actor / malware presence, data-leak signals & IOC density
* Config-driven onboarding of new sites (no code change to add domains)
* Clean failure isolation: raw file retained when indexing fails

## 4. Data Lifecycle (Contract)
| Stage | Input | Output | Guarantees |
|-------|-------|--------|------------|
| Crawl | HTTP/Tor responses | Normalized post JSON | `content_hash` stable per content variant |
| Persist | Scraped item | File in `data/raw/` | Filename timestamp + prefix of hash |
| Process | Raw JSON | Enriched dict | Adds NLP + scoring + geo fields |
| Index | Enriched dict | ES document | Idempotent via `content_hash` as id |

Failure Modes:
* ES unreachable → log + raw file left for retry
* NLP error (rare) → minimal doc skipped (logged), pipeline continues
* Redis down → startup failure (explicit) to avoid inconsistent delta state

## 5. Threat Scoring (Readable Formula)
Score composed of weighted components (clamped 0–100):
```
score = 50*CVE_count + 30*threat_actor_count + 20*malware_family_count
	+ 5*file_hash_count + 1*ip_count + 0.5*email_count
	+ (15 if any country referenced else 0)
	+ (40 if email_count > 10 leak signal)
```
Designed for prioritization, not absolute severity. Adjust in `CTINLPProcessor.get_threat_intelligence_summary`.

## 6. Selected Elasticsearch Fields
| Field | Purpose |
|-------|---------|
| `url` / `thread_id` / `post_id` | Traceability & uniqueness |
| `content` / `cleaned_content` | Raw vs sanitized text |
| `iocs.*` | Structured IOC buckets |
| `ioc_counts` | Fast aggregations without script fields |
| `malware_families`, `threat_actors` | Pivot dimensions |
| `geo_location.coordinates` | Geo point for maps |
| `breach_artifacts` | Nested (hash_type, hash_value) list |
| `threat_score` | Primary prioritization metric |
| `@timestamp`, `processed_at`, `crawled_at` | Temporal analysis |

## 7. Configuration Files
| File | Role |
|------|------|
| `config/crawler_config.yaml` | Sites, Tor, Selenium, concurrency, storage paths |
| `config/nlp_config.yaml` | Model name, custom entities, regex toggles |
| `config/elastic_config.yaml` | Host(s), index, logging |

Add a site: append its object under `target_sites` (selectors: follow_links, pagination, post_author, post_content...).

## 8. Quick Start
```bash
git clone https://github.com/Eyakadri/darknet-cti-platform.git
cd darknet-cti-platform
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
docker compose up -d   # Elasticsearch + Kibana
# (Optional) Add Grafana (now included in compose) for richer dashboards:
# docker compose up -d grafana
```
Run crawler:
```bash
python scripts/run_crawler.py
```
Process batch:
```bash
python scripts/run_processor.py batch
```
Create Kibana data view: index pattern `cti_intelligence`, time field `@timestamp`.

### Connectivity / Troubleshooting (Elasticsearch & Kibana)
If Kibana (5601) or Elasticsearch (9200) seem unreachable but containers show `healthy`, run the diagnostic helper:

```bash
chmod +x scripts/diagnose_stack.sh
bash scripts/diagnose_stack.sh
```

This gathers:
* Port bindings & listening sockets
* Quick curl status codes (host + in‑container)
* Recent container logs (tail 40)
* Any iptables rules affecting 9200 / 5601
* Proxy / localhost resolution context

Include its output when reporting an issue to speed triage.

### Grafana (Optional Observability Layer)
The stack now includes an optional Grafana service (port 3000) pre‑provisioned with:
* Elasticsearch data source (name: `Elasticsearch-CTI`) targeting the `cti_intelligence` index
* Example dashboard: Threat Intelligence Overview (docs/time series, avg threat score, top actors)

Start only Grafana (if ES already up):
```bash
docker compose up -d grafana
```
Access: http://localhost:3000 (user/pass: admin / admin — change in `docker-compose.yml`).

Provisioning files:
* `grafana/provisioning/datasources/elasticsearch.yml`
* `grafana/provisioning/dashboards/json/threat_overview.json`

Safe to remove Grafana at any time: it is read‑only vs Elasticsearch and won’t alter index mappings.

## 9. Testing
```bash
pytest -q
```
Coverage focus: spider parsing (links/posts), ES indexing contract, NLP IOC extraction.

## 10. Extensibility Guide
| Objective | Touchpoint |
|-----------|-----------|
| New IOC pattern | Add regex + map in `nlp_processor.py` |
| Adjust scoring weight | Edit scoring block in NLP summary |
| Alternate storage | Implement new client (mirror `CTIElasticsearchClient`) |
| Streaming mode | Replace file handoff with Redis Streams / Kafka topic |
| Multi-language | Detect language → route to per-language spaCy model |
| Advanced geo | Replace static country map with MaxMind or API |

## 11. Operational & Security Notes
* Ensure Tor circuit isolation if targeting sensitive forums (rotate circuits via controller).
* Selenium only for scripted / JavaScript-heavy sites; disable per target to reduce risk.
* Respect legal / ethical boundaries; do not ingest PII beyond legitimate CTI context.
* Raw files are your forensic buffer—retain for reprocessing & audit.

## 12. Suggested Kibana Dashboards
| Dashboard | Visualization Ideas |
|-----------|---------------------|
| Threat Overview | Score histogram, top actors, top malware families |
| IOC Density | Stacked bar (domains vs IPs vs hashes) over time |
| Geo Exposure | World map (geo_location.coordinates) |
| Leak Signals | Email count vs time, breach_artifact counts |
| CVE Timeline | CVE mentions vs `@timestamp` |

## 13. Roadmap (Next Iterations)
1. Containerize Data Processor + add to docker-compose
2. Real-time queue bridge (Redis Streams → consumer tail)
3. Alerting rules (high score + CVE + actor convergence)
4. Transformer embeddings for semantic clustering
5. Multi-model (lightweight vs deep) adaptive inference
6. API layer exporting STIX 2.1 bundles / TAXII feed

## 14. Ethical & Legal Considerations
This is an academic / research platform. Only crawl with authorization. Handle sensitive breach data responsibly; implement redaction if distributing outputs.

## 15. Credits & Author
Built by Eya Kadri. Uses: Scrapy, spaCy, Elasticsearch, Kibana, Redis, Tor.

---
Focused engineering delivering actionable CTI from noisy darknet sources.

