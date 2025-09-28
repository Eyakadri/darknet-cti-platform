# Darknet CTI Platform – Software Architecture Specification

Version: 1.0  
Status: Stable (Initial Formalization)  
Owner: Eya Kadri  
Last Updated: 2025-09-28

---

## 1. Executive Summary
The Darknet CTI Platform automates the collection and enrichment of cyber threat intelligence (CTI) from darknet / deep web forums. It ingests unstructured posts, extracts structured indicators (IOCs, CVEs, threat actors, malware families, breach artifacts), enriches them, and indexes normalized documents into Elasticsearch for analytical pivoting (Kibana / dashboards / alerting). The design emphasizes: repeatability, extensibility (config‑driven onboarding of new sources), data quality, and resilience to partial infrastructure failure (e.g., Elasticsearch down, NLP errors isolated).

## 2. Goals & Non‑Goals
### 2.1 Primary Goals
* Automate acquisition of darknet forum posts at per‑post granularity.
* Normalize & enrich text into analyst‑ready structured CTI documents.
* Provide deterministic threat scoring & entity extraction (reproducible).
* Support forensic traceability (content hash, raw vs cleaned variants).
* Enable quick pivoting across actors, malware, CVEs, infrastructures.
* Minimize operational complexity (lightweight stack, few external deps).

### 2.2 Non‑Goals (Current Scope)
* Real‑time streaming ingestion (batch file handoff used now).
* Full STIX/TAXII feed publication (planned).
* Advanced ML (transformer embeddings / clustering) – roadmap.
* Deep geo enrichment beyond country heuristic.
* Automated takedown / active response actions.

## 3. System Context (C4 Level 1)
```
+----------------------+         +---------------------------+
|  Hidden / Darknet    |  HTML   |  Darknet CTI Platform     |
|  Forums (.onion etc) | ----->  |  (Acquisition & Enrich)   |
+----------------------+         +------------+--------------+
                                            |
                                            | Enriched CTI Docs (Index API)
                                            v
                                   +---------------------+
                                   |  Elasticsearch      |
                                   |  (cti_intelligence) |
                                   +----------+----------+
                                              |
                                   Read / Query / Analyze
                                              v
                                        +-----------+
                                        |  Kibana   |
                                        +-----------+
```

External Actors:
* Analyst: Consumes dashboards, searches enriched documents.
* Operator: Runs crawler/processor, maintains infrastructure.
* (Future) Downstream systems: Alerting engine, STIX/TAXII exporter.

## 4. Quality Attribute Priorities
| Attribute | Rationale | Design Strategies |
|-----------|-----------|------------------|
| Accuracy (Entity/IOC) | Analysts depend on precision | Hybrid regex + curated patterns; conflict resolution |
| Traceability | Audit / reproducibility | Content hash, raw vs cleaned fields, file lineage |
| Resilience | ES or network may be transiently unavailable | Deferred failures, offline-safe ingestion, guarded ES calls |
| Extensibility | New forums / patterns added often | YAML selectors, pattern configs, modular processors |
| Performance | Large forum dumps | Single-pass NLP, chunking for long texts |
| Security & Ethics | Sensitive sources | Config scoping, no auto distribution, explicit disclaimers |
| Observability | Debug ingestion issues | Structured logging, processing summaries |

## 5. Logical Architecture (C4 Level 2)
```
┌──────────────────────────────────────────────────────────────────┐
| Acquisition Layer                                                |
|  • Scrapy Spider (DarknetSpider)                                 |
|  • Tor / Proxy Middleware                                        |
|  • (Optional) Selenium Rendering                                 |
└──────────────┬───────────────────────────────────────────────────┘
               │ Raw post JSON (filesystem queue: data/raw/*.json)
               ▼
┌──────────────────────────────────────────────────────────────────┐
| Processing Layer                                                 |
|  • DataProcessor (validation, assembly, scoring)                 |
|  • NLP Processor (spaCy + regex IOC extraction)                  |
|  • Breach Artifact Cleaner                                       |
└──────────────┬───────────────────────────────────────────────────┘
               │ Enriched documents (dict)                         
               ▼                                                   
┌──────────────────────────────────────────────────────────────────┐
| Storage & Access Layer                                           |
|  • Elasticsearch Client (index mgmt, idempotent writes)          |
|  • Index: cti_intelligence                                       |
└──────────────┬───────────────────────────────────────────────────┘
               │ Search / Aggregations                             
               ▼                                                   
┌──────────────────────────────────────────────────────────────────┐
| Analytics & Visualization                                        |
|  • Kibana (Dashboards / Lens)                                    |
|  • (Optional) Grafana (read-only ES datasource)                  |
└──────────────────────────────────────────────────────────────────┘

Support Components: Configuration Loader, Country Heuristics, Threat Scoring, File System Handoff.

## 6. Component Responsibilities
| Component | Key Responsibilities | Failure Behavior |
|-----------|---------------------|------------------|
| DarknetSpider | Acquire forum threads/posts, parse structure, export JSON | If site unreachable, logs & continues other targets |
| Tor Middleware | Route requests via Tor network | If Tor down, requests fail fast; recover on next run |
| DataProcessor | Load raw file, clean, orchestrate NLP & indexing | Skips file on fatal parsing; moves processed or skipped to processed dir |
| CTINLPProcessor | Entity + IOC extraction, victim profile, scoring | Returns partial result or empty set on exception |
| Elasticsearch Client | Safe index creation, idempotent writes using content_hash | If ES down, logs warning; file not moved to processed to allow retry |
| Config Loader | Centralized YAML ingestion | Fails early if essential config missing |

## 7. Data Flow (Detailed)
1. Crawl Cycle: Scrapy spider hits target URLs → extracts per post (author, timestamp, content, thread/post ids) → writes JSON to `data/raw/` with `content_hash`.
2. Processing Batch: DataProcessor iterates raw files → content length filter → breach artifact cleaning → NLP summary → threat scoring.
3. Document Assembly: Adds metadata (geo heuristics, ioc_counts, victim profile, artifact counts, normalized dates).
4. Indexing: Document pushed to ES (`index=cti_intelligence`, doc id = `content_hash` for idempotency). On failure: file retained for retry.
5. Analytics: Kibana dashboards query index facets (actors, malware, ioc types, threat_score). 

## 8. Domain Model (Conceptual)
| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| PostRaw | Unprocessed scraped forum post | url, thread_id, post_id, author, content, crawled_at, content_hash |
| EnrichedDocument | Final indexed CTI document | (PostRaw fields) + cleaned_content, iocs, entities, threat_score, geo_location, breach_artifacts |
| IOC (Logical) | Indicator of Compromise extracted | type (ip, domain,...), value |
| ThreatIndicator | Aggregated intelligence features | threat_score, malware_families, threat_actors, cves |

Mapping: EnrichedDocument serialized 1:1 to ES document. IOC types grouped under `iocs.*` arrays and counts mirrored in `ioc_counts` for faster aggregations.

## 9. Data Storage & Index Strategy
Index: `cti_intelligence`
* Shards: 1 (development) – scale to 3+ with replica factor for production.
* Mappings: Explicit keyword vs text analyzers to enable exact IOC aggregation while supporting full-text search on `content`.
* Idempotency: `_id = content_hash` prevents duplication when content recrawled unchanged.
* Retention: Implement ILM (future) for warm/cold phases or archive to object storage.

## 10. Threat Scoring Model
Deterministic linear composite (clamped 0–100). Components (weights tunable): CVE presence, threat actors, malware families, leak artifact density, IOC counts, country references.
Reason: Transparent scoring fosters analyst trust vs opaque ML black box.

## 11. Configuration Management
| File | Purpose |
|------|---------|
| `crawler_config.yaml` | Target sites, selectors, concurrency, Tor flag |
| `nlp_config.yaml` | spaCy model, custom entity regex, malware & actor lists, regex extraction toggles |
| `elastic_config.yaml` | Hosts, index name, timeouts |
Runtime Override: Environment variables (future enhancement) may supersede YAML (12‑factor alignment).

## 12. Deployment Architecture
### 12.1 Current (Local / PoC)
```
Host Machine
 ├─ Python venv (crawler + processor)
 ├─ Docker Compose
 │    ├─ Elasticsearch
 │    └─ Kibana
 └─ File system shared dirs: data/raw, data/processed
```

### 12.2 Future (Production Option)
| Layer | Technology Suggestion |
|-------|-----------------------|
| Acquisition | Containerized spider jobs (Kubernetes CronJob) |
| Queue / Handoff | Redis Streams or Kafka topic (replaces filesystem) |
| Processing | Stateful consumer deployment (K8s Deployment / autoscale) |
| Storage | Managed Elasticsearch / OpenSearch cluster |
| Observability | Prometheus + Grafana; structured logs → ELK |
| Secrets | Vault / K8s Secrets for Tor credentials, any API keys |

## 13. Scalability Considerations
| Pressure Point | Strategy |
|----------------|----------|
| Crawl Throughput | Parallel spiders with partitioned seed sets |
| NLP CPU | Horizontal scale processors; batch large posts; pre-compiled regex |
| ES Index Size | ILM rollover + compression; archive raw JSON externally |
| Memory (Entities) | Stream processing & chunked NER for >20k char posts |

## 14. Resilience & Failure Handling
| Failure | Mitigation |
|---------|-----------|
| ES down | Graceful skip (document not marked processed) – retry later |
| NLP exception | File logged; avoid crash; continue others |
| Partial crawl (site down) | Independent target listing; unaffected sites continue |
| Duplicate content | Content hash gating; idempotent ES indexing |
| Oversized text | Chunked NER fallback |

## 15. Security & Ethical Controls
* Tor isolation to minimize attribution risks (circuit rotation roadmap).
* Explicit disclaimers: research/academic use only; avoid unauthorized access.
* Potential PII filtration (future): optional redaction layer for emails when non‑threat context.
* No automated distribution of raw content (analyst review gate).

## 16. Performance Notes
* Single spaCy pipeline load per process (warm start ~1–2s).
* Regex extraction precompiled to minimize repeated compilation overhead.
* Content length filter short‑circuits trivial noise (<50 chars) early.
* Chunk threshold (20k chars) prevents extreme memory spikes.

## 17. Observability & Metrics (Planned Enhancements)
| Metric | Source | Purpose |
|--------|--------|---------|
| Files processed / min | DataProcessor counter | Throughput tracking |
| Avg NLP time / doc | Timed context manager | Capacity planning |
| ES index latency | ES _stats / custom timer | Detect cluster stress |
| Skipped (short / error) counts | Batch summary | Quality gating |

## 18. Testing Strategy
| Layer | Tests |
|-------|-------|
| Parsing | Spider extraction unit tests (selectors, edge HTML) |
| NLP | Regex / entity extraction correctness (fixtures) |
| Scoring | Deterministic scoring unit tests for feature combinations |
| ES Client | Index creation, doc idempotency, mapping contract |
| Integration (Future) | End-to-end: raw → enriched ES doc validation |

## 19. Extensibility Points
| Extension | How |
|-----------|-----|
| New IOC type | Add regex & map key in `CTINLPProcessor.ioc_mapping` |
| New site | Add block in `crawler_config.yaml` (selectors + flags) |
| Alternate storage | Implement `IndexingClient` interface; swap in processor |
| Streaming mode | Replace filesystem scan with queue consumer adapter |
| Multi-language | Language detection + per-model spaCy registry |

## 20. Open Issues / Future Roadmap
1. Replace filesystem handoff with Redis Streams (at-least-once semantics + offsets).
2. Introduce STIX 2.1 export & TAXII REST API.
3. Embed-based similarity clustering (threat campaign grouping).
4. ILM policies for ES index lifecycle.
5. Alerting rules engine (score + indicator convergence conditions).
6. Incremental site change detection (DOM diff heuristics) to reduce redundant fetch.

## 21. Risks & Mitigations
| Risk | Impact | Mitigation |
|------|--------|------------|
| Forum layout drift | Parsing failures | Config-driven selectors + monitoring |
| Over-fitting regex | False positives | Unit tests + precision review set |
| ES mapping drift | Query / aggregation errors | Central mapping function; controlled migrations |
| Legal exposure | Compliance violations | Ethical usage guidelines, scoped crawling |
| Single point (NLP process) | Throughput cap | Containerized horizontal scaling |

## 22. Design Rationale Highlights
| Decision | Rationale | Alternatives Considered |
|----------|-----------|-------------------------|
| File-based raw handoff | Simplicity; transparent audit trail | Direct streaming (Kafka) – deferred for complexity |
| Idempotent indexing via hash | Avoid duplicates; stable reference | Random UUID – would create duplicates |
| spaCy + regex hybrid | Balance accuracy & interpretability | Heavier ML (transformers) – performance cost |
| YAML config for patterns | Non-code updates by analysts | Database-driven config – unnecessary overhead |

## 23. Sequence Example (Happy Path)
```
Spider -> (Fetch URL) -> Parse Posts -> Write raw JSON (data/raw)
Processor (batch) -> Load file -> Clean artifacts -> NLP -> Score -> Index (ES) -> Move file to data/processed -> Dashboard visible
```

## 24. Glossary
| Term | Definition |
|------|------------|
| IOC | Indicator of Compromise (IP, domain, hash, etc.) |
| CTI | Cyber Threat Intelligence |
| Enriched Document | Structured, NLP-enhanced representation of a post |
| Content Hash | Deterministic digest for deduplication / idempotency |

## 25. Appendix – Suggested Future Interfaces
Interface abstraction for storage:
```
class IndexingClient:
    def ensure_index(self): ...
    def index_document(self, doc: dict) -> bool: ...
    def bulk_index(self, docs: list[dict]) -> dict: ...
```
Allows swapping Elasticsearch with OpenSearch / alternative backends with minimal change.

---
End of Architecture Specification.
