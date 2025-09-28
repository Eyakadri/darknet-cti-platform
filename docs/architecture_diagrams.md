# Darknet CTI Platform – Visual Architecture

This document provides visual representations (Mermaid + ASCII) of the system's data flow, component interactions, and processing lifecycle. Use these diagrams in docs, presentations, or onboarding.

---
## 1. End-to-End Data Flow (High-Level)
```mermaid
graph LR
    A[Hidden / Darknet Sites <br/> forums, markets, blogs] -->|HTTP / Tor| B[Scrapy Crawler <br/> DarknetSpider]
    B -->|Raw Post JSON<br/> data/raw/*.json| C[Filesystem Handoff]
    C --> D[Data Processor <br/> consumer/data_processor.py]
    D -->|spaCy + Regex| E[NLP Processor <br/> CTINLPProcessor]
    E --> D
    D -->|Enriched Document| F[(Elasticsearch <br/> cti_intelligence)]
    F --> G[Kibana / Dashboards]
    F --> H[Grafana (optional)]
    F --> I[Future APIs / Exports]
```

---
## 2. Scrapy Crawler Internal Flow
```mermaid
flowchart TD
    A[Start Crawl] --> B[Load crawler_config.yaml]
    B --> C{Target Site Loop}
    C --> D[Request Listing / Index Page]
    D --> E[Parse Links / Pagination]
    E --> F[Fetch Post Page]
    F --> G[Extract Fields (author, date, content, images, IDs)]
    G --> H[Compute content_hash]
    H --> I{Duplicate?
(redis state + session memory)}
    I -- Yes --> J[Skip Persist]
    I -- No --> K[Emit Item]
    K --> L[Item Pipelines]
    L --> M[Write JSON to data/raw]
    J --> C
    M --> C
    C --> N[End]
```

---
## 3. Data Processor Sequence (Single File)
```mermaid
sequenceDiagram
    participant FS as FileSystem
    participant DP as DataProcessor
    participant NLP as CTINLPProcessor
    participant ES as Elasticsearch

    FS->>DP: JSON file (url, content, meta)
    DP->>DP: Validate length / skip logic
    DP->>NLP: extract_and_clean_breach_artifacts(content)
    NLP-->>DP: cleaned_text + artifacts
    DP->>NLP: get_threat_intelligence_summary(cleaned_text)
    NLP-->>DP: {entities, iocs, threat_score,...}
    DP->>NLP: extract_victim_profile(raw data)
    NLP-->>DP: victim_profile
    DP->>DP: Assemble enriched doc (geo, counts, scoring)
    DP->>ES: index_document(doc)
    ES-->>DP: ack / fail
    DP->>FS: Move file to data/processed/
```

---
## 4. Bulk Batch Mode Workflow
```mermaid
flowchart LR
    R[data/raw/*.json] --> B[Batch Loader]
    B --> F{Content >= min_length?}
    F -- No --> S[Skip & Move ➜ processed]
    F -- Yes --> C[Clean Leak Artifacts]
    C --> N[Single-pass NLP]
    N --> A[Assemble Documents]
    A --> Q[Docs List]
    Q -->|bulk_index_documents| ES[(Elasticsearch)]
    ES --> M[Move All Processed Files]
```

---
## 5. Elasticsearch Document Logical Model
```mermaid
classDiagram
    class EnrichedDocument {
      string url
      string title
      string content
      string cleaned_content
      int raw_content_length
      int cleaned_content_length
      string content_hash
      date crawled_at
      date processed_at
      string site_category
      string author
      date post_date
      string thread_id
      string post_id
      int threat_score
      ThreatIndicators threat_indicators
      IOCBuckets iocs
      map ioc_counts
      Entity[] entities
      string[] malware_families
      string[] threat_actors
      Geo geo_location
      string[] image_urls
      BreachArtifact[] breach_artifacts
      VictimProfile victim_profile
      ProcessingMeta processing_meta
    }
    class ThreatIndicators {
      int malware_families
      int threat_actors
      int cves
      int total_iocs
      int unique_domains
      int ip_addresses
      int file_hashes
      int crypto_addresses
    }
    class IOCBuckets {
      string[] ip_addresses
      string[] domains
      string[] onion_domains
      string[] emails
      string[] urls
      string[] md5_hashes
      string[] sha1_hashes
      string[] sha256_hashes
      string[] btc_addresses
      string[] eth_addresses
      string[] cves
      string[] registry_keys
      string[] file_paths
      int[] ports
    }
    class Entity {
      string text
      string label
      int start
      int end
      float confidence
      string source
    }
    class Geo {
      string country_primary
      string[] countries_all
      string country
      GeoPoint coordinates
    }
    class GeoPoint { float lat; float lon }
    class BreachArtifact { string hash_type; string hash_value }
    class VictimProfile {
      string name
      string domain
      string description
      string[] tags
      Breach breach
    }
    class Breach {
      date date
      int record_count
      string[] leaked_tables
      string[] leaked_columns
      string download_link
      string proof_type
    }
    class ProcessingMeta { int min_content_length; int nlp_text_length; bool nlp_processed }
```

---
## 6. Threat Scoring Logic (Decision View)
```mermaid
flowchart TD
    A[Start Score=0] --> B[+50 * CVE_count]
    B --> C[+30 * Threat Actor count]
    C --> D[+20 * Malware Family count]
    D --> E{Email count > 10?}
    E -- Yes --> F[+40 Leak Bonus]
    E -- No --> G[No bonus]
    F --> H[+5 * File Hash count]
    G --> H
    H --> I[+1 * IP count]
    I --> J[+0.5 * Email count]
    J --> K{Any country entities?}
    K -- Yes --> L[+15 Geo Context]
    K -- No --> M[No geo points]
    L --> N[Clamp <= 100]
    M --> N
    N --> O[Final Threat Score]
```

---
## 7. Processing State Transitions
```mermaid
stateDiagram-v2
    [*] --> RawFile: Written by crawler
    RawFile --> SkippedShort: content_length < min_length
    RawFile --> Enriched: NLP + enrichment OK
    Enriched --> Indexed: ES index success
    Enriched --> RetainedRaw: ES failure (file stays in raw)
    SkippedShort --> Archived: moved to processed/
    Indexed --> Archived: file moved to processed/
```

---
## 8. Resilience & Degradation Paths
```mermaid
flowchart LR
    ES[(Elasticsearch Down)] -->|index_document fails| DP[Data Processor]
    DP -->|Log error & keep file| RAW[data/raw]
    RAW -->|Retry later| DP

    subgraph NLP Pipeline
      T[Text] --> P[NLP Processing]
      P -->|Exception| F[Fallback Empty Entities]
    end
```

---
## 9. Future Streaming Extension (Concept)
```mermaid
flowchart LR
    Crawl --> Kafka[(Kafka Topic: raw_posts)] --> StreamProc[Streaming Enricher]
    StreamProc --> ES[(Elasticsearch)]
    StreamProc --> S3[(Cold Storage)]
    ES --> Alert[Rule Engine / Alerts]
```

---
## 10. ASCII Quick Reference (Compact)
```
[Tor+Scrapy] -> data/raw/*.json -> (DataProcessor)
    -> NLP (entities+iocs+score)
    -> Elasticsearch(cti_intelligence) -> Kibana/Grafana

Failure: ES down => file stays in raw for retry.
```

---
## Usage
Embed any diagram in other Markdown:
```markdown
![](docs/architecture_diagrams.md#1-end-to-end-data-flow-high-level)
```
Regenerate as architecture evolves.

---
Maintained: 2025-09-28
