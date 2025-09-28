"""Elasticsearch client for indexing and querying CTI data.

Key improvements in this refactor:
 - Added robust `connect` method with retries & ping validation.
 - Added `connection_required` decorator to gracefully handle offline state.
 - Safe index creation only when connected.
 - Avoid sending `id=None` to ES (skip ID if missing).
 - Bulk indexing now omits `_id` when absent and returns consistent structure.
 - Added health / availability helper methods.
 - Defensive guards for every public method when ES is unavailable.
 - Removed unused imports & improved type hints & logging consistency.
"""

import logging
from datetime import datetime
from functools import wraps
from typing import Dict, List, Any, Callable, Optional, TypeVar

from elasticsearch import Elasticsearch, ConnectionError as ESConnectionError
from elasticsearch.helpers import bulk

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def connection_required(method: F) -> F:  # type: ignore
    """Decorator to ensure the Elasticsearch client is connected before executing.

    If not connected, logs a warning and returns a safe default based on method name.
    """
    @wraps(method)
    def wrapper(self: "CTIElasticsearchClient", *args: Any, **kwargs: Any):  # type: ignore
        if self.es is None:
            logger.warning(
                "Elasticsearch client not connected; skipping call to %s", method.__name__
            )
            # Safe defaults depending on expected return type
            if method.__name__.startswith("search"):
                return {"hits": {"total": {"value": 0}, "hits": []}}
            if method.__name__.startswith("get_"):
                return {}
            if method.__name__.startswith("delete_"):
                return 0
            return False
        return method(self, *args, **kwargs)

    return wrapper  # type: ignore

class CTIElasticsearchClient:
    """Elasticsearch client for CTI data indexing and querying.

    elastic_config is now optional – when omitted we attempt to pull values from
    the global `config` singleton (config.config_loader). This makes usage
    simpler for scripts that already load central configuration and resolves
    the previous runtime error where the client was constructed with no args.
    """
    
    def __init__(self, elastic_config: Optional[Dict[str, Any]] = None):
        # Late import to avoid circular dependency if config itself wants ES
        if elastic_config is None:
            try:  # type: ignore
                from config.config_loader import config as global_config  # local import
                elastic_section = getattr(global_config, 'elastic', {}) or {}
                # Accept legacy keys
                hosts = (elastic_section.get('elasticsearch', {}) or elastic_section).get('hosts')
                index = (elastic_section.get('elasticsearch', {}) or elastic_section).get('index')
                elastic_config = {
                    'connection': {
                        'hosts': hosts or getattr(global_config, 'ELASTICSEARCH_HOSTS', ['http://localhost:9200']),
                        'retries': 3,
                        'timeout': 10
                    },
                    'index_name': index or getattr(global_config, 'ELASTICSEARCH_INDEX', 'cti_intelligence')
                }
            except Exception:
                # Fallback to sane defaults
                elastic_config = {
                    'connection': {
                        'hosts': ['http://localhost:9200'],
                        'retries': 3,
                        'timeout': 10
                    },
                    'index_name': 'cti_intelligence'
                }

        es_conn_details = (elastic_config or {}).get("connection", {})
        self.hosts: List[str] = es_conn_details.get("hosts", ["http://localhost:9200"])
        self.index_name: str = (elastic_config or {}).get("index_name", "cti_intelligence")
        self.max_retries: int = int(es_conn_details.get("retries", 3))
        self.timeout: int = int(es_conn_details.get("timeout", 10))

        self.es: Optional[Elasticsearch] = None
        self.connected: bool = False

        self.connect()
        if self.connected:
            self.create_index_if_not_exists()

    # ------------------------------------------------------------------
    # Connection & health utilities
    # ------------------------------------------------------------------
    def connect(self) -> None:
        """Attempt to connect to Elasticsearch with retry logic."""
        for attempt in range(1, self.max_retries + 1):
            try:
                self.es = Elasticsearch(self.hosts, request_timeout=self.timeout)
                if self.es.ping():  # Simple health check
                    self.connected = True
                    logger.info(
                        "Connected to Elasticsearch at %s (attempt %d)", self.hosts, attempt
                    )
                    return
                else:
                    raise ESConnectionError("Ping to Elasticsearch failed")
            except Exception as exc:  # Broad on purpose: ES raises varied exceptions
                logger.warning(
                    "Elasticsearch connection attempt %d/%d failed: %s", attempt, self.max_retries, exc
                )
        # If we reach here, all attempts failed
        self.es = None
        self.connected = False
        logger.error("Failed to connect to Elasticsearch after %d attempts", self.max_retries)

    def is_available(self) -> bool:
        """Return True if connected and ping succeeds (cheap health check)."""
        if self.es is None:
            return False
        try:
            return bool(self.es.ping())
        except Exception:
            return False

    def refresh_index(self) -> bool:
        """Force a refresh of the index to make recent writes searchable sooner."""
        if self.es is None:
            return False
        try:
            self.es.indices.refresh(index=self.index_name)
            return True
        except Exception as exc:
            logger.error("Failed to refresh index '%s': %s", self.index_name, exc)
            return False
    
    def create_index_if_not_exists(self) -> None:
        """Create index with proper mappings if it doesn't exist (idempotent)."""
        if self.es is None:
            logger.debug("Skipping index creation; Elasticsearch not connected.")
            return

        try:
            if not self.es.indices.exists(index=self.index_name):
                mapping = self.get_index_mapping()
                body = {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0,
                        "analysis": {
                            "analyzer": {
                                "cti_analyzer": {
                                    "type": "custom",
                                    "tokenizer": "standard",
                                    "filter": ["lowercase", "stop"],
                                }
                            }
                        },
                    },
                    "mappings": mapping,
                }
                self.es.indices.create(index=self.index_name, body=body)
                logger.info("Created index '%s'", self.index_name)
            else:
                logger.debug("Index '%s' already exists", self.index_name)
        except Exception as exc:
            logger.error("Failed to create or verify index '%s': %s", self.index_name, exc)
    
    def get_index_mapping(self) -> Dict:
        """Get index mapping for CTI data."""
        return {
            "properties": {
                # Basic document fields
                "url": {"type": "keyword"},
                "title": {"type": "text", "analyzer": "cti_analyzer"},
                "content": {"type": "text", "analyzer": "cti_analyzer"},
                "content_hash": {"type": "keyword"},
                "crawled_at": {"type": "date"},
                "processed_at": {"type": "date"},
                "site_category": {"type": "keyword"},
                
                # Metadata
                "author": {"type": "keyword"},
                "post_date": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd||dd/MM/yyyy"},
                "thread_id": {"type": "keyword"},
                "post_id": {"type": "keyword"},
                "content_length": {"type": "integer"},
                
                # NLP processing results
                "threat_score": {"type": "integer"},
                "total_entities": {"type": "integer"},
                "entity_types_count": {"type": "integer"},
                
                # IOCs (Indicators of Compromise)
                "iocs": {
                    "properties": {
                        "ip_addresses": {"type": "ip"},
                        "ipv6_addresses": {"type": "keyword"},
                        "domains": {"type": "keyword"},
                        "onion_domains": {"type": "keyword"},
                        "urls": {"type": "keyword"},
                        "emails": {"type": "keyword"},
                        "md5_hashes": {"type": "keyword"},
                        "sha1_hashes": {"type": "keyword"},
                        "sha256_hashes": {"type": "keyword"},
                        "btc_addresses": {"type": "keyword"},
                        "eth_addresses": {"type": "keyword"},
                        "cves": {"type": "keyword"},
                        "executables": {"type": "keyword"},
                        "registry_keys": {"type": "keyword"},
                        "file_paths": {"type": "keyword"},
                        "mutexes": {"type": "keyword"},
                        "ports": {"type": "integer"}
                    }
                },
                
                # Entities
                "entities": {
                    "type": "nested",
                    "properties": {
                        "text": {"type": "keyword"},
                        "label": {"type": "keyword"},
                        "start": {"type": "integer"},
                        "end": {"type": "integer"},
                        "confidence": {"type": "float"}
                    }
                },
                
                # Threat intelligence
                "malware_families": {"type": "keyword"},
                "threat_actors": {"type": "keyword"},
                "attack_techniques": {"type": "keyword"},
                
                # Links and references
                "internal_links": {
                    "type": "nested",
                    "properties": {
                        "url": {"type": "keyword"},
                        "text": {"type": "text"}
                    }
                },
                
                # Geolocation (if available)
                "geo_location": {
                    "properties": {
                        "country": {"type": "keyword"},
                        "region": {"type": "keyword"},
                        "city": {"type": "keyword"},
                        "coordinates": {"type": "geo_point"}
                    }
                },
                
                # Tags and classification
                "tags": {"type": "keyword"},
                "classification": {"type": "keyword"},
                "severity": {"type": "keyword"},
                
                # Raw data reference
                "raw_data_file": {"type": "keyword"}
            }
        }
    
    @connection_required
    def index_document(self, doc_data: Dict[str, Any]) -> bool:
        """
        Index a single document.
        
        Args:
            doc_data: Document data to index
            
        Returns:
            True if successful, False otherwise
        """
        try:
            doc_data["processed_at"] = datetime.now().isoformat()
            doc_id = doc_data.get("content_hash")

            # Build kwargs to avoid sending id=None
            kwargs: Dict[str, Any] = {"index": self.index_name, "body": doc_data}
            if doc_id:
                kwargs["id"] = doc_id

            response = self.es.index(**kwargs)
            logger.debug(
                "Indexed document%s: %s result=%s",
                f" id={doc_id}" if doc_id else "",
                doc_data.get("url", "<no-url>"),
                response.get("result"),
            )
            return True
        except Exception as exc:
            logger.error("Failed to index document (hash=%s): %s", doc_data.get("content_hash"), exc)
            return False
    
    @connection_required
    def bulk_index_documents(self, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Bulk index multiple documents.
        
        Args:
            documents: List of documents to index
            
        Returns:
            Dictionary with success and error counts
        """
        if not documents:
            return {"success": 0, "errors": 0, "error_details": []}

        try:
            actions = []
            for doc in documents:
                doc["processed_at"] = datetime.now().isoformat()
                doc_id = doc.get("content_hash")
                action: Dict[str, Any] = {"_index": self.index_name, "_source": doc}
                if doc_id:
                    action["_id"] = doc_id
                actions.append(action)

            success_count, errors = bulk(
                self.es, actions, chunk_size=100, request_timeout=60, raise_on_error=False
            )
            error_count = len(errors) if errors else 0
            logger.info(
                "Bulk indexed: %d success, %d errors (requested %d)",
                success_count,
                error_count,
                len(documents),
            )
            return {"success": success_count, "errors": error_count, "error_details": errors or []}
        except Exception as exc:
            logger.error("Failed to bulk index documents: %s", exc)
            return {"success": 0, "errors": len(documents), "error_details": [str(exc)]}
    
    @connection_required
    def search_documents(self, query: Dict[str, Any], size: int = 10) -> Dict[str, Any]:
        """
        Search documents in the index.
        
        Args:
            query: Elasticsearch query
            size: Number of results to return
            
        Returns:
            Search results
        """
        try:
            response = self.es.search(index=self.index_name, body=query, size=size)
            return response
        except Exception as exc:
            logger.error("Search failed: %s", exc)
            return {"hits": {"total": {"value": 0}, "hits": []}}
    
    @connection_required
    def search_by_ioc(self, ioc_type: str, ioc_value: str) -> List[Dict[str, Any]]:
        """
        Search documents by IOC.
        
        Args:
            ioc_type: Type of IOC (e.g., 'ip_addresses', 'domains')
            ioc_value: IOC value to search for
            
        Returns:
            List of matching documents
        """
        query = {
            "query": {
                "term": {
                    f"iocs.{ioc_type}": ioc_value
                }
            }
        }
        
        response = self.search_documents(query, size=100)
        return [hit.get("_source", {}) for hit in response.get("hits", {}).get("hits", [])]
    
    @connection_required
    def search_by_threat_actor(self, actor_name: str) -> List[Dict[str, Any]]:
        """Search documents mentioning a specific threat actor."""
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"threat_actors": actor_name}},
                        {"match": {"content": actor_name}}
                    ]
                }
            }
        }
        
        response = self.search_documents(query, size=100)
        return [hit.get("_source", {}) for hit in response.get("hits", {}).get("hits", [])]
    
    @connection_required
    def search_by_malware_family(self, malware_name: str) -> List[Dict[str, Any]]:
        """Search documents mentioning a specific malware family."""
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"malware_families": malware_name}},
                        {"match": {"content": malware_name}}
                    ]
                }
            }
        }
        
        response = self.search_documents(query, size=100)
        return [hit.get("_source", {}) for hit in response.get("hits", {}).get("hits", [])]
    
    @connection_required
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        try:
            # Aggregation query for statistics
            query = {
                "size": 0,
                "aggs": {
                    "total_documents": {"value_count": {"field": "content_hash"}},
                    "avg_threat_score": {"avg": {"field": "threat_score"}},
                    "site_categories": {"terms": {"field": "site_category"}},
                    "top_malware_families": {"terms": {"field": "malware_families", "size": 10}},
                    "top_threat_actors": {"terms": {"field": "threat_actors", "size": 10}},
                    "documents_by_date": {
                        "date_histogram": {
                            "field": "crawled_at",
                            "calendar_interval": "day"
                        }
                    }
                }
            }
            
            response = self.es.search(index=self.index_name, body=query)
            aggs = response.get("aggregations", {})
            return {
                "total_documents": aggs.get("total_documents", {}).get("value", 0),
                "avg_threat_score": aggs.get("avg_threat_score", {}).get("value"),
                "site_categories": aggs.get("site_categories", {}).get("buckets", []),
                "top_malware_families": aggs.get("top_malware_families", {}).get("buckets", []),
                "top_threat_actors": aggs.get("top_threat_actors", {}).get("buckets", []),
                "documents_by_date": aggs.get("documents_by_date", {}).get("buckets", []),
            }
        except Exception as exc:
            logger.error("Failed to get statistics: %s", exc)
            return {}
    
    @connection_required
    def delete_old_documents(self, days_old: int = 30) -> int:
        """Delete documents older than specified days."""
        try:
            query = {
                "query": {
                    "range": {
                        "crawled_at": {
                            "lt": f"now-{days_old}d"
                        }
                    }
                }
            }
            
            response = self.es.delete_by_query(index=self.index_name, body=query)
            deleted_count = response.get("deleted", 0)
            logger.info("Deleted %d documents older than %d days", deleted_count, days_old)
            return deleted_count
        except Exception as exc:
            logger.error("Failed to delete old documents: %s", exc)
            return 0