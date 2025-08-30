"""
Elasticsearch client for indexing CTI data.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from config.config_loader import config

logger = logging.getLogger(__name__)


class CTIElasticsearchClient:
    """Elasticsearch client for CTI data indexing and querying."""
    
    def __init__(self):
        self.hosts = config.ELASTICSEARCH_HOSTS
        self.index_name = config.ELASTICSEARCH_INDEX

        self.es = None
        self.connect()
        self.create_index_if_not_exists()
    
    def connect(self):
        """Connect to Elasticsearch cluster."""
        try:
            self.es = Elasticsearch(
                hosts=self.hosts,
                timeout=30,
                max_retries=3,
                retry_on_timeout=True
            )
            
            # Test connection
            if self.es.ping():
                logger.info(f"Connected to Elasticsearch: {self.hosts}")
            else:
                raise ConnectionError("Failed to ping Elasticsearch")
                
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            raise
    
    def create_index_if_not_exists(self):
        """Create index with proper mappings if it doesn't exist."""
        if not self.es.indices.exists(index=self.index_name):
            mapping = self.get_index_mapping()
            
            try:
                self.es.indices.create(
                    index=self.index_name,
                    body={
                        "settings": {
                            "number_of_shards": 1,
                            "number_of_replicas": 0,
                            "analysis": {
                                "analyzer": {
                                    "cti_analyzer": {
                                        "type": "custom",
                                        "tokenizer": "standard",
                                        "filter": ["lowercase", "stop"]
                                    }
                                }
                            }
                        },
                        "mappings": mapping
                    }
                )
                logger.info(f"Created index: {self.index_name}")
            except Exception as e:
                logger.error(f"Failed to create index: {e}")
                raise
        else:
            logger.info(f"Index already exists: {self.index_name}")
    
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
    
    def index_document(self, doc_data: Dict[str, Any]) -> bool:
        """
        Index a single document.
        
        Args:
            doc_data: Document data to index
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Add processing timestamp
            doc_data['processed_at'] = datetime.now().isoformat()
            
            # Use content hash as document ID to avoid duplicates
            doc_id = doc_data.get('content_hash', None)
            
            response = self.es.index(
                index=self.index_name,
                id=doc_id,
                body=doc_data
            )
            
            logger.debug(f"Indexed document: {doc_id} - {response['result']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to index document: {e}")
            return False
    
    def bulk_index_documents(self, documents: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Bulk index multiple documents.
        
        Args:
            documents: List of documents to index
            
        Returns:
            Dictionary with success and error counts
        """
        if not documents:
            return {"success": 0, "errors": 0}
        
        try:
            # Prepare documents for bulk indexing
            actions = []
            for doc in documents:
                doc['processed_at'] = datetime.now().isoformat()
                doc_id = doc.get('content_hash', None)
                
                action = {
                    "_index": self.index_name,
                    "_id": doc_id,
                    "_source": doc
                }
                actions.append(action)
            
            # Perform bulk indexing
            success_count, errors = bulk(
                self.es,
                actions,
                chunk_size=100,
                request_timeout=60
            )
            
            error_count = len(errors) if errors else 0
            
            logger.info(f"Bulk indexed: {success_count} success, {error_count} errors")
            
            return {
                "success": success_count,
                "errors": error_count,
                "error_details": errors
            }
            
        except Exception as e:
            logger.error(f"Failed to bulk index documents: {e}")
            return {"success": 0, "errors": len(documents)}
    
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
            response = self.es.search(
                index=self.index_name,
                body=query,
                size=size
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return {"hits": {"total": {"value": 0}, "hits": []}}
    
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
        return [hit["_source"] for hit in response["hits"]["hits"]]
    
    def search_by_threat_actor(self, actor_name: str) -> List[Dict[str, Any]]:
        """Search documents mentioning a specific threat actor."""
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"threat_actors": actor_name.lower()}},
                        {"match": {"content": actor_name}}
                    ]
                }
            }
        }
        
        response = self.search_documents(query, size=100)
        return [hit["_source"] for hit in response["hits"]["hits"]]
    
    def search_by_malware_family(self, malware_name: str) -> List[Dict[str, Any]]:
        """Search documents mentioning a specific malware family."""
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"malware_families": malware_name.lower()}},
                        {"match": {"content": malware_name}}
                    ]
                }
            }
        }
        
        response = self.search_documents(query, size=100)
        return [hit["_source"] for hit in response["hits"]["hits"]]
    
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
            
            return {
                "total_documents": response["aggregations"]["total_documents"]["value"],
                "avg_threat_score": response["aggregations"]["avg_threat_score"]["value"],
                "site_categories": response["aggregations"]["site_categories"]["buckets"],
                "top_malware_families": response["aggregations"]["top_malware_families"]["buckets"],
                "top_threat_actors": response["aggregations"]["top_threat_actors"]["buckets"],
                "documents_by_date": response["aggregations"]["documents_by_date"]["buckets"]
            }
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
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
            
            response = self.es.delete_by_query(
                index=self.index_name,
                body=query
            )
            
            deleted_count = response.get("deleted", 0)
            logger.info(f"Deleted {deleted_count} old documents")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to delete old documents: {e}")
            return 0
