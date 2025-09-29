import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Iterable, List


# Import the class symbol directly so tests can monkeypatch
from elasticsearch import Elasticsearch  # type: ignore

logger = logging.getLogger(__name__)


class CTIElasticsearchClient:
    """Elasticsearch client wrapper used by the pipeline.

    Goals:
    - Keep a very small public surface (index_document only for now)
    - Be resilient when ES is not running (caller can check .connected)
    - Stay backward-compatible with earlier tests that passed a config dict.

    Parameters
    ----------
    elastic_config : dict | None
        Optional configuration. Supported shape:
        {
          "connection": {"hosts": ["http://localhost:9200"], "timeout": 10},
          "index_name": "cti_intelligence"
        }
    """

    def __init__(
        self,
        elastic_config: Optional[Dict[str, Any]] = None,
        es_client: Optional[Elasticsearch] = None,
    ):
        """Create a new Elasticsearch wrapper.

        Parameters
        ----------
        elastic_config : dict | None
            Optional configuration. Shape (example):
            {
              "connection": {
                "hosts": ["http://localhost:9200"],
                "timeout": 10,
                "api_key": ("id","key"),
                "basic_auth": ("user","pass"),
                "bearer_auth": "token",
                "verify_certs": True,
                "ca_certs": "/path/to/ca.pem"
              },
              "index_name": "cti_intelligence"
            }
        es_client : Elasticsearch | None
            Pre-instantiated low-level client (mainly for tests / dependency injection).
        """
        elastic_config = elastic_config or {}
        conn = elastic_config.get("connection", {}) or {}
        self.hosts = conn.get("hosts", ["http://localhost:9200"])
        self.timeout = int(conn.get("timeout", 10))
        self.index_name = elastic_config.get("index_name", "cti_intelligence")

        # Extract optional auth/TLS related parameters (whitelist for clarity)
        self._extra_conn_args: Dict[str, Any] = {}
        for key in (
            "api_key",
            "basic_auth",
            "bearer_auth",
            "verify_certs",
            "ca_certs",
            "ssl_show_warn",
            "request_timeout",  # allow override
        ):
            if key in conn:
                self._extra_conn_args[key] = conn[key]

        self.es: Optional[Elasticsearch] = es_client
        self.connected: bool = False

        if self.es is None:
            self._connect()
        else:  # Assume injected client already configured
            try:
                self.connected = bool(self.es.ping())
            except Exception:
                self.connected = False

        if self.connected:
            self.create_index_if_not_exists()

    # Internal helpers
    def _connect(self) -> None:
        """Attempt a single connection to Elasticsearch using current config."""
        try:
            # Allow request_timeout override via _extra_conn_args
            rt = self._extra_conn_args.get("request_timeout", self.timeout)
            self.es = Elasticsearch(self.hosts, request_timeout=rt, **self._extra_conn_args)
            if self.es.ping():
                self.connected = True
                logger.info("Elasticsearch connected (hosts=%s)", self.hosts)
            else:
                raise ConnectionError("Ping to Elasticsearch failed")
        except Exception as exc:  # pragma: no cover (network/ES specific branches)
            self.es = None
            self.connected = False
            logger.error("Failed to connect to Elasticsearch: %s (%s)", exc, exc.__class__.__name__)

    # ------------------------------------------------------------------
    # Public connection management helpers
    # ------------------------------------------------------------------
    def reconnect(self) -> bool:
        """Force a reconnect attempt. Returns True if connected afterwards."""
        self._connect()
        return self.connected

    def close(self) -> None:
        """Close underlying transport (best-effort)."""
        if self.es is not None:
            try:  # pragma: no cover (network specifics)
                self.es.transport.close()  # type: ignore[attr-defined]
            except Exception:
                pass
        self.connected = False

    def ping(self) -> bool:
        """Return True if cluster responds; updates connected flag."""
        if not self.es:
            return False
        try:
            self.connected = bool(self.es.ping())
        except Exception:
            self.connected = False
        return self.connected

    def create_index_if_not_exists(self) -> None:
        if not self.connected or not self.es:
            return
        try:
            # Some mocks may provide indices as a simple object already
            indices_client = getattr(self.es, "indices", None)
            if indices_client is None:
                logger.debug(
                    "Elasticsearch client has no 'indices' attribute (mock?) - skipping index creation"
                )
                return
            exists_fn = getattr(indices_client, "exists", None)
            if callable(exists_fn) and not exists_fn(index=self.index_name):
                # We rely on an external index template (cti_template) for mappings/settings.
                # Leaving explicit create logic commented for future explicit index creation if desired.
                # body = {"settings": {"number_of_shards": 1, "number_of_replicas": 0}, "mappings": self.get_index_mapping()}
                # create_fn = getattr(indices_client, "create", None)
                # if callable(create_fn):
                #     create_fn(index=self.index_name, body=body)
                #     logger.info("Created index '%s'", self.index_name)
                # else:
                #     logger.debug("No 'create' method on indices object (mock?) - cannot create index")
                logger.info(
                    "Index does not exist. It will be created automatically by Elasticsearch using the 'cti_template'."
                )
        except Exception as exc:  # pragma: no cover
            logger.error("Failed ensuring index '%s': %s", self.index_name, exc)

    def index_document(self, doc_data: Dict[str, Any]) -> bool:
        """Index a single document.

        Returns
        -------
        bool
            True on success, False otherwise.
        """
        if not self.connected or not self.es:
            logger.error("Cannot index document: Not connected to Elasticsearch.")
            return False
        try:
            # Work on a shallow copy so caller dict is not mutated unexpectedly.
            doc = dict(doc_data)
            processed_ts = datetime.now(timezone.utc).isoformat()
            doc.setdefault("processed_at", processed_ts)
            doc.setdefault("@timestamp", processed_ts)
            if "content" in doc and "content_length" not in doc:
                try:
                    doc["content_length"] = len(doc["content"])  # fallback derivation
                except Exception:
                    pass
            doc_id = doc.get("content_hash")
            try:
                self.es.index(index=self.index_name, id=doc_id, document=doc)  # type: ignore[arg-type]
            except TypeError:  # fallback for older client versions
                self.es.index(index=self.index_name, id=doc_id, body=doc)  # type: ignore
            logger.debug("Indexed document index=%s id=%s", self.index_name, doc_id)
            return True
        except Exception as exc:
            logger.error(
                "Failed to index document %s: %s", doc_data.get("content_hash"), exc
            )
            return False

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------
    def bulk_index_documents(self, docs: Iterable[Dict[str, Any]]) -> Dict[str, int]:
        """Bulk index a collection of documents.

        Parameters
        ----------
        docs : Iterable[dict]
            Iterator / list of documents (each similar to single index input).

        Returns
        -------
        dict
            { 'success': int, 'errors': int }
        """
        # Materialize in a list (we need potential multiple passes / length)
        docs_list: List[Dict[str, Any]] = list(docs)
        if not docs_list:
            return {"success": 0, "errors": 0}

        if not self.connected or not self.es:
            logger.error("bulk_index_documents: not connected; skipping (%d docs)", len(docs_list))
            return {"success": 0, "errors": len(docs_list)}

        try:  # Attempt fast path using helpers.bulk if available
            try:  # Local import (keeps import cost off hot path if unused)
                from elasticsearch import helpers as es_helpers  # type: ignore
            except Exception:  # pragma: no cover - helpers import failure
                es_helpers = None  # type: ignore

            actions = []
            now = datetime.now(timezone.utc).isoformat()
            for original in docs_list:
                doc = dict(original)
                doc.setdefault("processed_at", now)
                doc.setdefault("@timestamp", now)
                if "content" in doc and "content_length" not in doc:
                    try:
                        doc["content_length"] = len(doc["content"])  # derive
                    except Exception:
                        pass
                doc_id = doc.get("content_hash")
                action = {
                    "_op_type": "index",
                    "_index": self.index_name,
                    "_id": doc_id,
                    "_source": doc,
                }
                actions.append(action)

            if es_helpers is not None:
                try:
                    # stats_only -> returns (successes, errors)
                    successes, errors = es_helpers.bulk(  # type: ignore
                        self.es, actions, stats_only=True
                    )
                    if errors:
                        logger.warning(
                            "Bulk indexing completed with %d errors (success=%d)",
                            errors,
                            successes,
                        )
                    else:
                        logger.debug(
                            "Bulk indexing successful (count=%d)", successes
                        )
                    return {"success": int(successes), "errors": int(errors)}
                except Exception as exc:  # pragma: no cover (helpers.bulk failure)
                    logger.error(
                        "helpers.bulk failed (%s); falling back to per-doc indexing",
                        exc,
                    )

            # Fallback: per-document indexing
            success = 0
            errors = 0
            for action in actions:
                try:
                    try:
                        self.es.index(  # type: ignore
                            index=action["_index"],
                            id=action["_id"],
                            document=action["_source"],
                        )
                    except TypeError:
                        self.es.index(  # type: ignore
                            index=action["_index"],
                            id=action["_id"],
                            body=action["_source"],
                        )
                    success += 1
                except Exception as exc:
                    errors += 1
                    logger.error(
                        "Bulk fallback: failed to index id=%s: %s",
                        action.get("_id"),
                        exc,
                    )
            return {"success": success, "errors": errors}
        except Exception as outer_exc:  # pragma: no cover
            logger.error("bulk_index_documents: unexpected failure: %s", outer_exc)
            return {"success": 0, "errors": len(docs_list)}

    def get_index_mapping(self) -> dict:
        """
        Defines the structure (schema) of 'cti_intelligence' index.
        This tells Elasticsearch what kind of data to expect for each field.
        """
        return {
            "properties": {
                "url": {"type": "keyword"},
                "title": {"type": "text"},
                "content": {"type": "text"},
                "content_hash": {"type": "keyword"},
                "crawled_at": {"type": "date"},
                "processed_at": {"type": "date"},
                "site_category": {"type": "keyword"},
                "author": {"type": "keyword"},
                "post_date": {
                    "type": "date",
                    "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd||dd/MM/yyyy",
                },
                "thread_id": {"type": "keyword"},
                "post_id": {"type": "keyword"},
                "content_length": {"type": "integer"},
                "threat_score": {"type": "integer"},
                "iocs": {
                    "properties": {
                        "ip_addresses": {"type": "ip"},
                        "domains": {"type": "keyword"},
                        "onion_domains": {"type": "keyword"},
                        "urls": {"type": "keyword"},
                        "emails": {"type": "keyword"},
                        "sha256_hashes": {"type": "keyword"},
                        "cves": {"type": "keyword"},
                    }
                },
                "malware_families": {"type": "keyword"},
                "threat_actors": {"type": "keyword"},
                "geo_location": {
                    "properties": {
                        "country": {"type": "keyword"},
                        "region": {"type": "keyword"},
                        "city": {"type": "keyword"},
                        "coordinates": {"type": "geo_point"},
                    }
                },
                "image_urls": {"type": "keyword"},
                "breach_artifacts": {
                    "type": "nested",
                    "properties": {
                        "hash_type": {"type": "keyword"},
                        "hash_value": {"type": "keyword"},
                    },
                },
            }
        }

    # Convenience maintenance operations
    def refresh_index(self) -> bool:
        """Best-effort refresh of the target index so newly indexed docs
        become searchable immediately.

        Returns
        -------
        bool
            True if a refresh call was attempted successfully, False otherwise.
        """
        if not self.connected or not self.es:
            logger.debug("refresh_index: not connected; skipping")
            return False
        try:
            refresh_fn = getattr(self.es, "indices", None)
            if refresh_fn is None:
                logger.debug("refresh_index: client has no 'indices' attribute (mock?)")
                return False
            refresh_method = getattr(refresh_fn, "refresh", None)
            if callable(refresh_method):
                refresh_method(index=self.index_name)
                logger.debug("Refreshed index '%s'", self.index_name)
                return True
            logger.debug("refresh_index: no callable refresh method on indices object")
            return False
        except Exception as exc:  # pragma: no cover (network errors)
            logger.error("Failed to refresh index '%s': %s", self.index_name, exc)
            return False
