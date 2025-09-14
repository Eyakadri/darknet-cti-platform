import pytest
from consumer.elasticsearch_client import CTIElasticsearchClient

class DummyES:
    def __init__(self):
        self.indexed = []
        class Indices:
            def exists(self_inner, index):
                return True
            def create(self_inner, index, body):
                pass
            def refresh(self_inner, index):
                pass
        self.indices = Indices()
    def ping(self):
        return True
    def index(self, **kwargs):
        self.indexed.append(kwargs)
        return {"result": "created"}

def test_index_document_monkeypatch(monkeypatch):
    client = CTIElasticsearchClient({"connection": {"hosts": ["http://localhost:9200"], "retries": 1}})
    # Force inject dummy ES
    dummy = DummyES()
    client.es = dummy
    client.connected = True
    doc = {"url": "http://example", "content_hash": "abc", "content": "test"}
    assert client.index_document(doc) is True
    assert dummy.indexed
