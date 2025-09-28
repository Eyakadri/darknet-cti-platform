# In tests/test_elasticsearch_client.py

import pytest
from consumer.elasticsearch_client import CTIElasticsearchClient

# This is a fake (or "mock" ) object that pretends to be the real Elasticsearch client.
# It allows us to test our code without needing a real database.
class MockElasticsearch:
    def __init__(self, hosts, request_timeout):  # signature aligned with real client usage
        self._last_index_call = None
        # Provide an indices attribute mimicking elasticsearch client
        class MockIndices:
            def exists(self, index):
                return True  # Pretend index exists
            def create(self, index, body):
                return {"acknowledged": True, "index": index}
            def refresh(self, index=None):
                # Track refresh calls for assertions
                self._refreshed_index = index
        self.indices = MockIndices()

    def ping(self):
        return True

    def index(self, index, id, document=None, body=None, **kwargs):
        # Support both 'document' (8.x) and 'body' (7.x fallback)
        doc = document if document is not None else body
        self.last_call_args = {"index": index, "id": id, "document": doc}
        return {"result": "created"}


@pytest.fixture
def mock_es_client(monkeypatch):
    """
    This fixture creates an instance of our CTIElasticsearchClient,
    but it cleverly replaces the real Elasticsearch with our fake MockElasticsearch.
    """
    # When the code tries to import 'Elasticsearch' from the 'elasticsearch' library,
    # monkeypatch will give it our fake MockElasticsearch class instead.
    monkeypatch.setattr("consumer.elasticsearch_client.Elasticsearch", MockElasticsearch)
    
    # Now, when we create our client, its __init__ method will use the fake class.
    client = CTIElasticsearchClient()
    return client


def test_index_document_with_mock(mock_es_client):
    """
    Tests that index_document correctly calls the underlying es.index method.
    This test uses the mock_es_client and does NOT require a running database.
    """
    # 1. Arrange: Get the mocked client from the fixture and create a sample document.
    client = mock_es_client
    sample_doc = {
        "content_hash": "my-unique-hash-123",
        "title": "Test Document"
    }

    # 2. Act: Call the method we want to test.
    success = client.index_document(sample_doc)

    # 3. Assert: Check that the outcome is what we expect.
    
    # The method should report success.
    assert success is True

    # The 'es' attribute of our client is an instance of our MockElasticsearch class.
    # We can inspect it to see if it was used correctly.
    mock_es_instance = client.es
    
    # Check that the ID passed to the 'index' method was correct.
    assert mock_es_instance.last_call_args["id"] == "my-unique-hash-123"
    
    # Check that our method added the 'processed_at' timestamp to the document.
    assert "processed_at" in mock_es_instance.last_call_args["document"]


def test_refresh_index_with_mock(monkeypatch):
    """Ensure refresh_index attempts a refresh when connected and handles absence gracefully."""
    monkeypatch.setattr("consumer.elasticsearch_client.Elasticsearch", MockElasticsearch)
    client = CTIElasticsearchClient()
    assert client.connected is True
    # Invoke refresh_index
    success = client.refresh_index()
    assert success is True
    # Access the mock indices object to confirm attribute was set
    indices_obj = client.es.indices  # type: ignore
    assert getattr(indices_obj, "_refreshed_index", None) == client.index_name
