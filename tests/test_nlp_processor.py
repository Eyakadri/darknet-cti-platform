import pytest
import pytest  # duplicate import harmless; kept minimal edit (could remove)
try:
    from consumer.nlp_processor import CTINLPProcessor
except Exception as e:  # pragma: no cover
    CTINLPProcessor = None  # type: ignore


@pytest.mark.skipif(CTINLPProcessor is None, reason="spaCy model not available")
def test_basic_entity_extraction():
    proc = CTINLPProcessor()  # type: ignore
    text = "This sample references CVE-2024-1234 and connects to 192.168.1.10 with BTC address 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    summary = proc.get_threat_intelligence_summary(text)
    entities = summary['entities']
    labels = {e['label'] for e in entities}
    assert 'CVE' in labels
    assert summary['iocs']['ip_addresses']
    assert summary['iocs']['btc_addresses']
    assert summary['threat_score'] >= 0  # non-negative sanity
