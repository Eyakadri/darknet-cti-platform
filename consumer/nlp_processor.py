"""
NLP Processor for extracting CTI entities from text using spaCy.
"""

import re
import yaml
import spacy
import logging
from pathlib import Path
from spacy.lang.en.stop_words import STOP_WORDS
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class CTINLPProcessor:
    """NLP processor for extracting cyber threat intelligence entities."""

    def __init__(self, config_path: str = "config/nlp_config.yaml"):
        # Load YAML config
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

        # Load spaCy model
        self.model_name = self.config.get("models", ["en_core_web_sm"])[0]
        try:
            self.nlp = spacy.load(self.model_name)
            logger.info(f"Loaded spaCy model: {self.model_name}")
        except OSError:
            logger.error(f"Could not load spaCy model: {self.model_name}")
            raise

        # Preprocessing options
        self.lowercase = self.config.get("lowercase", True)
        self.lemmatize = self.config.get("lemmatize", True)
        self.remove_stopwords = self.config.get("remove_stopwords", True)

        # Stopwords (spaCy built-in)
        self.stopwords = STOP_WORDS if self.remove_stopwords else set()

        # Setup custom entities from YAML using spaCy v3 API
        # Add/ensure entity_ruler exists early before 'ner' so patterns can override
        if 'entity_ruler' in self.nlp.pipe_names:
            self.entity_ruler = self.nlp.get_pipe('entity_ruler')
        else:
            # create via factory name to be compatible with spaCy v3+ (E966 fix)
            self.entity_ruler = self.nlp.add_pipe('entity_ruler', before='ner', config={'overwrite_ents': True})
        self.setup_custom_entities()

        # Precompile IOC / artifact regex patterns (broad but bounded)
        self.compiled_patterns = {
            'IP_ADDRESS': re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
            'IPV6_ADDRESS': re.compile(r'\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b', re.IGNORECASE),
            'DOMAIN': re.compile(r'\b(?:(?!\d+\b)[a-z0-9-]{2,63}\.)+(?:[a-z]{2,24})\b', re.IGNORECASE),
            'ONION_DOMAIN': re.compile(r'\b[a-z2-7]{16,56}\.onion\b'),
            'EMAIL': re.compile(r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b', re.IGNORECASE),
            'URL': re.compile(r'\bhttps?://[\w\-.:/%?#=&;+,@()~]+', re.IGNORECASE),
            'MD5_HASH': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'SHA1_HASH': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'SHA256_HASH': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'BTC_ADDRESS': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
            'ETH_ADDRESS': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
            'CVE': re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
            'PORT_NUMBER': re.compile(r'\b(?:port\s+)?(\d{1,5})\b', re.IGNORECASE),
            'REGISTRY_KEY': re.compile(r'HKEY_[A-Z_]+\\[\\A-Za-z0-9_\-\s]+'),
            'FILE_PATH': re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'),
            'MUTEX': re.compile(r'Global\\[A-Za-z0-9_\-]+'),
            'USER_AGENT': re.compile(r'Mozilla/[0-9.]+|Chrome/[0-9.]+|Safari/[0-9.]+'),
        }

        # Load regex extraction behavior config safely
        self.regex_cfg = self.config.get('regex_extraction', {}) or {}
        self.regex_enabled = self.regex_cfg.get('enabled', True)
        self.regex_prefer = self.regex_cfg.get('prefer', 'ruler').lower()  # 'ruler' or 'regex'
        self.regex_include = set(self.regex_cfg.get('include') or [])
        self.regex_exclude = set(self.regex_cfg.get('exclude') or [])
        self.regex_drop_overlapping = self.regex_cfg.get('drop_overlapping', True)
        self.regex_skip_yaml = self.regex_cfg.get('skip_labels_from_yaml', True)

        if self.regex_skip_yaml:
            yaml_labels = set(self.config.get('custom_entities', {}).keys())
            # Remove overlapping labels from compiled patterns unless explicitly forced by include
            for lbl in list(self.compiled_patterns.keys()):
                if lbl in yaml_labels and (not self.regex_include or lbl not in self.regex_include):
                    self.compiled_patterns.pop(lbl, None)

        # If include is set, prune compiled patterns not in include
        if self.regex_include:
            for lbl in list(self.compiled_patterns.keys()):
                if lbl not in self.regex_include:
                    self.compiled_patterns.pop(lbl, None)

        # Explicit excludes
        for lbl in list(self.compiled_patterns.keys()):
            if lbl in self.regex_exclude:
                self.compiled_patterns.pop(lbl, None)

        logger.info(f"Regex extraction enabled={self.regex_enabled}; patterns={list(self.compiled_patterns.keys())}")

        # Cache IOC mapping for reuse
        self.ioc_mapping = {
            "IP_ADDRESS": "ip_addresses",
            "IPV6_ADDRESS": "ipv6_addresses",
            "DOMAIN": "domains",
            "ONION_DOMAIN": "onion_domains",
            "URL": "urls",
            "EMAIL": "emails",
            "MD5_HASH": "md5_hashes",
            "SHA1_HASH": "sha1_hashes",
            "SHA256_HASH": "sha256_hashes",
            "BTC_ADDRESS": "btc_addresses",
            "ETH_ADDRESS": "eth_addresses",
            "CVE": "cves",
            "EXECUTABLE": "executables",
            "REGISTRY_KEY": "registry_keys",
            "FILE_PATH": "file_paths",
            "MUTEX": "mutexes",
            "PORT_NUMBER": "ports"
        }

    def setup_custom_entities(self):
        """Setup custom entity ruler from YAML."""
        patterns = []

        custom_entities = self.config.get("custom_entities", {})
        for label, regex in custom_entities.items():
            patterns.append({
                "label": label,
                "pattern": [{"TEXT": {"REGEX": regex}}]
            })

        # Malware families
        for malware in self.config.get("malware_families", []):
            patterns.append({
                "label": "MALWARE_FAMILY",
                "pattern": [{"LOWER": malware.lower()}]
            })

        # Threat actors
        for actor in self.config.get("threat_actors", []):
            if " " in actor:
                pattern = [{"LOWER": word} for word in actor.lower().split()]
            else:
                pattern = [{"LOWER": actor.lower()}]
            patterns.append({
                "label": "THREAT_ACTOR",
                "pattern": pattern
            })

        self.entity_ruler.add_patterns(patterns)
        logger.info(f"Added {len(patterns)} CTI entity patterns")

    def preprocess_text(self, text: str) -> str:
        """Return a normalized version of text for auxiliary analytics (NOT used for NER offsets)."""
        if not text or len(text.strip()) < 10:
            return text
        # Lightweight tokenization without full pipeline to avoid double NER work
        doc = self.nlp.make_doc(text)
        out_tokens = []
        for token in doc:
            t = token.text
            if self.lowercase:
                t = t.lower()
            if self.lemmatize:
                # fallback to lower if lemma empty
                lemma = getattr(token, 'lemma_', '')
                if lemma:
                    t = lemma.lower() if self.lowercase else lemma
            if self.remove_stopwords and t in self.stopwords:
                continue
            out_tokens.append(t)
        return " ".join(out_tokens)

    def process_text(self, text: str) -> Dict[str, Any]:
        """Process original text for NER; keep normalization separate to preserve offsets."""
        if not text or len(text.strip()) < 10:
            return {"entities": [], "text_length": len(text or ''), "processed": False, "normalized_text": text}
        try:
            MAX_CHARS = 20000  # heuristic chunk size limit
            entities = []  # ruler (spaCy pipeline + entity ruler) sourced
            if len(text) <= MAX_CHARS:
                doc = self.nlp(text)
                entities.extend([
                    {
                        'text': ent.text,
                        'label': ent.label_,
                        'start': ent.start_char,
                        'end': ent.end_char,
                        'confidence': getattr(ent, 'confidence', 1.0),
                        'source': 'ruler'
                    } for ent in doc.ents
                ])
            else:
                # Chunk on sentence boundaries if possible, fallback to fixed-size slices
                logger.debug(f"Large text ({len(text)} chars) – applying chunked NER")
                offset = 0
                while offset < len(text):
                    chunk = text[offset: offset + MAX_CHARS]
                    doc = self.nlp(chunk)
                    for ent in doc.ents:
                        entities.append({
                            'text': ent.text,
                            'label': ent.label_,
                            'start': ent.start_char + offset,
                            'end': ent.end_char + offset,
                            'confidence': getattr(ent, 'confidence', 1.0),
                            'source': 'ruler'
                        })
                    offset += MAX_CHARS
            entities_by_type = {}
            for e in entities:
                entities_by_type.setdefault(e['label'], []).append(e)

            # Regex-based extras operate on ORIGINAL text to preserve offsets
            additional_entities = []
            if self.regex_enabled and self.compiled_patterns:
                additional_entities = self.extract_additional_patterns(text)
            merged_entities = entities + additional_entities

            # Dedupe / conflict resolution if configured
            final_entities = self._dedupe_entities(merged_entities)

            # Rebuild entities_by_type from final entities
            entities_by_type = {}
            for e in final_entities:
                entities_by_type.setdefault(e['label'], []).append(e)

            stats = {
                'total_entities': sum(len(v) for v in entities_by_type.values()),
                'entity_types': len(entities_by_type),
                'entities_by_type': {k: len(v) for k, v in entities_by_type.items()}
            }
            normalized_text = self.preprocess_text(text)
            return {
                'entities': final_entities,
                'entities_by_type': entities_by_type,
                'stats': stats,
                'text_length': len(text),
                'normalized_text': normalized_text,
                'processed': True
            }
        except Exception as e:
            logger.error(f"Error processing text: {e}")
            return {"entities": [], "text_length": len(text), "processed": False, "error": str(e), 'normalized_text': ''}

    def extract_additional_patterns(self, text: str) -> List[Dict]:
        """Extract additional patterns using regex that spaCy might miss."""
        additional_entities: List[Dict] = []
        for label, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(text):
                additional_entities.append({
                    'text': match.group(1) if label == 'PORT_NUMBER' and match.lastindex else match.group(),
                    'label': label,
                    'start': match.start(1) if label == 'PORT_NUMBER' and match.lastindex else match.start(),
                    'end': match.end(1) if label == 'PORT_NUMBER' and match.lastindex else match.end(),
                    'confidence': 0.8,
                    'source': 'regex'
                })
        return additional_entities

    def _dedupe_entities(self, entities: List[Dict]) -> List[Dict]:
        if not entities:
            return entities
        # Apply include/exclude early (case-insensitive label logic not needed since labels normalized)
        filtered = []
        for e in entities:
            label = e['label']
            if self.regex_include and label not in self.regex_include:
                continue
            if label in self.regex_exclude:
                continue
            filtered.append(e)

        if not self.regex_drop_overlapping:
            return filtered

        # Key by span + label; if conflict choose per preference
        by_key = {}
        for e in filtered:
            key = (e['label'], e['start'], e['end'], e['text'].lower())
            existing = by_key.get(key)
            if not existing:
                by_key[key] = e
                continue
            # conflict resolution: prefer configured source
            if self.regex_prefer == 'regex' and existing.get('source') == 'ruler' and e.get('source') == 'regex':
                by_key[key] = e
            elif self.regex_prefer == 'ruler' and existing.get('source') == 'regex' and e.get('source') == 'ruler':
                by_key[key] = e
            # else keep existing

        # Optional: could remove nested overlaps (different spans) – keep simple for now
        return list(by_key.values())

    def extract_iocs(self, text: str, result: Dict[str, Any] = None) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise (IOCs) from text.

        Avoids re-running NLP if a processed result dict is provided.
        """
        if result is None:
            result = self.process_text(text)
        iocs: Dict[str, List[str]] = {}
        for entity in result.get("entities", []):
            label = entity["label"]
            mapped = self.ioc_mapping.get(label)
            if not mapped:
                continue
            bucket = iocs.setdefault(mapped, [])
            if entity["text"] not in bucket:
                bucket.append(entity["text"])
        return iocs

    def get_threat_intelligence_summary(self, text: str) -> Dict[str, Any]:
        """Get a comprehensive threat intelligence summary from text (single NLP pass)."""
        result = self.process_text(text)
        iocs = self.extract_iocs(text, result=result)

        threat_indicators = {
            "malware_families": len(result.get("entities_by_type", {}).get("MALWARE_FAMILY", [])),
            "threat_actors": len(result.get("entities_by_type", {}).get("THREAT_ACTOR", [])),
            "cves": len(result.get("entities_by_type", {}).get("CVE", [])),
            "total_iocs": sum(len(v) for v in iocs.values()),
            "unique_domains": len(iocs.get("domains", [])) + len(iocs.get("onion_domains", [])),
            "ip_addresses": len(iocs.get("ip_addresses", [])),
            "file_hashes": len(iocs.get("md5_hashes", [])) + len(iocs.get("sha1_hashes", [])) + len(iocs.get("sha256_hashes", [])),
            "crypto_addresses": len(iocs.get("btc_addresses", [])) + len(iocs.get("eth_addresses", []))
        }

        threat_score = (
            threat_indicators["malware_families"] * 10 +
            threat_indicators["threat_actors"] * 15 +
            threat_indicators["cves"] * 20 +
            threat_indicators["total_iocs"] * 2
        )

        return {
            "threat_score": min(threat_score, 100),
            "threat_indicators": threat_indicators,
            "iocs": iocs,
            "entities": result.get("entities", []),
            "processing_stats": result.get("stats", {}),
            "normalized_text": result.get("normalized_text"),
            "text_length": result.get("text_length", 0)
        }
