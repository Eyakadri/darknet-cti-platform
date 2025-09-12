"""
NLP Processor for extracting CTI entities from text using spaCy.
"""

import re
import yaml
import spacy
import logging
from pathlib import Path
from spacy.pipeline import EntityRuler
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

        # Setup custom entities from YAML
        self.entity_ruler = EntityRuler(self.nlp, overwrite_ents=True)
        self.setup_custom_entities()
        self.nlp.add_pipe(self.entity_ruler, before="ner")

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
        """Apply lowercase, lemmatization, and stopword removal."""
        if not text or len(text.strip()) < 10:
            return text

        doc = self.nlp.make_doc(text)

        tokens = []
        for token in doc:
            t = token.text
            if self.lowercase:
                t = t.lower()
            if self.lemmatize:
                t = token.lemma_
            if self.remove_stopwords and t in self.stopwords:
                continue
            tokens.append(t)
        return " ".join(tokens)

    def process_text(self, text: str) -> Dict[str, Any]:
        """Process text and extract CTI entities."""
        if not text or len(text.strip()) < 10:
            return {"entities": [], "text_length": 0, "processed": False}

        try:
            preprocessed = self.preprocess_text(text)
            doc = self.nlp(preprocessed)

            entities = []
            for ent in doc.ents:
                entities.append({
                    "text": ent.text,
                    "label": ent.label_,
                    "start": ent.start_char,
                    "end": ent.end_char,
                    "confidence": getattr(ent, "confidence", 1.0)
                })

            # Group entities by type
            entities_by_type = {}
            for entity in entities:
                label = entity["label"]
                entities_by_type.setdefault(label, []).append(entity)

            # Additional regex-based patterns
            additional_entities = self.extract_additional_patterns(text)
            for entity in additional_entities:
                entities_by_type.setdefault(entity["label"], []).append(entity)

            stats = {
                "total_entities": len(entities) + len(additional_entities),
                "entity_types": len(entities_by_type),
                "entities_by_type": {k: len(v) for k, v in entities_by_type.items()}
            }

            result = {
                "entities": entities + additional_entities,
                "entities_by_type": entities_by_type,
                "stats": stats,
                "text_length": len(text),
                "processed": True
            }

            logger.debug(f"Processed text: {len(text)} chars, {stats['total_entities']} entities")
            return result

        except Exception as e:
            logger.error(f"Error processing text: {e}")
            return {"entities": [], "text_length": len(text), "processed": False, "error": str(e)}

    def extract_additional_patterns(self, text: str) -> List[Dict]:
        """Extract additional patterns using regex that spaCy might miss."""
        additional_entities = []

        patterns = {
            "REGISTRY_KEY": r"HKEY_[A-Z_]+\\[\\A-Za-z0-9_\-\s]+",
            "FILE_PATH": r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*",
            "MUTEX": r"Global\\[A-Za-z0-9_\-]+",
            "SERVICE_NAME": r"svchost\.exe|winlogon\.exe|explorer\.exe|lsass\.exe|csrss\.exe",
            "PORT_NUMBER": r"\b(?:port\s+)?(\d{1,5})\b",
            "USER_AGENT": r"Mozilla/[0-9.]+|Chrome/[0-9.]+|Safari/[0-9.]+",
        }

        for label, regex in patterns.items():
            for match in re.finditer(regex, text, re.IGNORECASE):
                additional_entities.append({
                    "text": match.group(),
                    "label": label,
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.8
                })

        return additional_entities

    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise (IOCs) from text."""
        result = self.process_text(text)

        ioc_mapping = {
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

        iocs = {}
        for entity in result.get("entities", []):
            label = entity["label"]
            if label in ioc_mapping:
                ioc_type = ioc_mapping[label]
                iocs.setdefault(ioc_type, [])
                if entity["text"] not in iocs[ioc_type]:
                    iocs[ioc_type].append(entity["text"])
        return iocs

    def get_threat_intelligence_summary(self, text: str) -> Dict[str, Any]:
        """Get a comprehensive threat intelligence summary from text."""
        result = self.process_text(text)
        iocs = self.extract_iocs(text)

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
            "text_length": result.get("text_length", 0)
        }
