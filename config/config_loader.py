import yaml
from pathlib import Path

# Central config loader. Simple singleton so the rest of the code can just do:
#   from config.config_loader import config
# and not worry about re-reading YAML or path setup. Keeps things DRY.

class Config:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._load_yaml_configs()
            cls._instance._set_paths()
        return cls._instance

    def _load_yaml_configs(self):
        self.BASE_DIR = Path(__file__).resolve().parent.parent
        config_dir = self.BASE_DIR / 'config'

        # Load crawler config
        with open(config_dir / 'crawler_config.yaml', 'r', encoding='utf-8') as f:
            self.crawler = yaml.safe_load(f)

        # Load elastic config
        with open(config_dir / 'elastic_config.yaml', 'r', encoding='utf-8') as f:
            self.elastic = yaml.safe_load(f)

        # Load NLP config
        with open(config_dir / 'nlp_config.yaml', 'r', encoding='utf-8') as f:
            self.nlp = yaml.safe_load(f)

    def _set_paths(self):
        # Default directories (can be in crawler_config.yaml too)
        raw_dir = self.crawler.get('data_storage', {}).get('raw_dir', 'data/raw')
        processed_dir = self.crawler.get('data_storage', {}).get('processed_dir', 'data/processed')

        self.RAW_DATA_DIR = self.BASE_DIR / raw_dir
        self.PROCESSED_DATA_DIR = self.BASE_DIR / processed_dir

        # Ensure directories exist
        self.RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Elasticsearch configuration exposure
        es_section = (self.elastic or {}).get('elasticsearch', {}) if hasattr(self, 'elastic') else {}
        self.ELASTICSEARCH_HOSTS = es_section.get('hosts', ['http://localhost:9200'])
        self.ELASTICSEARCH_INDEX = es_section.get('index', 'cti_intelligence')

        # Logging level fallback
        logging_section = (self.elastic or {}).get('logging', {}) if hasattr(self, 'elastic') else {}
        self.LOG_LEVEL = logging_section.get('level', 'INFO')

# Singleton instance
config = Config()
