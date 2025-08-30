import yaml
from pathlib import Path

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
        state_db = self.crawler.get('data_storage', {}).get('state_db', 'db/state.db')
        log_file = self.crawler.get('data_storage', {}).get('log_file', 'logs/app.log')

        self.RAW_DATA_DIR = self.BASE_DIR / raw_dir
        self.PROCESSED_DATA_DIR = self.BASE_DIR / processed_dir
        self.STATE_DB_PATH = self.BASE_DIR / state_db
        self.LOG_FILE = self.BASE_DIR / log_file

        # Ensure directories exist
        self.RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.STATE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Singleton instance
config = Config()
