# crawler/darknet_scraper/darknet_scraper/session_manager.py

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)

class SessionManager:
    """
    Manages session cookies and authentication tokens.
    An instance of this class is created by middlewares that need session data,
    and it gets its configuration from the Scrapy settings object.
    """
    def __init__(self, settings):
        """Initializes the SessionManager using Scrapy settings."""
        # Load the file path from Scrapy's settings, with a default value.
        sessions_file = settings.get('SESSIONS_FILE_PATH', 'data/sessions.json')
        self.sessions_file = Path(sessions_file)
        self.sessions_file.parent.mkdir(parents=True, exist_ok=True)
        self.sessions = {}
        self.load_sessions()

    def load_sessions(self):
        """Load sessions from the JSON file."""
        if not self.sessions_file.exists():
            logger.info("No sessions file found. Starting with empty session list.")
            self.sessions = {}
            return

        try:
            with open(self.sessions_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.sessions = data.get('sessions', {})
            logger.info(f"Loaded {len(self.sessions)} sessions from {self.sessions_file}")
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Could not read or decode {self.sessions_file}: {e}. Starting fresh.")
            self.sessions = {}

    def save_sessions(self):
        """Save the current sessions dictionary to the JSON file."""
        try:
            data = {
                'sessions': self.sessions,
                'last_updated': datetime.now().isoformat()
            }
            with open(self.sessions_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            logger.debug("Sessions saved to file.")
        except IOError as e:
            logger.error(f"Could not write to sessions file {self.sessions_file}: {e}")

    def add_session(self, domain: str, cookies: Dict[str, str],
                   headers: Optional[Dict[str, str]] = None,
                   expires_hours: int = 24):
        """
        Adds or updates a session for a given domain.
        This is an administrative method, typically called from a separate tool or script.
        """
        expires_at = (datetime.now() + timedelta(hours=expires_hours)).isoformat()
        session_data = {
            'cookies': cookies,
            'headers': headers or {},
            'created_at': datetime.now().isoformat(),
            'expires_at': expires_at,
            'last_used': None,
            'use_count': 0
        }
        self.sessions[domain] = session_data
        self.save_sessions()
        logger.info(f"Added/updated session for {domain} (expires in {expires_hours}h)")

    def get_session(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves valid session data for a domain.
        It automatically checks for expiration and returns None if the session is invalid.
        """
        session = self.sessions.get(domain)
        if not session:
            return None

        # Check for expiration
        expires_at = datetime.fromisoformat(session['expires_at'])
        if datetime.now() > expires_at:
            logger.info(f"Session expired for {domain}. Removing.")
            del self.sessions[domain]
            self.save_sessions()
            return None

        # Update usage stats before returning the session
        session['last_used'] = datetime.now().isoformat()
        session['use_count'] = session.get('use_count', 0) + 1
        self.save_sessions() # Save on get to persist usage stats

        logger.debug(f"Retrieved valid session for {domain}")
        return session

    def remove_session(self, domain: str):
        """Removes a session for a given domain."""
        if domain in self.sessions:
            del self.sessions[domain]
            self.save_sessions()
            logger.info(f"Removed session for {domain}")
