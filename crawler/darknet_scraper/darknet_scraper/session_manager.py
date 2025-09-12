# In crawler/darknet_scraper/darknet_scraper/session_manager.py

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Any
import requests # We need requests for the test_session method

logger = logging.getLogger(__name__)

class SessionManager:
    """
    Manages session cookies and authentication tokens, with methods
    callable by both the crawler and helper scripts.
    """
    def __init__(self, settings):
        """Initializes the SessionManager using Scrapy settings."""
        sessions_file = settings.get('SESSIONS_FILE_PATH', 'data/sessions.json')
        self.sessions_file = Path(sessions_file)
        self.sessions_file.parent.mkdir(parents=True, exist_ok=True)
        self.sessions: Dict[str, Any] = {}
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

    # --- Methods for session_helper.py ---

    def import_browser_cookies(self, domain: str, cookie_string: str, expires_hours: int = 24):
        """
        Parses a browser cookie string (e.g., "name1=value1; name2=value2")
        and adds it as a session.
        """
        cookies = {}
        for cookie_pair in cookie_string.split(';'):
            cookie_pair = cookie_pair.strip()
            if '=' in cookie_pair:
                name, value = cookie_pair.split('=', 1)
                cookies[name.strip()] = value.strip()
        
        if not cookies:
            raise ValueError("Cookie string was empty or invalid.")
            
        self.add_session(domain=domain, cookies=cookies, expires_hours=expires_hours)

    def list_sessions(self) -> Dict[str, Any]:
        """
        Returns a dictionary with the status of all managed sessions.
        """
        status_list = {}
        for domain, session in self.sessions.items():
            expires_at = datetime.fromisoformat(session['expires_at'])
            status_list[domain] = {
                'is_expired': datetime.now() > expires_at,
                'cookies_count': len(session.get('cookies', {})),
                'last_used': session.get('last_used')
            }
        return status_list

    def test_session(self, domain: str, test_url: str) -> bool:
        """
        Tests a session by making a real request to a test URL through the Tor proxy.
        """
        session = self.get_session(domain)
        if not session:
            return False

        # Define the Tor/Privoxy proxy. This should match your crawler's config.
        proxies = {
            'http': 'http://127.0.0.1:8118',
            'https': 'http://127.0.0.1:8118',
        }

        try:
            with requests.Session() as s:
                s.cookies.update(session['cookies'])
                s.headers.update(session.get('headers', {}))
                # Add the proxies to the request
                response = s.get(test_url, timeout=60, proxies=proxies) # Increased timeout for Tor

                if response.ok and "captcha" not in response.text.lower() and "login" not in response.text.lower():
                    return True
                # Log why the test failed for better debugging
                logger.warning(f"Test failed for {domain}. Status: {response.status_code}. Found 'captcha' or 'login' in response.")
                return False
        except requests.RequestException as e:
            logger.error(f"Test request for {test_url} failed: {e}")
            return False

    def cleanup_expired_sessions(self):
        """Removes all expired sessions from the file."""
        # We need to iterate over a copy of the keys since we're modifying the dict
        for domain in list(self.sessions.keys()):
            session = self.sessions[domain]
            expires_at = datetime.fromisoformat(session['expires_at'])
            if datetime.now() > expires_at:
                del self.sessions[domain]
                logger.info(f"Cleaned up expired session for {domain}")
        self.save_sessions()

    # --- Methods used by the Crawler ---

    def add_session(self, domain: str, cookies: Dict[str, str],
                   headers: Optional[Dict[str, str]] = None,
                   expires_hours: int = 24):
        """
        Adds or updates a session for a given domain.
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
        Retrieves valid session data for a domain, checking for expiration.
        """
        session = self.sessions.get(domain)
        if not session:
            return None

        expires_at = datetime.fromisoformat(session['expires_at'])
        if datetime.now() > expires_at:
            logger.info(f"Session expired for {domain}. Removing.")
            del self.sessions[domain]
            self.save_sessions()
            return None

        session['last_used'] = datetime.now().isoformat()
        session['use_count'] = session.get('use_count', 0) + 1
        self.save_sessions()

        logger.debug(f"Retrieved valid session for {domain}")
        return session

    def remove_session(self, domain: str):
        """Removes a session for a given domain."""
        if domain in self.sessions:
            del self.sessions[domain]
            self.save_sessions()
            logger.info(f"Removed session for {domain}")

