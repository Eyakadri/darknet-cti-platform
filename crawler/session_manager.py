"""
Session Manager for handling cookies and authentication tokens after manual CAPTCHA solving.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Any
import requests

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages session cookies and authentication tokens for crawler."""
    
    def __init__(self, sessions_file='data/sessions.json'):
        self.sessions_file = Path(sessions_file)
        self.sessions_file.parent.mkdir(parents=True, exist_ok=True)
        self.sessions = {}
        self.load_sessions()
    
    def load_sessions(self):
        """Load sessions from file."""
        try:
            if self.sessions_file.exists():
                with open(self.sessions_file, 'r') as f:
                    data = json.load(f)
                    self.sessions = data.get('sessions', {})
                logger.info(f"Loaded {len(self.sessions)} sessions")
            else:
                self.sessions = {}
                logger.info("No existing sessions file found")
        except Exception as e:
            logger.error(f"Error loading sessions: {e}")
            self.sessions = {}
    
    def save_sessions(self):
        """Save sessions to file."""
        try:
            data = {
                'sessions': self.sessions,
                'last_updated': datetime.now().isoformat()
            }
            with open(self.sessions_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug("Sessions saved to file")
        except Exception as e:
            logger.error(f"Error saving sessions: {e}")
    
    def add_session(self, domain: str, cookies: Dict[str, str], 
                   headers: Optional[Dict[str, str]] = None,
                   expires_hours: int = 24):
        """
        Add session cookies and headers for a domain.
        
        Args:
            domain: Domain name (e.g., 'example.onion')
            cookies: Dictionary of cookies
            headers: Optional additional headers
            expires_hours: Hours until session expires
        """
        try:
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
            
            logger.info(f"Added session for {domain} (expires in {expires_hours}h)")
            
        except Exception as e:
            logger.error(f"Error adding session for {domain}: {e}")
    
    def get_session(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get session data for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            Session data if valid, None otherwise
        """
        try:
            if domain not in self.sessions:
                logger.debug(f"No session found for {domain}")
                return None
            
            session = self.sessions[domain]
            
            # Check if session has expired
            expires_at = datetime.fromisoformat(session['expires_at'])
            if datetime.now() > expires_at:
                logger.info(f"Session expired for {domain}")
                del self.sessions[domain]
                self.save_sessions()
                return None
            
            # Update usage statistics
            session['last_used'] = datetime.now().isoformat()
            session['use_count'] += 1
            self.save_sessions()
            
            logger.debug(f"Retrieved session for {domain}")
            return session
            
        except Exception as e:
            logger.error(f"Error getting session for {domain}: {e}")
            return None
    
    def remove_session(self, domain: str):
        """Remove session for a domain."""
        try:
            if domain in self.sessions:
                del self.sessions[domain]
                self.save_sessions()
                logger.info(f"Removed session for {domain}")
            else:
                logger.debug(f"No session to remove for {domain}")
        except Exception as e:
            logger.error(f"Error removing session for {domain}: {e}")
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions."""
        try:
            expired_domains = []
            current_time = datetime.now()
            
            for domain, session in self.sessions.items():
                expires_at = datetime.fromisoformat(session['expires_at'])
                if current_time > expires_at:
                    expired_domains.append(domain)
            
            for domain in expired_domains:
                del self.sessions[domain]
            
            if expired_domains:
                self.save_sessions()
                logger.info(f"Cleaned up {len(expired_domains)} expired sessions")
            
        except Exception as e:
            logger.error(f"Error cleaning up expired sessions: {e}")
    
    def list_sessions(self) -> Dict[str, Dict[str, Any]]:
        """List all active sessions with their status."""
        try:
            session_status = {}
            current_time = datetime.now()
            
            for domain, session in self.sessions.items():
                expires_at = datetime.fromisoformat(session['expires_at'])
                is_expired = current_time > expires_at
                
                status = {
                    'domain': domain,
                    'created_at': session['created_at'],
                    'expires_at': session['expires_at'],
                    'last_used': session.get('last_used'),
                    'use_count': session.get('use_count', 0),
                    'is_expired': is_expired,
                    'cookies_count': len(session.get('cookies', {})),
                    'has_headers': bool(session.get('headers', {}))
                }
                
                session_status[domain] = status
            
            return session_status
            
        except Exception as e:
            logger.error(f"Error listing sessions: {e}")
            return {}
    
    def test_session(self, domain: str, test_url: str) -> bool:
        """
        Test if a session is still valid by making a test request.
        
        Args:
            domain: Domain name
            test_url: URL to test the session against
            
        Returns:
            True if session is valid, False otherwise
        """
        try:
            session = self.get_session(domain)
            if not session:
                return False
            
            # Prepare request with session data
            cookies = session.get('cookies', {})
            headers = session.get('headers', {})
            
            # Add default headers if not present
            if 'User-Agent' not in headers:
                headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            
            # Configure proxy for Tor
            proxies = {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }
            
            # Make test request
            response = requests.get(
                test_url,
                cookies=cookies,
                headers=headers,
                proxies=proxies,
                timeout=30,
                allow_redirects=True
            )
            
            # Check if we're still authenticated (not redirected to login/captcha)
            if response.status_code == 200:
                # Simple heuristic: if we don't see common captcha/login indicators
                content_lower = response.text.lower()
                captcha_indicators = ['captcha', 'recaptcha', 'hcaptcha', 'cloudflare', 'please verify']
                login_indicators = ['login', 'sign in', 'authenticate', 'access denied']
                
                has_captcha = any(indicator in content_lower for indicator in captcha_indicators)
                needs_login = any(indicator in content_lower for indicator in login_indicators)
                
                if not has_captcha and not needs_login:
                    logger.info(f"Session test passed for {domain}")
                    return True
                else:
                    logger.warning(f"Session test failed for {domain} - captcha/login required")
                    return False
            else:
                logger.warning(f"Session test failed for {domain} - HTTP {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error testing session for {domain}: {e}")
            return False
    
    def import_browser_cookies(self, domain: str, cookie_string: str, expires_hours: int = 24):
        """
        Import cookies from browser cookie string format.
        
        Args:
            domain: Domain name
            cookie_string: Cookie string from browser (e.g., "name1=value1; name2=value2")
            expires_hours: Hours until session expires
        """
        try:
            cookies = {}
            
            # Parse cookie string
            for cookie_pair in cookie_string.split(';'):
                cookie_pair = cookie_pair.strip()
                if '=' in cookie_pair:
                    name, value = cookie_pair.split('=', 1)
                    cookies[name.strip()] = value.strip()
            
            if cookies:
                self.add_session(domain, cookies, expires_hours=expires_hours)
                logger.info(f"Imported {len(cookies)} cookies for {domain}")
            else:
                logger.warning("No valid cookies found in cookie string")
                
        except Exception as e:
            logger.error(f"Error importing browser cookies: {e}")


# Global session manager instance
session_manager = SessionManager()


def get_session_for_request(url: str) -> Dict[str, Any]:
    """
    Get session data (cookies and headers) for a request URL.
    
    Args:
        url: Request URL
        
    Returns:
        Dictionary with 'cookies' and 'headers' keys
    """
    try:
        from urllib.parse import urlparse
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        session = session_manager.get_session(domain)
        
        if session:
            return {
                'cookies': session.get('cookies', {}),
                'headers': session.get('headers', {})
            }
        else:
            return {'cookies': {}, 'headers': {}}
            
    except Exception as e:
        logger.error(f"Error getting session for request {url}: {e}")
        return {'cookies': {}, 'headers': {}}

