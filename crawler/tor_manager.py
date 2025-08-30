"""
Tor Manager for handling Tor circuit management and proxy configuration.
"""

import time
import logging
from stem import Signal
from stem.control import Controller
from stem.util import term
import requests
import socket
from config.config_loader import config

logger = logging.getLogger(__name__)


class TorManager:
    """Manages Tor connections and circuit rotation."""
    
    def __init__(self):
        self.control_port = config.TOR_CONTROL_PORT
        self.control_password = config.TOR_CONTROL_PASSWORD
        self.proxy_port = config.TOR_PROXY_PORT
        self.max_failures = config.MAX_CIRCUIT_FAILURES
        self.controller = None
        self.circuit_failures = 0

        
    def connect_controller(self):
        """Connect to Tor control port."""
        try:
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate(password=self.control_password)
            logger.info("Connected to Tor control port")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Tor control port: {e}")
            return False
    
    def get_new_circuit(self):
        """Request a new Tor circuit."""
        if not self.controller:
            if not self.connect_controller():
                return False
        
        try:
            self.controller.signal(Signal.NEWNYM)
            logger.info("Requested new Tor circuit")
            time.sleep(5)  # Wait for circuit to establish
            return True
        except Exception as e:
            logger.error(f"Failed to get new circuit: {e}")
            return False
    
    def get_current_ip(self):
        """Get current external IP address through Tor."""
        try:
            proxies = {
                'http': f'socks5://127.0.0.1:{self.proxy_port}',
                'https': f'socks5://127.0.0.1:{self.proxy_port}'
            }
            response = requests.get('http://httpbin.org/ip', 
                                  proxies=proxies, 
                                  timeout=10)
            if response.status_code == 200:
                ip = response.json().get('origin', 'Unknown')
                logger.info(f"Current Tor IP: {ip}")
                return ip
        except Exception as e:
            logger.error(f"Failed to get current IP: {e}")
        return None
    
    def test_tor_connection(self):
        """Test if Tor proxy is working."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(('127.0.0.1', self.proxy_port))
            sock.close()
            
            if result == 0:
                logger.info("Tor proxy is accessible")
                return True
            else:
                logger.error("Tor proxy is not accessible")
                return False
        except Exception as e:
            logger.error(f"Error testing Tor connection: {e}")
            return False
    
    def handle_circuit_failure(self):
        """Handle circuit failures and request new circuit if needed."""
        self.circuit_failures += 1
        logger.warning(f"Circuit failure #{self.circuit_failures}")
        
        if self.circuit_failures >= self.max_failures:
            logger.info("Max circuit failures reached, requesting new circuit")
            if self.get_new_circuit():
                self.circuit_failures = 0
                return True
            else:
                logger.error("Failed to get new circuit after max failures")
                return False
        return True
    
    def reset_failure_count(self):
        """Reset circuit failure count after successful requests."""
        if self.circuit_failures > 0:
            logger.info("Resetting circuit failure count")
            self.circuit_failures = 0
    
    def close(self):
        """Close Tor controller connection."""
        if self.controller:
            self.controller.close()
            logger.info("Closed Tor controller connection")


# Singleton instance
tor_manager = TorManager()
