#!/usr/bin/env python3
"""
Session Helper Tool for manually managing sessions after solving CAPTCHAs.

Usage:
    python session_helper.py add <domain> --cookies "cookie_string" [--headers "header_string"] [--expires 24]
    python session_helper.py list
    python session_helper.py test <domain> <test_url>
    python session_helper.py remove <domain>
    python session_helper.py cleanup
"""

import sys
import argparse
import json
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from producer.session_manager import session_manager


def add_session(args):
    """Add a new session."""
    try:
        # Parse headers if provided
        headers = {}
        if args.headers:
            for header_pair in args.headers.split(';'):
                header_pair = header_pair.strip()
                if ':' in header_pair:
                    name, value = header_pair.split(':', 1)
                    headers[name.strip()] = value.strip()
        
        # Add session
        session_manager.import_browser_cookies(
            domain=args.domain,
            cookie_string=args.cookies,
            expires_hours=args.expires
        )
        
        if headers:
            # Update session with headers
            session = session_manager.get_session(args.domain)
            if session:
                session['headers'].update(headers)
                session_manager.save_sessions()
        
        print(f"✓ Session added for {args.domain}")
        
    except Exception as e:
        print(f"✗ Error adding session: {e}")


def list_sessions(args):
    """List all sessions."""
    try:
        sessions = session_manager.list_sessions()
        
        if not sessions:
            print("No active sessions found.")
            return
        
        print(f"\n{'Domain':<40} {'Status':<10} {'Cookies':<8} {'Last Used':<20}")
        print("-" * 80)
        
        for domain, status in sessions.items():
            status_text = "EXPIRED" if status['is_expired'] else "ACTIVE"
            last_used = status['last_used'] or "Never"
            if last_used != "Never":
                last_used = last_used.split('T')[0]  # Just the date
            
            print(f"{domain:<40} {status_text:<10} {status['cookies_count']:<8} {last_used:<20}")
        
        print()
        
    except Exception as e:
        print(f"✗ Error listing sessions: {e}")


def test_session(args):
    """Test a session."""
    try:
        print(f"Testing session for {args.domain}...")
        
        is_valid = session_manager.test_session(args.domain, args.test_url)
        
        if is_valid:
            print(f"✓ Session for {args.domain} is valid")
        else:
            print(f"✗ Session for {args.domain} is invalid or expired")
            
    except Exception as e:
        print(f"✗ Error testing session: {e}")


def remove_session(args):
    """Remove a session."""
    try:
        session_manager.remove_session(args.domain)
        print(f"✓ Session removed for {args.domain}")
        
    except Exception as e:
        print(f"✗ Error removing session: {e}")


def cleanup_sessions(args):
    """Clean up expired sessions."""
    try:
        session_manager.cleanup_expired_sessions()
        print("✓ Expired sessions cleaned up")
        
    except Exception as e:
        print(f"✗ Error cleaning up sessions: {e}")


def show_help():
    """Show detailed help with examples."""
    help_text = """
Session Helper Tool - Manage crawler sessions after solving CAPTCHAs

EXAMPLES:

1. Add session after solving CAPTCHA:
   python session_helper.py add example.onion --cookies "session_id=abc123; csrf_token=xyz789" --expires 48

2. Add session with custom headers:
   python session_helper.py add example.onion --cookies "session=123" --headers "X-Forwarded-For: 1.2.3.4; Authorization: Bearer token123"

3. List all sessions:
   python session_helper.py list

4. Test if session is still valid:
   python session_helper.py test example.onion http://example.onion/forum

5. Remove a session:
   python session_helper.py remove example.onion

6. Clean up expired sessions:
   python session_helper.py cleanup

HOW TO GET COOKIES FROM BROWSER:

1. Open browser and navigate to the site
2. Solve CAPTCHA manually
3. Open Developer Tools (F12)
4. Go to Application/Storage tab
5. Click on Cookies for the domain
6. Copy cookie values in format: "name1=value1; name2=value2"

ALTERNATIVE - Copy from Network tab:
1. Open Developer Tools (F12)
2. Go to Network tab
3. Make a request to the site
4. Right-click on the request → Copy → Copy as cURL
5. Extract the Cookie header value

The session will be automatically used by the crawler for that domain.
"""
    print(help_text)


def main():
    parser = argparse.ArgumentParser(
        description="Session Helper Tool for managing crawler sessions",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add session command
    add_parser = subparsers.add_parser('add', help='Add a new session')
    add_parser.add_argument('domain', help='Domain name (e.g., example.onion)')
    add_parser.add_argument('--cookies', required=True, help='Cookie string from browser')
    add_parser.add_argument('--headers', help='Additional headers (format: "name1: value1; name2: value2")')
    add_parser.add_argument('--expires', type=int, default=24, help='Hours until session expires (default: 24)')
    
    # List sessions command
    list_parser = subparsers.add_parser('list', help='List all sessions')
    
    # Test session command
    test_parser = subparsers.add_parser('test', help='Test a session')
    test_parser.add_argument('domain', help='Domain name')
    test_parser.add_argument('test_url', help='URL to test the session against')
    
    # Remove session command
    remove_parser = subparsers.add_parser('remove', help='Remove a session')
    remove_parser.add_argument('domain', help='Domain name')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up expired sessions')
    
    # Help command
    help_parser = subparsers.add_parser('help', help='Show detailed help with examples')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Execute command
    if args.command == 'add':
        add_session(args)
    elif args.command == 'list':
        list_sessions(args)
    elif args.command == 'test':
        test_session(args)
    elif args.command == 'remove':
        remove_session(args)
    elif args.command == 'cleanup':
        cleanup_sessions(args)
    elif args.command == 'help':
        show_help()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()

