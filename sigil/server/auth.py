#!/usr/bin/env python3
"""
SIGIL Server - Authentication, Rate Limiting & Access Logging
"""

import sys
import hmac
import hashlib
import secrets
from pathlib import Path
from datetime import datetime
from functools import wraps

from flask import request, abort

# =============================================================================
#                              CONFIGURATION
# =============================================================================

SIGIL_DIR = Path.home() / ".sigil"
API_KEY_FILE = SIGIL_DIR / "api.key"
ACCESS_LOG = SIGIL_DIR / "access.log"

# Rate limiting
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 30     # requests per window

# Global state
_rate_limits = {}  # IP -> (count, window_start)
_api_key_hash = None

# =============================================================================
#                            AUTHENTICATION
# =============================================================================

def generate_api_key() -> str:
    """Generate a new API key"""
    key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(key.encode()).hexdigest()

    SIGIL_DIR.mkdir(parents=True, exist_ok=True)
    API_KEY_FILE.write_text(key_hash)
    API_KEY_FILE.chmod(0o600)

    return key

def load_api_key_hash() -> str:
    """Load API key hash from file"""
    if not API_KEY_FILE.exists():
        print("[!] No API key configured. Generate one with:")
        print("    ./sigil_server.py --generate-key")
        sys.exit(1)
    return API_KEY_FILE.read_text().strip()

def verify_api_key(provided_key: str) -> bool:
    """Verify provided API key against stored hash"""
    if not _api_key_hash:
        return False
    provided_hash = hashlib.sha256(provided_key.encode()).hexdigest()
    return hmac.compare_digest(provided_hash, _api_key_hash)

def require_auth(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check Authorization header
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
            if verify_api_key(token):
                return f(*args, **kwargs)

        # Check X-API-Key header
        api_key = request.headers.get('X-API-Key', '')
        if api_key and verify_api_key(api_key):
            return f(*args, **kwargs)

        log_access("AUTH_FAIL", request.remote_addr)
        abort(401, description="Invalid or missing API key")

    return decorated

# =============================================================================
#                             RATE LIMITING
# =============================================================================

def check_rate_limit(ip: str) -> bool:
    """Check if IP is within rate limit"""
    now = datetime.now()

    if ip in _rate_limits:
        count, window_start = _rate_limits[ip]

        # Reset window if expired
        if (now - window_start).seconds >= RATE_LIMIT_WINDOW:
            _rate_limits[ip] = (1, now)
            return True

        # Check limit
        if count >= RATE_LIMIT_MAX:
            return False

        _rate_limits[ip] = (count + 1, window_start)
    else:
        _rate_limits[ip] = (1, now)

    return True

def rate_limit(f):
    """Decorator for rate limiting"""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        if not check_rate_limit(ip):
            log_access("RATE_LIMIT", ip)
            abort(429, description="Rate limit exceeded")
        return f(*args, **kwargs)
    return decorated

# =============================================================================
#                               LOGGING
# =============================================================================

def log_access(action: str, ip: str, details: str = ""):
    """Log access attempt"""
    SIGIL_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().isoformat()
    log_line = f"{timestamp} | {ip:15} | {action:15} | {details}\n"

    with open(ACCESS_LOG, 'a') as f:
        f.write(log_line)

    # Also print to console
    print(f"[{action}] {ip} {details}")
