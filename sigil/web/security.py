"""
SIGIL Web - Security Hardening

Honeypot tracking, rate limiting, input validation, CSRF protection,
and security headers.
"""

import re
import hmac
import json
import time
import secrets
from collections import defaultdict
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import request, session, redirect, url_for, flash

from sigil.web.helpers import SIGIL_DIR

# =========================================================================
#                         HONEYPOT TRACKING
# =========================================================================

_honeypot_hits = defaultdict(list)  # IP -> [(timestamp, endpoint)]
HONEYPOT_LOG = SIGIL_DIR / "honeypot.log"

# =========================================================================
#                         RATE LIMITING
# =========================================================================

_login_attempts = defaultdict(list)  # IP -> [timestamps]
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300  # 5 minute lockout


def _check_rate_limit(ip: str) -> bool:
    """Check if IP is rate limited. Returns True if allowed, False if blocked."""
    now = time.time()
    # Clean old attempts
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < LOGIN_LOCKOUT_SECONDS]
    return len(_login_attempts[ip]) < MAX_LOGIN_ATTEMPTS


def _record_login_attempt(ip: str):
    """Record a failed login attempt"""
    _login_attempts[ip].append(time.time())


def _log_honeypot(ip: str, endpoint: str, data: dict = None):
    """Log attacker activity to honeypot log"""
    try:
        SIGIL_DIR.mkdir(parents=True, exist_ok=True)
        with open(HONEYPOT_LOG, 'a') as f:
            entry = {
                'time': datetime.now().isoformat(),
                'ip': ip,
                'endpoint': endpoint,
                'user_agent': request.headers.get('User-Agent', ''),
                'data': data or {}
            }
            f.write(json.dumps(entry) + '\n')
    except:
        pass


# =========================================================================
#                         CRYPTO HELPERS
# =========================================================================

def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks"""
    return hmac.compare_digest(a.encode(), b.encode())


# =========================================================================
#                         INPUT VALIDATION
# =========================================================================

def _validate_bitcoin_address(addr: str) -> bool:
    """Validate Bitcoin address format"""
    if not addr:
        return False
    # Bech32 mainnet/testnet
    if re.match(r'^(bc1|tb1)[a-z0-9]{39,59}$', addr.lower()):
        return True
    # Legacy P2PKH
    if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', addr):
        return True
    # Legacy P2SH
    if re.match(r'^[23][a-km-zA-HJ-NP-Z1-9]{25,34}$', addr):
        return True
    return False


def _validate_amount(amount: int) -> bool:
    """Validate satoshi amount is sane"""
    return 0 < amount <= 21_000_000 * 100_000_000  # Max 21M BTC


def _validate_fee_rate(rate: int) -> bool:
    """Validate fee rate is reasonable"""
    return 1 <= rate <= 2000  # 1-2000 sat/vB


def _validate_key_slot(slot: str) -> bool:
    """Validate SE050 key slot ID"""
    try:
        val = int(slot, 16)
        # Valid SE050 user key range
        return 0x20000000 <= val <= 0x7FFFFFFF
    except:
        return False


# =========================================================================
#                         CSRF PROTECTION
# =========================================================================

def _generate_csrf_token():
    """Generate a CSRF token for the session"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def _validate_csrf():
    """Validate CSRF token from form"""
    token = request.form.get('_csrf_token', '')
    session_token = session.get('_csrf_token', '')
    if not session_token or not token:
        return False
    return _constant_time_compare(token, session_token)


def csrf_required(f):
    """Decorator to require valid CSRF token on POST"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST':
            if not _validate_csrf():
                flash('Security validation failed. Please try again.', 'error')
                return redirect(request.referrer or url_for('dashboard_bp.dashboard'))
        return f(*args, **kwargs)
    return decorated


# =========================================================================
#                         CONTEXT PROCESSOR & HEADERS
# =========================================================================

def inject_csrf():
    """Context processor: make CSRF token and connection status available to all templates"""
    from sigil.web.helpers import get_connection_status
    return {'csrf_token': _generate_csrf_token, 'connection_status': get_connection_status()}


def add_security_headers(response):
    """Add security headers to every response"""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    response.headers["Content-Security-Policy"] = csp
    if "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response
