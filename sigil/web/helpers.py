"""
SIGIL Web - Helper Functions

Configuration constants, Tor/network helpers, password management,
signing PIN support, login decorator, and banner display.
"""

import os
import time
import secrets
import hashlib
import hmac
import json
from pathlib import Path
from typing import Dict
from functools import wraps

from flask import request, session, redirect, url_for, flash

# =========================================================================
#                         CONFIGURATION
# =========================================================================

SIGIL_VERSION = "1.0.0"
SIGIL_DIR = Path.home() / ".sigil"
WEB_SECRET_FILE = SIGIL_DIR / "web_secret.key"
WEB_PASSWORD_FILE = SIGIL_DIR / "web_password.hash"
SIGNING_PIN_FILE = SIGIL_DIR / "signing_pin.hash"  # Separate PIN for transaction signing

MEMPOOL_ONION = "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion"

SESSION_TIMEOUT = 1800  # 30 minutes


# =========================================================================
#                         TOR & NETWORK HELPERS
# =========================================================================

def get_tor_enabled():
    """Check if Tor is enabled in settings (for outbound API calls)"""
    settings_file = SIGIL_DIR / "network_settings.json"
    if settings_file.exists():
        try:
            data = json.loads(settings_file.read_text())
            return data.get('use_tor', False)
        except:
            pass
    return False


def is_onion_request():
    """Check if current request is via .onion (Tor hidden service)"""
    try:
        host = request.host.lower()
        return host.endswith('.onion') or host.endswith('.onion:80')
    except:
        return False


def get_connection_status():
    """Get connection status: 'onion', 'localhost', or 'clearnet'"""
    try:
        host = request.host.lower()
        if '.onion' in host:
            return 'onion'
        elif host.startswith('127.') or host.startswith('localhost'):
            return 'localhost'
        else:
            return 'clearnet'
    except:
        return 'unknown'


def get_exit_ip():
    """Get current exit IP address"""
    import requests
    try:
        if get_tor_enabled():
            proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
            resp = requests.get('https://check.torproject.org/api/ip', proxies=proxies, timeout=15)
            data = resp.json()
            return data.get('IP', 'Unknown'), data.get('IsTor', False)
        else:
            resp = requests.get('https://api.ipify.org?format=json', timeout=10)
            return resp.json().get('ip', 'Unknown'), False
    except Exception as e:
        return f'Error: {str(e)[:25]}', False


def get_mempool_base():
    """Get mempool explorer base URL based on how the user is accessing SIGIL.

    If the user is browsing via .onion, give them .onion explorer links so
    their browser stays on Tor.  Otherwise use clearnet links — even if the
    *backend* routes API calls through Tor, the user's browser is on clearnet
    and can't follow .onion links.
    """
    from sigil.bitcoin.config import Config
    onion = is_onion_request()
    testnet = Config.NETWORK == "testnet"

    if onion and testnet:
        return MEMPOOL_ONION + "/testnet4"
    elif onion:
        return MEMPOOL_ONION
    elif testnet:
        return "https://mempool.space/testnet4"
    else:
        return "https://mempool.space"


# =========================================================================
#                         PASSWORD MANAGEMENT
# =========================================================================

def get_or_create_secret():
    """Get or create Flask secret key"""
    SIGIL_DIR.mkdir(parents=True, exist_ok=True)
    if WEB_SECRET_FILE.exists():
        return WEB_SECRET_FILE.read_text().strip()
    secret = secrets.token_hex(32)
    WEB_SECRET_FILE.write_text(secret)
    WEB_SECRET_FILE.chmod(0o600)
    return secret


def set_password(password: str):
    """Set web interface password with PBKDF2 + salt"""
    SIGIL_DIR.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_hex(16)
    # PBKDF2 with 600k iterations (OWASP recommendation)
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 600000).hex()
    # Store as salt:hash
    WEB_PASSWORD_FILE.write_text(f"{salt}:{pw_hash}")
    WEB_PASSWORD_FILE.chmod(0o600)


def check_password(password: str) -> bool:
    """Verify password (supports both old SHA256 and new PBKDF2 format)"""
    if not WEB_PASSWORD_FILE.exists():
        return False
    stored = WEB_PASSWORD_FILE.read_text().strip()

    if ':' in stored:
        # New format: salt:hash (PBKDF2)
        salt, stored_hash = stored.split(':', 1)
        provided_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 600000).hex()
    else:
        # Old format: plain SHA256 (migrate on next password change)
        stored_hash = stored
        provided_hash = hashlib.sha256(password.encode()).hexdigest()

    return hmac.compare_digest(stored_hash, provided_hash)


# =========================================================================
#                         SIGNING PIN (2FA for transactions)
# =========================================================================

def signing_pin_enabled() -> bool:
    """Check if signing PIN is configured"""
    return SIGNING_PIN_FILE.exists()


def set_signing_pin(pin: str):
    """Set signing PIN with PBKDF2 + salt"""
    SIGIL_DIR.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_hex(16)
    pin_hash = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt.encode(), 600000).hex()
    SIGNING_PIN_FILE.write_text(f"{salt}:{pin_hash}")
    SIGNING_PIN_FILE.chmod(0o600)


_pin_attempts: Dict[str, list] = {}
PIN_MAX_ATTEMPTS = 5
PIN_LOCKOUT_SECONDS = 300  # 5 minutes


def check_signing_pin(pin: str) -> bool:
    """Verify signing PIN with rate limiting (5 attempts per 5 minutes)"""
    if not SIGNING_PIN_FILE.exists():
        return True  # No PIN set = no check required

    # Rate limit by client IP
    client_ip = request.remote_addr or 'unknown'
    now = time.time()
    attempts = _pin_attempts.get(client_ip, [])
    # Prune old attempts
    attempts = [t for t in attempts if now - t < PIN_LOCKOUT_SECONDS]
    _pin_attempts[client_ip] = attempts

    if len(attempts) >= PIN_MAX_ATTEMPTS:
        return False  # Locked out

    stored = SIGNING_PIN_FILE.read_text().strip()
    if ':' in stored:
        salt, stored_hash = stored.split(':', 1)
        provided_hash = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt.encode(), 600000).hex()
    else:
        stored_hash = stored
        provided_hash = hashlib.sha256(pin.encode()).hexdigest()

    result = hmac.compare_digest(stored_hash, provided_hash)
    if not result:
        _pin_attempts[client_ip] = attempts + [now]
    else:
        # Clear attempts on success
        _pin_attempts[client_ip] = []
    return result


def clear_signing_pin():
    """Remove signing PIN requirement"""
    if SIGNING_PIN_FILE.exists():
        SIGNING_PIN_FILE.unlink()


# =========================================================================
#                         LOGIN DECORATOR
# =========================================================================

def login_required(f):
    """Decorator for authenticated routes with session timeout"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('auth_bp.login'))
        # Check session timeout
        last_active = session.get('last_active', 0)
        if time.time() - last_active > SESSION_TIMEOUT:
            session.clear()
            flash('Session expired. Please login again.', 'warning')
            return redirect(url_for('auth_bp.login'))
        # Update last active time
        session['last_active'] = time.time()
        return f(*args, **kwargs)
    return decorated


# =========================================================================
#                         BANNER
# =========================================================================

def print_banner():
    print("""
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557\u2588\u2588\u2557     \u2588\u2588\u2557    \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2557
\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2551    \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2551 \u2588\u2557 \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d
\u255a\u2550\u2550\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2551\u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u255d  \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u255a\u2588\u2588\u2588\u2554\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u255d\u255a\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u255d

    Hardware Wallet Web Interface v{}
""".format(SIGIL_VERSION))
