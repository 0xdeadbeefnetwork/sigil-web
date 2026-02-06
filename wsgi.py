#!/usr/bin/env python3
"""
WSGI Entry Point for SIGIL Web
Run with: gunicorn -c gunicorn.conf.py wsgi:app
"""

import os
import sys
import json
from pathlib import Path

# Add application directory to path
APP_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(APP_DIR))

# Import from refactored package
from sigil.web import create_app
from sigil.web.helpers import get_or_create_secret, SIGIL_DIR
from sigil.bitcoin.config import Config

# Create the Flask application
app = create_app()

# Production configuration
app.config.update(
    DEBUG=False,
    TESTING=False,
    PROPAGATE_EXCEPTIONS=False,
    SESSION_COOKIE_SECURE=False,  # Tor uses HTTP internally
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_NAME="sigil_session",
    SEND_FILE_MAX_AGE_DEFAULT=0,
)

# Set secret key
app.secret_key = get_or_create_secret()

# Load saved key slot
keyslot_file = SIGIL_DIR / "keyslot.conf"
if keyslot_file.exists():
    try:
        Config.KEY_ID = keyslot_file.read_text().strip().upper()
    except:
        pass

# Load network settings
settings_file = SIGIL_DIR / "network_settings.json"
if settings_file.exists():
    try:
        data = json.loads(settings_file.read_text())
        Config.NETWORK = data.get("network", "mainnet")
        Config.TOR_ENABLED = data.get("use_tor", False)
        Config.API_BACKEND = data.get("api_backend", "mempool")
    except:
        pass

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
