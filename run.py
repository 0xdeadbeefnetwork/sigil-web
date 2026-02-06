#!/usr/bin/env python3
"""
SIGIL Web - Development Server Entry Point

Usage:
    python run.py                    # Start on port 5000
    python run.py --port 8080        # Custom port
    python run.py --debug            # Enable debug mode
"""

from sigil.web import create_app
from sigil.web.helpers import get_or_create_secret, SIGIL_DIR
from sigil.bitcoin.config import Config

import json


def main():
    app = create_app()
    app.secret_key = get_or_create_secret()

    # Load network settings
    settings_file = SIGIL_DIR / 'network_settings.json'
    if settings_file.exists():
        try:
            settings = json.loads(settings_file.read_text())
            Config.TOR_ENABLED = settings.get('use_tor', False)
            if settings.get('network') in ('mainnet', 'testnet'):
                Config.NETWORK = settings.get('network')
        except Exception:
            pass

    # Load key slot
    keyslot_file = SIGIL_DIR / 'keyslot.conf'
    if keyslot_file.exists():
        try:
            slot = keyslot_file.read_text().strip()
            if slot:
                Config.KEY_ID = slot
        except Exception:
            pass

    import argparse
    parser = argparse.ArgumentParser(description='SIGIL Web - Development Server')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
