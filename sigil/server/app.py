#!/usr/bin/env python3
"""
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557\u2588\u2588\u2557
\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2551\u2588\u2588\u2551
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551
\u255a\u2550\u2550\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551\u2588\u2588\u2551
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d

SIGIL - Remote Signing Oracle
==============================

A Tor hidden service that exposes your SE050 hardware wallet
as a remote signing API. Access your wallet from anywhere.

"The Net interprets censorship as damage and routes around it."
                                        - John Gilmore

Usage:
    ./sigil_server.py                    # Start server
    ./sigil_server.py --generate-key     # Generate new API key
    ./sigil_server.py --port 8080        # Custom port

Setup (Tor hidden service):
    1. Add to /etc/tor/torrc:
       HiddenServiceDir /var/lib/tor/sigil/
       HiddenServicePort 80 127.0.0.1:5000

    2. sudo systemctl restart tor
    3. sudo cat /var/lib/tor/sigil/hostname  # Your .onion address
    4. ./sigil_server.py

License: Cypherpunk Open Hardware License
"""

import os
import sys
import json
import argparse
import threading
from pathlib import Path
from datetime import datetime

# Try to import Flask
try:
    from flask import Flask, request, jsonify, abort
except ImportError:
    print("=" * 60)
    print("SIGIL requires Flask. Install with:")
    print("  pip3 install flask")
    print("=" * 60)
    sys.exit(1)

# Import from new package structure
from sigil.bitcoin.config import Config
from sigil.wallet.core import Wallet
from sigil.hardware.interface import (
    se050_connect, se050_disconnect, se050_sign,
    se050_get_uid, se050_key_exists, se050_export_pubkey,
    se050_get_random
)
from sigil.bitcoin.network import (
    get_utxos, get_address_info, get_fee_estimates,
    broadcast_transaction
)
from sigil.bitcoin.addresses import derive_addresses, compress_pubkey, parse_der_pubkey
from sigil.bitcoin.transaction import build_and_sign_transaction
from sigil.crypto.hashing import sha256, hash160
from sigil.crypto.signatures import sign_message_with_se050, encode_signed_message
from sigil.server.auth import (
    require_auth, rate_limit, generate_api_key, log_access,
    load_api_key_hash, API_KEY_FILE, SIGIL_DIR
)
import sigil.server.auth as _auth_module

# =============================================================================
#                              CONFIGURATION
# =============================================================================

SIGIL_VERSION = "1.0.0"
CONFIG_FILE = SIGIL_DIR / "config.json"

# Session timeout
SESSION_TIMEOUT = 300   # 5 minutes of inactivity

# =============================================================================
#                              SIGIL SERVER
# =============================================================================

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Global state
_se050_lock = threading.Lock()
_last_activity = datetime.now()

# =============================================================================
#                             API ENDPOINTS
# =============================================================================

@app.route('/')
@rate_limit
def index():
    """Root endpoint - basic info"""
    return jsonify({
        "name": "SIGIL",
        "version": SIGIL_VERSION,
        "description": "Remote Signing Oracle",
        "status": "online",
        "authenticated": False,
        "endpoints": [
            "GET  /status",
            "GET  /balance",
            "GET  /address",
            "GET  /address/<index>",
            "GET  /utxos",
            "POST /sign",
            "POST /sign-message",
            "POST /broadcast",
            "GET  /fees"
        ]
    })

@app.route('/status')
@rate_limit
@require_auth
def status():
    """Get SE050 connection status"""
    log_access("STATUS", request.remote_addr)

    with _se050_lock:
        connected = se050_connect() is not None

        result = {
            "connected": connected,
            "network": Config.NETWORK,
            "key_slot": Config.KEY_ID,
            "key_present": False,
            "uid": None
        }

        if connected:
            try:
                result["key_present"] = se050_key_exists(Config.KEY_ID)
                result["uid"] = se050_get_uid()
            except Exception as e:
                result["error"] = str(e)

    return jsonify(result)

@app.route('/balance')
@rate_limit
@require_auth
def balance():
    """Get wallet balance"""
    log_access("BALANCE", request.remote_addr)

    try:
        wallet = Wallet()
        if not wallet.load():
            return jsonify({"error": "No wallet loaded"}), 404

        # Get UTXOs for wallet address
        total_sats = 0
        utxo_count = 0

        addr_dict = derive_addresses(wallet.pubkey_compressed)
        segwit_addr = addr_dict.get('segwit', '')
        utxos = get_utxos(segwit_addr)
        if utxos:
            for utxo in utxos:
                total_sats += utxo.get('value', 0)
                utxo_count += 1

        return jsonify({
            "balance_sats": total_sats,
            "balance_btc": total_sats / 100_000_000,
            "utxo_count": utxo_count,
            "address": segwit_addr
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/address')
@app.route('/address/<int:index>')
@rate_limit
@require_auth
def address(index: int = 0):
    """Get receive address"""
    log_access("ADDRESS", request.remote_addr, f"index={index}")

    try:
        wallet = Wallet()
        if not wallet.load():
            return jsonify({"error": "No wallet loaded"}), 404

        addr_dict = derive_addresses(wallet.pubkey_compressed)
        if not addr_dict:
            return jsonify({"error": "Could not derive address"}), 500

        return jsonify({
            "index": index,
            "address": addr_dict.get('segwit', ''),
            "legacy_address": addr_dict.get('legacy', ''),
            "type": "bech32"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/utxos')
@rate_limit
@require_auth
def utxos():
    """Get all UTXOs"""
    log_access("UTXOS", request.remote_addr)

    try:
        wallet = Wallet()
        if not wallet.load():
            return jsonify({"error": "No wallet loaded"}), 404

        all_utxos = []
        addr_dict = derive_addresses(wallet.pubkey_compressed)
        segwit_addr = addr_dict.get('segwit', '')

        addr_utxos = get_utxos(segwit_addr)
        if addr_utxos:
            for utxo in addr_utxos:
                utxo['address'] = segwit_addr
                all_utxos.append(utxo)

        return jsonify({
            "count": len(all_utxos),
            "utxos": all_utxos
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/sign', methods=['POST'])
@rate_limit
@require_auth
def sign():
    """Sign a transaction hash

    Request body:
    {
        "hash": "hex-encoded 32-byte hash",
        "key_id": "optional key slot (hex)"
    }
    """
    log_access("SIGN", request.remote_addr)

    data = request.get_json()
    if not data or 'hash' not in data:
        return jsonify({"error": "Missing 'hash' in request body"}), 400

    try:
        hash_hex = data['hash']
        hash_bytes = bytes.fromhex(hash_hex)

        if len(hash_bytes) != 32:
            return jsonify({"error": "Hash must be 32 bytes"}), 400

        key_id = data.get('key_id', Config.KEY_ID)

        with _se050_lock:
            signature = se050_sign(key_id, hash_bytes)

        if signature:
            log_access("SIGN_OK", request.remote_addr, f"key=0x{key_id}")
            return jsonify({
                "signature": signature.hex(),
                "key_id": f"0x{key_id}",
                "hash": hash_hex
            })
        else:
            return jsonify({"error": "Signing failed"}), 500

    except ValueError as e:
        return jsonify({"error": f"Invalid hex: {e}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/sign-message', methods=['POST'])
@rate_limit
@require_auth
def sign_message():
    """Sign a message (Bitcoin message signing format)

    Request body:
    {
        "message": "message to sign"
    }
    """
    log_access("SIGN_MSG", request.remote_addr)

    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({"error": "Missing 'message' in request body"}), 400

    try:
        message = data['message']

        wallet = Wallet()
        if not wallet.load():
            return jsonify({"error": "No wallet loaded"}), 404

        addr_dict = derive_addresses(wallet.pubkey_compressed)
        if not addr_dict:
            return jsonify({"error": "Could not derive address"}), 500

        address = addr_dict.get('segwit', '')

        with _se050_lock:
            (r, s), recovery_id = sign_message_with_se050(Config.KEY_ID, message)

        if r and s:
            encoded = encode_signed_message(r, s, recovery_id)
            log_access("SIGN_MSG_OK", request.remote_addr)
            return jsonify({
                "address": address,
                "message": message,
                "signature": encoded
            })
        else:
            return jsonify({"error": "Message signing failed"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/broadcast', methods=['POST'])
@rate_limit
@require_auth
def broadcast():
    """Broadcast a signed transaction

    Request body:
    {
        "tx_hex": "raw transaction hex"
    }
    """
    log_access("BROADCAST", request.remote_addr)

    data = request.get_json()
    if not data or 'tx_hex' not in data:
        return jsonify({"error": "Missing 'tx_hex' in request body"}), 400

    try:
        tx_hex = data['tx_hex']
        txid = broadcast_transaction(tx_hex)

        if txid:
            log_access("BROADCAST_OK", request.remote_addr, f"txid={txid[:16]}...")
            return jsonify({
                "success": True,
                "txid": txid
            })
        else:
            return jsonify({"error": "Broadcast failed"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/fees')
@rate_limit
@require_auth
def fees():
    """Get current fee estimates"""
    log_access("FEES", request.remote_addr)

    try:
        estimates = get_fee_estimates()
        return jsonify(estimates)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health')
def health():
    """Health check (no auth required)"""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

# =============================================================================
#                              ERROR HANDLERS
# =============================================================================

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized", "message": str(e.description)}), 401

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found", "message": str(e.description)}), 404

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Rate limited", "message": str(e.description)}), 429

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500

# =============================================================================
#                                 MAIN
# =============================================================================

def print_banner():
    """Print SIGIL banner"""
    banner = """
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557\u2588\u2588\u2557
\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2551\u2588\u2588\u2551
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551
\u255a\u2550\u2550\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551\u2588\u2588\u2551
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d

    Remote Signing Oracle v{}

    "Privacy is not about hiding. Privacy is about autonomy."

""".format(SIGIL_VERSION)
    print(banner)

def main():
    parser = argparse.ArgumentParser(description='SIGIL - Remote Signing Oracle')
    parser.add_argument('--generate-key', action='store_true',
                        help='Generate new API key')
    parser.add_argument('--port', type=int, default=5000,
                        help='Port to listen on (default: 5000)')
    parser.add_argument('--host', default='127.0.0.1',
                        help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')

    args = parser.parse_args()

    print_banner()

    # Generate API key
    if args.generate_key:
        key = generate_api_key()
        print("=" * 60)
        print("NEW API KEY GENERATED")
        print("=" * 60)
        print()
        print(f"  {key}")
        print()
        print("=" * 60)
        print("SAVE THIS KEY! It will not be shown again.")
        print(f"Key hash stored in: {API_KEY_FILE}")
        print("=" * 60)
        return

    # Load API key
    _auth_module._api_key_hash = load_api_key_hash()
    print(f"[*] API key loaded from {API_KEY_FILE}")

    # Connect to SE050
    print(f"[*] Connecting to SE050...")
    if not se050_connect():
        print("[!] Failed to connect to SE050")
        print("    Check: USB connected, SE050ARD attached")
        sys.exit(1)

    print(f"[*] SE050 connected")
    print(f"[*] Key slot: 0x{Config.KEY_ID}")
    print(f"[*] Network: {Config.NETWORK}")
    print()
    print("=" * 60)
    print(f"SIGIL listening on http://{args.host}:{args.port}")
    print("=" * 60)
    print()
    print("For Tor hidden service, add to /etc/tor/torrc:")
    print(f"  HiddenServiceDir /var/lib/tor/sigil/")
    print(f"  HiddenServicePort 80 127.0.0.1:{args.port}")
    print()
    print("Then: sudo systemctl restart tor")
    print("Get your .onion: sudo cat /var/lib/tor/sigil-web/hostname")
    print()
    print("Press Ctrl+C to stop")
    print()

    # Run server
    try:
        app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        se050_disconnect()
        print("[*] SE050 disconnected")

if __name__ == '__main__':
    main()
