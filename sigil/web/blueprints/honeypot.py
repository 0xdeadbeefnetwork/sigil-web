"""
SIGIL Web - Honeypot Blueprint

Fake routes that look juicy to attackers but do nothing except log
their attempts and waste their time.

Routes: /admin, /api/v1/wallet/export, /debug, /.env, /config.json,
        /wallet.dat, /api/v1/send, /api/transfer, /phpmyadmin,
        /wp-admin, /administrator, /.git/config, /robots.txt
"""

import time
import secrets

from flask import (
    Blueprint, request, render_template_string, jsonify
)

from sigil.web.helpers import SIGIL_VERSION
from sigil.web.security import _log_honeypot

honeypot_bp = Blueprint('honeypot_bp', __name__)


@honeypot_bp.route('/admin', methods=['GET', 'POST'])
@honeypot_bp.route('/admin/', methods=['GET', 'POST'])
@honeypot_bp.route('/admin/login', methods=['GET', 'POST'])
def honeypot_admin():
    """Fake admin panel - log everything"""
    client_ip = request.remote_addr or 'unknown'
    _log_honeypot(client_ip, '/admin', {
        'method': request.method,
        'form': dict(request.form),
        'args': dict(request.args)
    })
    # Return a fake login page that always fails after a delay
    # No sleep - single gunicorn worker means we'd DoS ourselves
    if request.method == 'POST':
        # Removed sleep - single worker self-DoS
        return render_template_string("""
        <html><head><title>Admin - Error</title></head>
        <body style="background:#1a1a2e;color:#fff;font-family:monospace;padding:50px;">
        <h1>Authentication Failed</h1>
        <p>Invalid credentials. This attempt has been logged.</p>
        <p>IP: {{ ip }}</p>
        </body></html>
        """, ip=client_ip), 401
    return render_template_string("""
    <html><head><title>SIGIL Admin</title></head>
    <body style="background:#1a1a2e;color:#fff;font-family:monospace;padding:50px;">
    <h1>SIGIL Admin Panel</h1>
    <form method="POST">
        <p>Username: <input name="username" type="text"></p>
        <p>Password: <input name="password" type="password"></p>
        <p><button type="submit">Login</button></p>
    </form>
    </body></html>
    """)


@honeypot_bp.route('/api/v1/wallet/export', methods=['GET', 'POST'])
@honeypot_bp.route('/api/wallet/dump', methods=['GET', 'POST'])
@honeypot_bp.route('/api/keys', methods=['GET', 'POST'])
@honeypot_bp.route('/backup', methods=['GET', 'POST'])
@honeypot_bp.route('/export-keys', methods=['GET', 'POST'])
def honeypot_export():
    """Fake key export endpoint - attackers love these"""
    client_ip = request.remote_addr or 'unknown'
    _log_honeypot(client_ip, request.path, {
        'method': request.method,
        'headers': dict(request.headers),
        'form': dict(request.form),
        'args': dict(request.args)
    })
    # Removed sleep
    # Return fake "encrypted" keys that are actually garbage
    fake_keys = {
        "status": "success",
        "warning": "Keys exported successfully",
        "encrypted_seed": secrets.token_hex(32),
        "encrypted_xpriv": secrets.token_hex(64),
        "iv": secrets.token_hex(16),
        "checksum": secrets.token_hex(8)
    }
    return jsonify(fake_keys)


@honeypot_bp.route('/debug', methods=['GET', 'POST'])
@honeypot_bp.route('/debug/', methods=['GET', 'POST'])
@honeypot_bp.route('/.env', methods=['GET'])
@honeypot_bp.route('/config.json', methods=['GET'])
@honeypot_bp.route('/wallet.dat', methods=['GET'])
def honeypot_debug():
    """Fake debug/config endpoints"""
    client_ip = request.remote_addr or 'unknown'
    _log_honeypot(client_ip, request.path, {'method': request.method})
    time.sleep(2)
    if '.env' in request.path:
        # Return fake environment vars
        return """# SIGIL Configuration
FLASK_SECRET=not_the_real_secret_nice_try
DATABASE_URL=sqlite:///fake.db
WALLET_KEY=0000000000000000000000000000000000000000000000000000000000000000
DEBUG=false
""", 200, {'Content-Type': 'text/plain'}
    if 'wallet.dat' in request.path:
        # Return garbage that looks like a wallet file
        return secrets.token_bytes(1024), 200, {'Content-Type': 'application/octet-stream'}
    return jsonify({"debug": False, "version": SIGIL_VERSION, "error": "Access denied"})


@honeypot_bp.route('/api/v1/send', methods=['POST'])
@honeypot_bp.route('/api/transfer', methods=['POST'])
def honeypot_api_send():
    """Fake API send endpoint - logs attempted theft"""
    client_ip = request.remote_addr or 'unknown'
    _log_honeypot(client_ip, request.path, {
        'method': 'POST',
        'json': request.get_json(silent=True),
        'form': dict(request.form),
        'headers': {k: v for k, v in request.headers if k.lower() in ['authorization', 'x-api-key', 'content-type']}
    })
    # Removed sleep
    # Return fake success to make them think it worked
    return jsonify({
        "status": "success",
        "txid": secrets.token_hex(32),
        "message": "Transaction broadcast successfully",
        "confirmations": 0
    })


@honeypot_bp.route('/phpmyadmin', methods=['GET', 'POST'])
@honeypot_bp.route('/wp-admin', methods=['GET', 'POST'])
@honeypot_bp.route('/administrator', methods=['GET', 'POST'])
@honeypot_bp.route('/.git/config', methods=['GET'])
@honeypot_bp.route('/robots.txt', methods=['GET'])
def honeypot_scanner():
    """Catch common scanner/bot requests"""
    client_ip = request.remote_addr or 'unknown'
    _log_honeypot(client_ip, request.path, {'user_agent': request.headers.get('User-Agent', '')})
    if 'robots.txt' in request.path:
        # Point scanners at more honeypots
        return """User-agent: *
Disallow: /admin/
Disallow: /api/keys/
Disallow: /backup/
Disallow: /debug/
Disallow: /export-keys/
Disallow: /.env
""", 200, {'Content-Type': 'text/plain'}
    # Removed sleep
    return "Not Found", 404
