#!/usr/bin/env python3
"""
SIGIL Client - Remote Wallet Access (HTTP Client)
"""

import sys
import json
import urllib.request
import urllib.error
from pathlib import Path

# =============================================================================
#                              CONFIGURATION
# =============================================================================

SIGIL_CLIENT_DIR = Path.home() / ".sigil"
CLIENT_CONFIG = SIGIL_CLIENT_DIR / "client.json"

DEFAULT_CONFIG = {
    "server": "http://127.0.0.1:5000",
    "api_key": "",
    "use_tor": False,
    "tor_proxy": "socks5h://127.0.0.1:9050"
}

# =============================================================================
#                               TOR SUPPORT
# =============================================================================

def get_tor_opener(proxy: str):
    """Create urllib opener with Tor SOCKS proxy"""
    try:
        import socks
        import socket

        proxy_parts = proxy.replace("socks5h://", "").replace("socks5://", "")
        host, port = proxy_parts.split(":")

        # Try sockshandler first
        try:
            from sockshandler import SocksiPyHandler
            return urllib.request.build_opener(
                SocksiPyHandler(socks.SOCKS5, host, int(port), rdns=True)
            )
        except ImportError:
            pass

        # Fallback: monkeypatch socket
        socks.set_default_proxy(socks.SOCKS5, host, int(port), rdns=True)
        socket.socket = socks.socksocket
        return urllib.request.build_opener()

    except ImportError:
        print("[!] PySocks not installed. Install with: pip3 install PySocks")
        sys.exit(1)

# =============================================================================
#                              API CLIENT
# =============================================================================

class SigilClient:
    """Client for SIGIL remote signing server"""

    def __init__(self, server: str, api_key: str, use_tor: bool = False,
                 tor_proxy: str = "socks5h://127.0.0.1:9050"):
        self.server = server.rstrip('/')
        self.api_key = api_key
        self.use_tor = use_tor
        self.tor_proxy = tor_proxy
        self.opener = None

        # Auto-detect Tor for .onion addresses
        if '.onion' in self.server:
            self.use_tor = True

        if self.use_tor:
            self.opener = get_tor_opener(self.tor_proxy)

    def _request(self, method: str, endpoint: str, data: dict = None) -> dict:
        """Make API request"""
        url = f"{self.server}{endpoint}"

        headers = {
            'User-Agent': 'SIGIL-Client/1.0',
            'X-API-Key': self.api_key,
            'Content-Type': 'application/json'
        }

        body = None
        if data:
            body = json.dumps(data).encode()

        try:
            req = urllib.request.Request(url, data=body, headers=headers, method=method)

            if self.opener:
                with self.opener.open(req, timeout=60) as resp:
                    return json.loads(resp.read().decode())
            else:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read().decode())

        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else str(e)
            try:
                return json.loads(error_body)
            except:
                return {"error": f"HTTP {e.code}: {error_body}"}
        except urllib.error.URLError as e:
            return {"error": f"Connection failed: {e.reason}"}
        except Exception as e:
            return {"error": str(e)}

    def get(self, endpoint: str) -> dict:
        return self._request('GET', endpoint)

    def post(self, endpoint: str, data: dict) -> dict:
        return self._request('POST', endpoint, data)

    # API Methods

    def status(self) -> dict:
        """Get SE050 status"""
        return self.get('/status')

    def balance(self) -> dict:
        """Get wallet balance"""
        return self.get('/balance')

    def address(self, index: int = 0) -> dict:
        """Get receive address"""
        return self.get(f'/address/{index}')

    def utxos(self) -> dict:
        """Get all UTXOs"""
        return self.get('/utxos')

    def sign(self, hash_hex: str) -> dict:
        """Sign a hash"""
        return self.post('/sign', {'hash': hash_hex})

    def sign_message(self, message: str) -> dict:
        """Sign a message"""
        return self.post('/sign-message', {'message': message})

    def broadcast(self, tx_hex: str) -> dict:
        """Broadcast a transaction"""
        return self.post('/broadcast', {'tx_hex': tx_hex})

    def fees(self) -> dict:
        """Get fee estimates"""
        return self.get('/fees')

    def health(self) -> dict:
        """Health check (no auth)"""
        return self.get('/health')

# =============================================================================
#                              CONFIG MANAGEMENT
# =============================================================================

def load_config() -> dict:
    """Load client configuration"""
    if CLIENT_CONFIG.exists():
        try:
            return json.loads(CLIENT_CONFIG.read_text())
        except:
            pass
    return DEFAULT_CONFIG.copy()

def save_config(config: dict):
    """Save client configuration"""
    SIGIL_CLIENT_DIR.mkdir(parents=True, exist_ok=True)
    CLIENT_CONFIG.write_text(json.dumps(config, indent=2))
    CLIENT_CONFIG.chmod(0o600)
