"""
Local Bitcoin Core node RPC interface.
"""

import json
import urllib.request
import urllib.error
from typing import Tuple, Optional, Dict
from pathlib import Path

from sigil.bitcoin.config import Config


def _get_local_node_auth() -> Tuple[str, str]:
    """Get Bitcoin Core RPC credentials (config or cookie auth)"""
    if Config.LOCAL_NODE_RPC_PASS:
        return Config.LOCAL_NODE_RPC_USER, Config.LOCAL_NODE_RPC_PASS

    # Try cookie authentication
    cookie_path = Config.LOCAL_NODE_COOKIE_PATH
    if Config.NETWORK == "testnet":
        cookie_path = Path.home() / ".bitcoin" / "testnet4" / ".cookie"

    try:
        cookie = cookie_path.read_text().strip()
        user, password = cookie.split(":")
        return user, password
    except Exception:
        return Config.LOCAL_NODE_RPC_USER, Config.LOCAL_NODE_RPC_PASS


def local_node_rpc(method: str, params: list = None) -> Optional[Dict]:
    """Call Bitcoin Core JSON-RPC method"""
    if params is None:
        params = []

    user, password = _get_local_node_auth()
    url = f"http://{Config.LOCAL_NODE_RPC_HOST}:{Config.LOCAL_NODE_RPC_PORT}"

    payload = json.dumps({
        "jsonrpc": "1.0",
        "id": "se050wallet",
        "method": method,
        "params": params
    }).encode()

    try:
        req = urllib.request.Request(url, data=payload, method='POST')
        req.add_header('Content-Type', 'application/json')

        # Basic auth
        import base64
        credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
        req.add_header('Authorization', f'Basic {credentials}')

        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            if result.get("error"):
                # print(f"  [!] RPC error: {result['error']['message']}")
                return None
            return result.get("result")
    except urllib.error.URLError as e:
        # print(f"  [!] Cannot connect to local node: {e}")
        print(f"      Is Bitcoin Core running? Check: bitcoin-cli getblockchaininfo")
        return None
    except Exception as e:
        # print(f"  [!] Local node RPC error: {e}")
        return None


def broadcast_via_local_node(raw_tx_hex: str) -> Optional[str]:
    """Broadcast transaction via local Bitcoin Core node"""
    # print(f"  [TX] Broadcasting via local node...")
    result = local_node_rpc("sendrawtransaction", [raw_tx_hex])
    if result:
        # print(f"  [OK] Broadcast successful via local node")
        return result  # txid
    return None
