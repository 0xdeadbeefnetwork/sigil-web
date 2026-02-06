"""
Network and API interface for Bitcoin operations.
Handles mempool.space API, Tor routing, Electrum backend, and UTXO retrieval.
"""

import json
import urllib.request
import urllib.error
from typing import Optional, List, Dict

from sigil.bitcoin.config import Config
from sigil.bitcoin.local_node import local_node_rpc, broadcast_via_local_node


_tor_warned = False
_tor_available = None  # None = not checked, True = works, False = unavailable


def _get_tor_opener():
    """Create urllib opener with Tor SOCKS proxy"""
    global _tor_warned, _tor_available
    import urllib.request

    # Return cached result if already checked
    if _tor_available is False:
        return None

    # Try to use PySocks for SOCKS5 support
    try:
        import socks
        import socket

        # Parse proxy address
        proxy_parts = Config.TOR_PROXY.replace("socks5h://", "").replace("socks5://", "")
        host, port = proxy_parts.split(":")

        # Try sockshandler first (cleaner urllib integration)
        try:
            from sockshandler import SocksiPyHandler
            opener = urllib.request.build_opener(SocksiPyHandler(socks.SOCKS5, host, int(port), rdns=True))
            _tor_available = True
            return opener
        except ImportError:
            pass

        # Fallback: monkeypatch socket (affects all connections)
        socks.set_default_proxy(socks.SOCKS5, host, int(port), rdns=True)
        socket.socket = socks.socksocket
        _tor_available = True
        return urllib.request.build_opener()  # Uses patched socket

    except ImportError:
        pass

    # Mark Tor as unavailable and warn once
    _tor_available = False
    if not _tor_warned:
        _tor_warned = True
        # print("  [!] PySocks not installed. Install with: pip install PySocks")
        # print("      Falling back to clearnet API (Tor disabled)")
    return None


def _api_base_with_tor() -> str:
    """Get API base URL, using onion if Tor enabled AND available"""
    if Config.TOR_ENABLED and _tor_available is not False:
        if Config.NETWORK == "testnet":
            return Config.MEMPOOL_TESTNET_ONION
        return Config.MEMPOOL_ONION
    return Config.api_base()


def api_get(endpoint: str) -> Optional[Dict]:
    """GET request to mempool.space API (with Tor support)"""
    # Check Tor availability BEFORE deciding URL
    opener = None
    if Config.TOR_ENABLED:
        opener = _get_tor_opener()

    # Now get URL (will use clearnet if Tor unavailable)
    url = f"{_api_base_with_tor()}{endpoint}"

    try:
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'SE050-Bitcoin-Wallet/1.0')

        if opener:
            with opener.open(req, timeout=30) as resp:
                return json.loads(resp.read().decode())

        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    except Exception as e:
        print(f"API error: {e}")
        return None


def api_post(endpoint: str, data: bytes) -> Optional[str]:
    """POST request to mempool.space API (with Tor support)"""
    # Check Tor availability BEFORE deciding URL
    opener = None
    if Config.TOR_ENABLED:
        opener = _get_tor_opener()

    # Now get URL (will use clearnet if Tor unavailable)
    url = f"{_api_base_with_tor()}{endpoint}"

    try:
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'text/plain')
        req.add_header('User-Agent', 'SE050-Bitcoin-Wallet/1.0')

        if opener:
            with opener.open(req, timeout=60) as resp:
                return resp.read().decode()

        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode()
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else str(e)
        print(f"Broadcast error: {error_body}")
        return None


def broadcast_transaction(raw_tx_hex: str) -> Optional[str]:
    """
    Broadcast transaction using configured method.

    BROADCAST_METHOD options:
      - "local": Use your Bitcoin Core node only
      - "api": Use mempool.space API (with Tor if enabled)
      - "both": Try local first, fall back to API
    """
    method = Config.BROADCAST_METHOD

    if method == "local":
        return broadcast_via_local_node(raw_tx_hex)

    elif method == "both":
        # Try local first
        if Config.LOCAL_NODE_ENABLED:
            result = broadcast_via_local_node(raw_tx_hex)
            if result:
                return result
            # print(f"  [!] Local broadcast failed, trying API...")

        # Fall back to API
        if Config.TOR_ENABLED:
            pass  # debug print removed
            # print(f"  [TX] Broadcasting via Tor...")
        else:
            pass  # debug print removed
            # print(f"  [TX] Broadcasting via mempool.space...")
        return api_post("/tx", raw_tx_hex.encode())

    else:  # "api"
        # Use Electrum backend if configured
        if Config.API_BACKEND == "electrum":
            try:
                from electrum_client import electrum_broadcast
                # print(f"  [TX] Broadcasting via Electrum...")
                return electrum_broadcast(raw_tx_hex, Config.NETWORK, Config.TOR_ENABLED)
            except Exception as e:
                # print(f"  [ELECTRUM] Broadcast error: {e}")
                return None

        if Config.TOR_ENABLED:
            pass  # debug print removed
            # print(f"  [TX] Broadcasting via Tor...")
        else:
            pass  # debug print removed
            # print(f"  [TX] Broadcasting via mempool.space...")
        return api_post("/tx", raw_tx_hex.encode())


def get_utxos_local(address: str) -> List[Dict]:
    """Fetch UTXOs from local Bitcoin Core node using scantxoutset"""
    # Note: This requires Bitcoin Core 0.17+ and may take time on first scan
    result = local_node_rpc("scantxoutset", ["start", [f"addr({address})"]])
    if not result:
        return []

    utxos = []
    for unspent in result.get("unspents", []):
        utxos.append({
            "txid": unspent["txid"],
            "vout": unspent["vout"],
            "value": int(unspent["amount"] * 100000000),  # BTC to sats
            "status": {"confirmed": True}  # scantxoutset only returns confirmed
        })
    return utxos


def get_utxos(address: str) -> List[Dict]:
    """Fetch UTXOs for address (local node, Electrum, or mempool API)"""
    if Config.LOCAL_NODE_ENABLED:
        utxos = get_utxos_local(address)
        if utxos or Config.BROADCAST_METHOD == "local":
            return utxos

    # Use Electrum backend if configured
    if Config.API_BACKEND == "electrum":
        try:
            from electrum_client import electrum_get_utxos
            return electrum_get_utxos(address, Config.NETWORK, Config.TOR_ENABLED)
        except Exception as e:
            # print(f"  [ELECTRUM] Error: {e}")
            return []

    result = api_get(f"/address/{address}/utxo")
    return result if result else []


def get_address_info(address: str) -> Optional[Dict]:
    """Get address balance and transaction info"""
    return api_get(f"/address/{address}")


def get_address_txs(address: str, limit: int = 10) -> List[Dict]:
    """Get transaction history for address"""
    result = api_get(f"/address/{address}/txs")
    if result:
        return result[:limit]
    return []


def get_fee_estimates() -> Dict[str, int]:
    """Get current fee estimates"""
    if Config.API_BACKEND == "electrum":
        try:
            from electrum_client import electrum_get_fee
            fast = electrum_get_fee(1, Config.NETWORK, Config.TOR_ENABLED)
            medium = electrum_get_fee(6, Config.NETWORK, Config.TOR_ENABLED)
            slow = electrum_get_fee(12, Config.NETWORK, Config.TOR_ENABLED)
            return {'fastestFee': fast, 'halfHourFee': medium, 'hourFee': slow}
        except Exception as e:
            pass  # debug print removed
            # print(f"  [ELECTRUM] Fee error: {e}")

    result = api_get("/v1/fees/recommended")
    return result if result else {'fastestFee': 20, 'halfHourFee': 10, 'hourFee': 5}


def get_btc_price(currency: str = 'USD') -> Optional[float]:
    """Get current BTC price from mempool.space (via Tor if enabled)"""
    # Use Tor-aware API call
    try:
        result = api_get("/v1/prices")
        if result:
            return float(result.get(currency, result.get('USD', 0)))
    except:
        pass
    return None
