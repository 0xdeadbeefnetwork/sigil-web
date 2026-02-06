#!/usr/bin/env python3
"""
Minimal Electrum Client for SIGIL
=================================
Lightweight Electrum protocol client with Tor support, TOFU certificate pinning,
and peer discovery via server.peers.subscribe.

Certificate Pinning (Trust On First Use):
  On first SSL connection to a server, the server's certificate fingerprint
  (SHA-256 of DER-encoded cert) is saved to ~/.sigil/electrum_pins.json.
  On subsequent connections, the fingerprint is verified against the stored pin.
  If the fingerprint changes, the connection is refused (possible MITM).
  Pins can be cleared per-server or entirely via the web UI settings.

Peer Discovery:
  After connecting to any server, SIGIL calls server.peers.subscribe to discover
  additional peers. Discovered peers are cached in ~/.sigil/electrum_peers.json
  and used on subsequent connections (shuffled for load balancing). The cache
  expires after 24 hours.  Hardcoded seed servers are used as fallback.
"""

import json
import socket
import ssl
import hashlib
import time
import secrets
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from sigil.crypto.encoding import bech32_decode, b58check_decode

# =========================================================================
#                    SEED SERVERS (FALLBACK)
# =========================================================================

# Hardcoded seed servers — used only when no cached peers are available.
# Format: (host, tcp_port, ssl_port, onion_host_or_None)
MAINNET_SEEDS = [
    ("electrum.blockstream.info", 50001, 50002, None),
    ("electrum.emzy.de", 50001, 50002, None),
    ("bolt.schulzemic.net", 50001, 50002, None),
    ("electrum.jochen-hoenicke.de", 50001, 50002, None),
    ("2ex.electrum.be", 50001, 50002, None),
]

TESTNET_SEEDS = [
    ("electrum.blockstream.info", 60001, 60002, None),
]

# =========================================================================
#                    FILE PATHS
# =========================================================================

_SIGIL_DIR = Path.home() / ".sigil"
_PINS_FILE = _SIGIL_DIR / "electrum_pins.json"
_PEERS_FILE = _SIGIL_DIR / "electrum_peers.json"
_PEERS_MAX_AGE = 86400  # 24 hours — re-discover after this


# =========================================================================
#                    TOFU CERTIFICATE PINNING
# =========================================================================

def _load_pins() -> Dict[str, Any]:
    """Load stored certificate pins from disk"""
    if _PINS_FILE.exists():
        try:
            return json.loads(_PINS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_pins(pins: Dict[str, Any]):
    """Save certificate pins to disk with restricted permissions"""
    _SIGIL_DIR.mkdir(parents=True, exist_ok=True)
    _PINS_FILE.write_text(json.dumps(pins, indent=2))
    try:
        _PINS_FILE.chmod(0o600)
    except OSError:
        pass


def get_pinned_servers() -> Dict[str, Any]:
    """Get all pinned server certificates (for UI display)"""
    return _load_pins()


def clear_pin(server_key: str) -> bool:
    """Remove a single server's certificate pin. Returns True if pin existed."""
    pins = _load_pins()
    if server_key in pins:
        del pins[server_key]
        _save_pins(pins)
        return True
    return False


def clear_all_pins():
    """Remove all stored certificate pins"""
    _save_pins({})


def _get_cert_fingerprint(sock: ssl.SSLSocket) -> str:
    """Get SHA-256 fingerprint of the server's DER-encoded certificate"""
    der_cert = sock.getpeercert(binary_form=True)
    if der_cert is None:
        raise Exception("No certificate presented by server")
    return hashlib.sha256(der_cert).hexdigest()


def _verify_or_pin_cert(sock: ssl.SSLSocket, host: str, port: int) -> str:
    """
    TOFU: verify server cert against stored pin, or pin it on first connect.
    Returns the fingerprint.
    Raises Exception if fingerprint doesn't match stored pin (MITM detected).
    """
    fingerprint = _get_cert_fingerprint(sock)
    server_key = f"{host}:{port}"

    pins = _load_pins()

    if server_key in pins:
        stored = pins[server_key]
        stored_fp = stored.get("fingerprint", "")
        if stored_fp != fingerprint:
            raise Exception(
                f"CERTIFICATE MISMATCH for {server_key}! "
                f"Expected {stored_fp[:16]}..., got {fingerprint[:16]}... "
                f"Possible MITM attack. Connection refused. "
                f"If the server legitimately rotated its certificate, "
                f"clear the pin via Settings > Network > Electrum Cert Pins."
            )
        # Pin matches — update last_seen
        pins[server_key]["last_seen"] = int(time.time())
        _save_pins(pins)
    else:
        # First connection — trust and pin
        pins[server_key] = {
            "fingerprint": fingerprint,
            "first_seen": int(time.time()),
            "last_seen": int(time.time()),
        }
        _save_pins(pins)

    return fingerprint


# =========================================================================
#                    PEER DISCOVERY & CACHE
# =========================================================================

def _load_cached_peers(network: str) -> List[Tuple[str, int, int, Optional[str]]]:
    """Load cached peer list from disk. Returns empty list if stale or missing."""
    if not _PEERS_FILE.exists():
        return []
    try:
        data = json.loads(_PEERS_FILE.read_text())
        # Check age
        cached_at = data.get("cached_at", 0)
        if time.time() - cached_at > _PEERS_MAX_AGE:
            return []  # Stale cache
        peers = data.get(network, [])
        # Convert back to tuples
        return [(p[0], p[1], p[2], p[3]) for p in peers]
    except (json.JSONDecodeError, OSError, IndexError, KeyError):
        return []


def _save_cached_peers(network: str, peers: List[Tuple[str, int, int, Optional[str]]]):
    """Save discovered peers to disk cache"""
    _SIGIL_DIR.mkdir(parents=True, exist_ok=True)
    # Load existing data (may have other networks cached)
    existing = {}
    if _PEERS_FILE.exists():
        try:
            existing = json.loads(_PEERS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    existing[network] = [list(p) for p in peers]
    existing["cached_at"] = int(time.time())
    _PEERS_FILE.write_text(json.dumps(existing, indent=2))
    try:
        _PEERS_FILE.chmod(0o600)
    except OSError:
        pass


def _parse_peer_features(features: List[str]) -> Dict[str, Any]:
    """
    Parse Electrum peer feature strings.
    Features: v=version, p=pruning, t=tcp port, s=ssl port
    e.g. ["v1.4", "p10000", "t", "s"] → tcp=50001, ssl=50002
    e.g. ["v1.4", "s50003"]           → tcp=None, ssl=50003
    """
    result = {"version": None, "tcp_port": None, "ssl_port": None, "pruning": None}
    for f in features:
        if not f:
            continue
        prefix = f[0]
        rest = f[1:]
        if prefix == 'v':
            result["version"] = rest
        elif prefix == 'p':
            try:
                result["pruning"] = int(rest)
            except ValueError:
                pass
        elif prefix == 't':
            result["tcp_port"] = int(rest) if rest else 50001
        elif prefix == 's':
            result["ssl_port"] = int(rest) if rest else 50002
    return result


def _discover_peers(client: 'ElectrumClient') -> List[Tuple[str, int, int, Optional[str]]]:
    """
    Call server.peers.subscribe on the connected server to discover peers.
    Returns list of (host, tcp_port, ssl_port, onion) tuples.
    """
    try:
        raw_peers = client._call("server.peers.subscribe")
        if not raw_peers or not isinstance(raw_peers, list):
            return []
    except Exception:
        return []

    discovered = []
    seen_hosts = set()

    for entry in raw_peers:
        try:
            # Format: [ip_address, hostname, [features...]]
            if len(entry) < 3:
                continue
            _ip, hostname, features = entry[0], entry[1], entry[2]

            if not hostname or not isinstance(features, list):
                continue

            # Skip if we already have this host
            if hostname in seen_hosts:
                continue
            seen_hosts.add(hostname)

            parsed = _parse_peer_features(features)

            # We need at least an SSL port (we prefer SSL)
            ssl_port = parsed.get("ssl_port")
            tcp_port = parsed.get("tcp_port")
            if not ssl_port and not tcp_port:
                continue

            # Detect onion addresses
            onion = None
            if hostname.endswith('.onion'):
                onion = hostname
                hostname = hostname  # For onion, host IS the onion address

            discovered.append((
                hostname,
                tcp_port or 50001,
                ssl_port or 50002,
                onion
            ))

        except (ValueError, TypeError, IndexError):
            continue

    return discovered


def _shuffle_list(lst: list) -> list:
    """Shuffle a list using CSPRNG (Fisher-Yates)"""
    result = list(lst)
    for i in range(len(result) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        result[i], result[j] = result[j], result[i]
    return result


def get_cached_peer_count(network: str = "mainnet") -> int:
    """Get number of cached peers for display in UI"""
    return len(_load_cached_peers(network))


# =========================================================================
#                    ELECTRUM CLIENT
# =========================================================================

class ElectrumClient:
    """Minimal Electrum protocol client with TOFU cert pinning and peer discovery"""

    def __init__(self, network="mainnet", use_tor=False, tor_proxy="127.0.0.1:9050", timeout=30):
        self.network = network
        self.use_tor = use_tor
        parts = tor_proxy.split(":")
        self.tor_host = parts[0]
        self.tor_port = int(parts[1])
        self.timeout = timeout
        self.sock = None
        self.server = None
        self._id = 0

    def _get_servers(self) -> List[Tuple[str, int, int, Optional[str]]]:
        """
        Get server list: cached discovered peers (shuffled) + seed servers as fallback.
        """
        net = "testnet" if self.network == "testnet" else "mainnet"
        seeds = TESTNET_SEEDS if self.network == "testnet" else MAINNET_SEEDS

        # Try cached peers first (shuffled for load balancing)
        cached = _load_cached_peers(net)
        if cached:
            return _shuffle_list(cached) + seeds

        # No cache — just use seeds (shuffled)
        return _shuffle_list(list(seeds))

    def _create_socket(self, host, port, use_ssl=False):
        """Create socket, optionally through Tor SOCKS5, with TOFU cert pinning"""
        if self.use_tor:
            import socks
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, self.tor_host, self.tor_port, rdns=True)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(self.timeout)
        sock.connect((host, port))

        if use_ssl:
            # We use CERT_NONE for the SSL context because Electrum servers
            # use self-signed certs (no CA to verify against). Instead, we
            # do TOFU pinning: trust the cert on first connect, reject if
            # it changes on subsequent connects.
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

            # TOFU: verify or pin the certificate fingerprint
            _verify_or_pin_cert(sock, host, port)

        return sock

    def connect(self, server=None, port=None, use_ssl=True):
        """Connect to an Electrum server, then discover peers for next time"""
        if self.sock:
            self.close()

        servers = self._get_servers()

        if server and port:
            try_list = [(server, port, port, None)]
        else:
            try_list = servers

        for srv in try_list:
            host, tcp_port, ssl_port, onion = srv

            if self.use_tor and onion:
                host = onion

            target_port = ssl_port if use_ssl else tcp_port

            try:
                self.sock = self._create_socket(host, target_port, use_ssl)
                self.server = host + ":" + str(target_port)

                result = self._call("server.version", ["SIGIL", "1.4"])
                if result:
                    # Connected! Now discover peers in the background
                    self._discover_and_cache_peers()
                    return True
            except Exception as e:
                if self.sock:
                    try:
                        self.sock.close()
                    except:
                        pass
                    self.sock = None
                # If this was a cert mismatch, don't silently try next server —
                # propagate so the user knows about the MITM risk
                if "CERTIFICATE MISMATCH" in str(e):
                    raise
                continue

        return False

    def _discover_and_cache_peers(self):
        """After connecting, discover peers and cache them for next time"""
        net = "testnet" if self.network == "testnet" else "mainnet"
        try:
            peers = _discover_peers(self)
            if peers:
                _save_cached_peers(net, peers)
        except Exception as e:
            # Non-fatal — we're already connected, peer discovery is best-effort
            import logging
            logging.getLogger(__name__).warning("Peer discovery failed: %s", e)

    def close(self):
        """Close connection"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
            self.server = None

    def _call(self, method, params=None):
        """Make JSON-RPC call"""
        if not self.sock:
            raise Exception("Not connected")

        self._id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": method,
            "params": params or []
        }

        msg = json.dumps(request) + "\n"
        self.sock.sendall(msg.encode())

        response = b""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"\n" in response:
                break

        if not response:
            raise Exception("Empty response")

        data = json.loads(response.decode().strip())

        if "error" in data and data["error"]:
            raise Exception("Electrum error: " + str(data["error"]))

        return data.get("result")

    @staticmethod
    def address_to_scripthash(address):
        """Convert Bitcoin address to Electrum scripthash"""
        # Decode address to scriptPubKey
        if address.startswith(("bc1q", "tb1q")):  # Bech32 P2WPKH
            hrp, witness_version, witness_program = bech32_decode(address)
            if witness_program is None:
                raise ValueError("Invalid bech32 address: " + address)
            script = bytes([0x00, len(witness_program)]) + witness_program
        elif address.startswith(("bc1p", "tb1p")):  # Bech32m P2TR
            hrp, witness_version, witness_program = bech32_decode(address)
            if witness_program is None:
                raise ValueError("Invalid bech32m address: " + address)
            script = bytes([0x51, len(witness_program)]) + witness_program
        elif address[0] in ("1", "m", "n"):  # P2PKH
            version, pubkey_hash = b58check_decode(address)
            script = bytes([0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac])
        elif address[0] in ("3", "2"):  # P2SH
            version, script_hash = b58check_decode(address)
            script = bytes([0xa9, 0x14]) + script_hash + bytes([0x87])
        else:
            raise ValueError("Unsupported address format: " + address)

        h = hashlib.sha256(script).digest()
        return h[::-1].hex()

    def get_balance(self, address):
        """Get address balance"""
        scripthash = self.address_to_scripthash(address)
        result = self._call("blockchain.scripthash.get_balance", [scripthash])
        return {
            "confirmed": result.get("confirmed", 0),
            "unconfirmed": result.get("unconfirmed", 0)
        }

    def get_utxos(self, address):
        """Get UTXOs for address"""
        scripthash = self.address_to_scripthash(address)
        utxos = self._call("blockchain.scripthash.listunspent", [scripthash])

        result = []
        for utxo in utxos:
            result.append({
                "txid": utxo["tx_hash"],
                "vout": utxo["tx_pos"],
                "value": utxo["value"],
                "status": {"confirmed": utxo.get("height", 0) > 0}
            })
        return result

    def get_history(self, address):
        """Get transaction history for address"""
        scripthash = self.address_to_scripthash(address)
        return self._call("blockchain.scripthash.get_history", [scripthash])

    def get_transaction(self, txid):
        """Get raw transaction hex"""
        return self._call("blockchain.transaction.get", [txid])

    def broadcast(self, raw_tx):
        """Broadcast transaction, returns txid"""
        return self._call("blockchain.transaction.broadcast", [raw_tx])

    def get_fee_estimate(self, blocks=6):
        """Get fee estimate in BTC/kB"""
        result = self._call("blockchain.estimatefee", [blocks])
        return result if result and result > 0 else 0.0001

    def get_block_height(self):
        """Get current block height"""
        header = self._call("blockchain.headers.subscribe")
        return header.get("height", 0)


# Singleton client
_client = None

def get_client(network="mainnet", use_tor=False):
    """Get or create Electrum client"""
    global _client

    if _client is None or _client.network != network or _client.use_tor != use_tor:
        if _client:
            _client.close()
        _client = ElectrumClient(network=network, use_tor=use_tor)

    if not _client.sock:
        if not _client.connect():
            raise Exception("Failed to connect to any Electrum server")

    return _client


# Convenience functions
def electrum_get_utxos(address, network="mainnet", use_tor=False):
    client = get_client(network, use_tor)
    return client.get_utxos(address)

def electrum_get_balance(address, network="mainnet", use_tor=False):
    client = get_client(network, use_tor)
    return client.get_balance(address)

def electrum_get_history(address, network="mainnet", use_tor=False):
    client = get_client(network, use_tor)
    return client.get_history(address)

def electrum_broadcast(raw_tx, network="mainnet", use_tor=False):
    client = get_client(network, use_tor)
    return client.broadcast(raw_tx)

def electrum_get_fee(blocks=6, network="mainnet", use_tor=False):
    client = get_client(network, use_tor)
    btc_per_kb = client.get_fee_estimate(blocks)
    sat_per_vb = int(btc_per_kb * 100_000_000 / 1000)
    return max(1, sat_per_vb)
