"""
Wallet configuration for the SIGIL Bitcoin wallet.
"""

import json
import glob
import os
from pathlib import Path


class Config:
    """Wallet configuration"""
    # SE050 Key slot - change this to manage multiple wallets
    KEY_ID = "20000001"

    # SE050 Secure storage object IDs
    ENTROPY_HMAC_KEY_ID = 0x40000001  # HMAC key for storing mnemonic entropy
    ENTROPY_BINARY_ID = 0x30000001    # Binary storage for encrypted entropy backup

    # Data directory for wallet files
    WALLET_DIR = Path.home() / ".se050-wallet"

    # API endpoints (clearnet)
    MEMPOOL_API = "https://mempool.space/api"
    MEMPOOL_TESTNET_API = "https://mempool.space/testnet4/api"

    # Tor hidden service endpoints (for maximum privacy)
    MEMPOOL_ONION = "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/api"
    MEMPOOL_TESTNET_ONION = "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/testnet4/api"

    # Network: "mainnet" or "testnet"
    NETWORK = "mainnet"

    # Fee rate in sat/vbyte
    DEFAULT_FEE_RATE = 10

    # ==========================================================================
    # PRIVACY & SOVEREIGNTY SETTINGS
    # ==========================================================================

    # Tor Configuration
    # Set TOR_ENABLED=True to route all API requests through Tor
    TOR_ENABLED = False
    TOR_PROXY = "socks5h://127.0.0.1:9050"  # Standard Tor SOCKS proxy

    # API Backend: "mempool" or "electrum"
    # Electrum is more private and works better over Tor
    API_BACKEND = "mempool"

    # Local Bitcoin Core Node (for full sovereignty)
    # Set LOCAL_NODE_ENABLED=True to use your own node instead of mempool.space
    LOCAL_NODE_ENABLED = False
    LOCAL_NODE_RPC_HOST = "127.0.0.1"
    LOCAL_NODE_RPC_PORT = 8332  # 18332 for testnet
    LOCAL_NODE_RPC_USER = "bitcoinrpc"
    LOCAL_NODE_RPC_PASS = ""  # Set this or use cookie auth
    LOCAL_NODE_COOKIE_PATH = Path.home() / ".bitcoin" / ".cookie"  # Auto cookie auth

    # Broadcast method: "api" (mempool.space), "local" (your node), "both"
    # "both" = try local first, fall back to API
    BROADCAST_METHOD = "api"

    # ==========================================================================

    # SE050 Connection settings
    # Connection type: "vcom" for USB serial, "t1oi2c" for I2C
    CONNECTION_TYPE = "vcom"
    # Port: Auto-detect if None, or specify e.g. "/dev/ttyACM0"
    CONNECTION_PORT = None

    @classmethod
    def get_connection_port(cls) -> str:
        """Get SE050 connection port, auto-detecting if needed"""
        if cls.CONNECTION_PORT:
            return cls.CONNECTION_PORT

        # Auto-detect ttyACM device
        devices = glob.glob('/dev/ttyACM*')
        if devices:
            return devices[0]

        # Try ttyUSB as fallback
        devices = glob.glob('/dev/ttyUSB*')
        if devices:
            return devices[0]

        return "none"

    @classmethod
    def pubkey_der_path(cls) -> Path:
        return cls.WALLET_DIR / f"pubkey_{cls.KEY_ID}.der"

    @classmethod
    def pubkey_pem_path(cls) -> Path:
        return cls.WALLET_DIR / f"pubkey_{cls.KEY_ID}.pem"

    @classmethod
    def wallet_info_path(cls) -> Path:
        return cls.WALLET_DIR / f"wallet_{cls.KEY_ID}.json"

    @classmethod
    def api_base(cls) -> str:
        return cls.MEMPOOL_TESTNET_API if cls.NETWORK == "testnet" else cls.MEMPOOL_API

    @classmethod
    def address_version(cls) -> bytes:
        return b'\x6f' if cls.NETWORK == "testnet" else b'\x00'

    @classmethod
    def bech32_hrp(cls) -> str:
        return "tb" if cls.NETWORK == "testnet" else "bc"

    @classmethod
    def load_saved_settings(cls):
        """Load networking settings from GUI config file if it exists"""
        config_path = cls.WALLET_DIR / "gui_config.json"
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    settings = json.load(f)
                if 'tor_enabled' in settings:
                    cls.TOR_ENABLED = settings['tor_enabled']
                if 'tor_proxy' in settings:
                    cls.TOR_PROXY = settings['tor_proxy']
                if 'local_node_enabled' in settings:
                    cls.LOCAL_NODE_ENABLED = settings['local_node_enabled']
                if 'local_node_host' in settings:
                    cls.LOCAL_NODE_RPC_HOST = settings['local_node_host']
                if 'local_node_port' in settings:
                    cls.LOCAL_NODE_RPC_PORT = settings['local_node_port']
                if 'local_node_user' in settings:
                    cls.LOCAL_NODE_RPC_USER = settings['local_node_user']
                if 'local_node_pass' in settings:
                    cls.LOCAL_NODE_RPC_PASS = settings['local_node_pass']
                if 'broadcast_method' in settings:
                    cls.BROADCAST_METHOD = settings['broadcast_method']
            except Exception:
                pass  # Silently ignore errors, use defaults


# Load saved settings on import
Config.load_saved_settings()
