"""
Wallet state management.
"""

import json
from typing import Optional, Dict
from datetime import datetime

from sigil.bitcoin.config import Config
from sigil.bitcoin.addresses import parse_der_pubkey, compress_pubkey, derive_addresses
from sigil.crypto.hashing import hash160


class Wallet:
    """Wallet state management"""

    def __init__(self):
        self.pubkey_uncompressed: Optional[bytes] = None
        self.pubkey_compressed: Optional[bytes] = None
        self.addresses: Optional[Dict[str, str]] = None
        self.created_at: Optional[str] = None

    def load(self) -> bool:
        """Load wallet from disk"""
        if not Config.pubkey_der_path().exists():
            return False

        try:
            der_data = Config.pubkey_der_path().read_bytes()
            self.pubkey_uncompressed = parse_der_pubkey(der_data)
            self.pubkey_compressed = compress_pubkey(self.pubkey_uncompressed)
            self.addresses = derive_addresses(self.pubkey_compressed)

            if Config.wallet_info_path().exists():
                info = json.loads(Config.wallet_info_path().read_text())
                self.created_at = info.get('created_at')

            return True
        except Exception as e:
            print(f"Failed to load wallet: {e}")
            return False

    def save_info(self):
        """Save wallet metadata"""
        info = {
            'key_id': Config.KEY_ID,
            'created_at': self.created_at or datetime.now().isoformat(),
            'network': Config.NETWORK,
            'pubkey_compressed': self.pubkey_compressed.hex() if self.pubkey_compressed else None,
            'addresses': self.addresses
        }
        Config.wallet_info_path().write_text(json.dumps(info, indent=2))

    @property
    def pubkey_hash(self) -> bytes:
        """Get pubkey hash (HASH160 of compressed pubkey)"""
        if not self.pubkey_compressed:
            raise ValueError("Wallet not loaded")
        return hash160(self.pubkey_compressed)
