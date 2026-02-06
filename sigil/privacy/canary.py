#!/usr/bin/env python3
"""
SIGIL Privacy - Canary System
==============================
Cryptographic proof of non-compromise via warrant canary.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from sigil.hardware.session import SE050Session

SIGIL_DIR = Path.home() / ".sigil"
CANARY_FILE = SIGIL_DIR / "canary.json"


class Canary:
    """Cryptographic proof of non-compromise"""

    def __init__(self):
        self.message: Optional[str] = None
        self.signature: Optional[str] = None
        self.address: Optional[str] = None
        self.created_at: Optional[str] = None
        self.expires_at: Optional[str] = None
        self.sequence: int = 0

    def to_dict(self) -> dict:
        return {
            "message": self.message,
            "signature": self.signature,
            "address": self.address,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "sequence": self.sequence,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Canary":
        c = cls()
        for key, value in data.items():
            if hasattr(c, key):
                setattr(c, key, value)
        return c

    def save(self):
        SIGIL_DIR.mkdir(parents=True, exist_ok=True)
        CANARY_FILE.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls) -> Optional["Canary"]:
        if CANARY_FILE.exists():
            try:
                data = json.loads(CANARY_FILE.read_text())
                return cls.from_dict(data)
            except:
                pass
        return None

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        expires = datetime.fromisoformat(self.expires_at)
        return datetime.now() > expires

    def days_until_expiry(self) -> int:
        if not self.expires_at:
            return 999
        expires = datetime.fromisoformat(self.expires_at)
        delta = expires - datetime.now()
        return max(0, delta.days)


def generate_canary_message(validity_days: int = 30, custom_text: str = "") -> str:
    """Generate canary message text"""
    now = datetime.now()
    expires = now + timedelta(days=validity_days)

    msg = f"""=== SIGIL WARRANT CANARY ===

As of {now.strftime('%Y-%m-%d %H:%M UTC')}, I hereby declare:

1. I have NOT received any National Security Letters or FISA court orders.
2. I have NOT been subject to any gag orders preventing disclosure.
3. I have NOT been compelled to compromise the security of my systems.
4. I have NOT provided any private keys or access to any third party.
5. I am in full control of this wallet and signing key.

This canary is valid until: {expires.strftime('%Y-%m-%d %H:%M UTC')}
If this canary is not renewed by the expiration date, assume compromise.

{custom_text}

Sequence number: {{seq}}"""
    return msg.strip()


def create_canary(validity_days: int = 30, custom_text: str = "") -> Canary:
    """Create and sign a new canary"""
    from sigil.bitcoin.config import Config
    from sigil.crypto.signatures import sign_message_with_se050, encode_signed_message
    from sigil.hardware.interface import se050_connect, se050_disconnect

    # Load wallet
    from sigil.wallet.core import Wallet
    wallet = Wallet()
    if not wallet.load():
        raise Exception("Wallet not loaded")

    # Get previous sequence number
    prev = Canary.load()
    seq = (prev.sequence + 1) if prev else 1

    # Generate message
    msg = generate_canary_message(validity_days, custom_text)
    msg = msg.replace("{seq}", str(seq))

    # Sign with SE050
    se050_connect()
    try:
        (r, s), recovery_id = sign_message_with_se050(Config.KEY_ID, msg)
        signature = encode_signed_message(r, s, recovery_id)
    finally:
        se050_disconnect()

    # Create canary
    canary = Canary()
    canary.message = msg
    canary.signature = signature
    canary.address = wallet.addresses.get("segwit", "")
    canary.created_at = datetime.now().isoformat()
    canary.expires_at = (datetime.now() + timedelta(days=validity_days)).isoformat()
    canary.sequence = seq
    canary.save()

    return canary


def export_canary_text(canary: Canary) -> str:
    """Export canary as verifiable text"""
    return f"""{canary.message}

-----BEGIN BITCOIN SIGNED MESSAGE-----
Address: {canary.address}
Signature: {canary.signature}
-----END BITCOIN SIGNED MESSAGE-----
"""


__all__ = [
    "Canary", "generate_canary_message", "create_canary", "export_canary_text",
]
