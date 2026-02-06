#!/usr/bin/env python3
"""
SIGIL Privacy - Message Verification
======================================
Verify Bitcoin signed messages.
"""

import base64
import hashlib

from sigil.crypto.ecc import _point_multiply, SECP256K1_P, SECP256K1_N, SECP256K1_Gx, SECP256K1_Gy
from sigil.crypto.signatures import _recover_pubkey
from sigil.bitcoin.addresses import derive_addresses, compress_pubkey


def verify_signed_message(address: str, signature: str, message: str) -> bool:
    """Verify a Bitcoin signed message"""
    try:
        # Decode signature
        sig_bytes = base64.b64decode(signature)
        if len(sig_bytes) != 65:
            return False

        header = sig_bytes[0]
        r = int.from_bytes(sig_bytes[1:33], 'big')
        s = int.from_bytes(sig_bytes[33:65], 'big')

        # Recovery ID and compression flag
        if header < 27 or header > 34:
            return False
        recovery_id = (header - 27) & 3
        compressed = (header - 27) >= 4

        # Hash the message (Bitcoin signed message format)
        prefix = b'\x18Bitcoin Signed Message:\n'
        msg_bytes = message.encode('utf-8')
        msg_len = len(msg_bytes)
        if msg_len < 0xfd:
            len_bytes = bytes([msg_len])
        elif msg_len <= 0xffff:
            len_bytes = b'\xfd' + msg_len.to_bytes(2, 'little')
        else:
            len_bytes = b'\xfe' + msg_len.to_bytes(4, 'little')
        full_msg = prefix + len_bytes + msg_bytes
        msg_hash = hashlib.sha256(hashlib.sha256(full_msg).digest()).digest()

        # Recover public key from signature
        raw_pubkey = _recover_pubkey(msg_hash, r, s, recovery_id)
        if not raw_pubkey:
            return False

        # _recover_pubkey returns 64 bytes (x+y), compress_pubkey expects 65 (0x04+x+y)
        uncompressed = b'\x04' + raw_pubkey
        pubkey_compressed = compress_pubkey(uncompressed)

        # Derive address and compare
        addresses = derive_addresses(pubkey_compressed)

        # Check if any derived address matches
        return address in addresses.values()

    except Exception as e:
        print(f"Verify error: {e}")
        return False


__all__ = [
    "verify_signed_message",
]
