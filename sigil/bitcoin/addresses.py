"""
Bitcoin address derivation from public keys.
"""

from typing import Dict

from sigil.crypto.hashing import hash160
from sigil.crypto.encoding import b58check_encode, bech32_encode, convertbits
from sigil.bitcoin.config import Config


def compress_pubkey(pubkey: bytes) -> bytes:
    """Compress 65-byte uncompressed public key to 33-byte compressed"""
    if len(pubkey) != 65 or pubkey[0] != 0x04:
        raise ValueError("Invalid uncompressed public key")
    x = pubkey[1:33]
    y = pubkey[33:65]
    prefix = b'\x02' if y[-1] % 2 == 0 else b'\x03'
    return prefix + x


def parse_der_pubkey(der_data: bytes) -> bytes:
    """Extract 65-byte uncompressed public key from DER-encoded SubjectPublicKeyInfo"""
    idx = der_data.find(b'\x04', 20)
    if idx == -1:
        raise ValueError("Could not find uncompressed public key marker in DER data")
    return der_data[idx:idx + 65]


def derive_addresses(pubkey_compressed: bytes) -> Dict[str, str]:
    """Derive Bitcoin addresses from compressed public key"""
    pubkey_hash = hash160(pubkey_compressed)

    legacy = b58check_encode(Config.address_version(), pubkey_hash)
    segwit = bech32_encode(Config.bech32_hrp(), [0] + convertbits(pubkey_hash, 8, 5))

    return {
        'legacy': legacy,
        'segwit': segwit,
        'pubkey_hash': pubkey_hash.hex()
    }
