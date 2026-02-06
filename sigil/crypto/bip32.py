import hmac
import hashlib
from typing import Tuple

from sigil.crypto.ecc import (
    SECP256K1_N,
    _privkey_to_pubkey,
    _serialize_pubkey_compressed,
)


def derive_master_key(seed: bytes) -> Tuple[bytes, bytes]:
    """Derive master private key and chain code from seed (BIP32)."""
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_key = I[:32]
    chain_code = I[32:]

    # Verify key is valid
    k = int.from_bytes(master_key, 'big')
    if k == 0 or k >= SECP256K1_N:
        raise ValueError("Invalid master key derived")

    return master_key, chain_code


def derive_child_key(parent_key: bytes, parent_chain: bytes, index: int, hardened: bool = False) -> Tuple[bytes, bytes]:
    """Derive child private key from parent (BIP32)."""
    if hardened:
        index += 0x80000000
        data = b'\x00' + parent_key + index.to_bytes(4, 'big')
    else:
        pubkey = _privkey_to_pubkey(parent_key)
        pubkey_compressed = _serialize_pubkey_compressed(pubkey)
        data = pubkey_compressed + index.to_bytes(4, 'big')

    I = hmac.new(parent_chain, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]

    child_key = (int.from_bytes(IL, 'big') + int.from_bytes(parent_key, 'big')) % SECP256K1_N
    if child_key == 0:
        raise ValueError("Invalid child key")

    return child_key.to_bytes(32, 'big'), IR


def derive_bip44_key(seed: bytes, account: int = 0, change: int = 0, index: int = 0,
                     coin_type: int = 0) -> Tuple[bytes, bytes]:
    """
    Derive BIP44 key: m/44'/coin'/account'/change/index
    coin_type: 0 = Bitcoin mainnet, 1 = testnet
    Returns (private_key, public_key_uncompressed)
    """
    master_key, chain_code = derive_master_key(seed)

    # m/44' (purpose)
    key, chain = derive_child_key(master_key, chain_code, 44, hardened=True)
    # m/44'/coin' (coin type)
    key, chain = derive_child_key(key, chain, coin_type, hardened=True)
    # m/44'/coin'/account' (account)
    key, chain = derive_child_key(key, chain, account, hardened=True)
    # m/44'/coin'/account'/change (external/internal)
    key, chain = derive_child_key(key, chain, change, hardened=False)
    # m/44'/coin'/account'/change/index (address index)
    key, chain = derive_child_key(key, chain, index, hardened=False)

    pubkey = _privkey_to_pubkey(key)
    return key, pubkey


def derive_bip84_key(seed: bytes, account: int = 0, change: int = 0, index: int = 0,
                     coin_type: int = 0) -> Tuple[bytes, bytes]:
    """
    Derive BIP84 key (Native SegWit): m/84'/coin'/account'/change/index
    coin_type: 0 = Bitcoin mainnet, 1 = testnet
    Returns (private_key, public_key_uncompressed)
    """
    master_key, chain_code = derive_master_key(seed)

    # m/84' (purpose - native segwit)
    key, chain = derive_child_key(master_key, chain_code, 84, hardened=True)
    # m/84'/coin'
    key, chain = derive_child_key(key, chain, coin_type, hardened=True)
    # m/84'/coin'/account'
    key, chain = derive_child_key(key, chain, account, hardened=True)
    # m/84'/coin'/account'/change
    key, chain = derive_child_key(key, chain, change, hardened=False)
    # m/84'/coin'/account'/change/index
    key, chain = derive_child_key(key, chain, index, hardened=False)

    pubkey = _privkey_to_pubkey(key)
    return key, pubkey
