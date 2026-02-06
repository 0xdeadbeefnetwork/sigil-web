import hashlib


def sha256(data: bytes) -> bytes:
    """Single SHA256 hash - use sha256_se050() for hardware version"""
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    """Double SHA256 hash (Bitcoin standard)"""
    return sha256(sha256(data))


def ripemd160(data: bytes) -> bytes:
    """RIPEMD160 hash"""
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()


def hash160(data: bytes) -> bytes:
    """HASH160: SHA256 followed by RIPEMD160"""
    return ripemd160(sha256(data))
