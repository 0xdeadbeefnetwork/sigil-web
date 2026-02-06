from typing import Tuple, Optional


# secp256k1 curve parameters
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# secp256k1 curve order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_ORDER = SECP256K1_ORDER // 2


def _modinv(a: int, m: int) -> int:
    """Modular multiplicative inverse using extended Euclidean algorithm."""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def _point_add(p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    """Add two points on secp256k1 curve."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        return None

    if x1 == x2:
        m = (3 * x1 * x1 * _modinv(2 * y1, SECP256K1_P)) % SECP256K1_P
    else:
        m = ((y2 - y1) * _modinv(x2 - x1, SECP256K1_P)) % SECP256K1_P

    x3 = (m * m - x1 - x2) % SECP256K1_P
    y3 = (m * (x1 - x3) - y1) % SECP256K1_P
    return (x3, y3)


def _point_multiply(k: int, point: Optional[Tuple[int, int]] = None) -> Optional[Tuple[int, int]]:
    """Multiply point by scalar on secp256k1 curve."""
    if point is None:
        point = (SECP256K1_Gx, SECP256K1_Gy)

    result = None
    addend = point

    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1

    return result


def _privkey_to_pubkey(privkey: bytes) -> bytes:
    """Derive uncompressed public key from private key."""
    k = int.from_bytes(privkey, 'big')
    point = _point_multiply(k)
    if point is None:
        raise ValueError("Invalid private key")
    x, y = point
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def _serialize_pubkey_compressed(pubkey: bytes) -> bytes:
    """Serialize public key in compressed format."""
    if len(pubkey) == 33:
        return pubkey
    if len(pubkey) != 65 or pubkey[0] != 0x04:
        raise ValueError("Invalid public key")
    x = pubkey[1:33]
    y = int.from_bytes(pubkey[33:65], 'big')
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x
