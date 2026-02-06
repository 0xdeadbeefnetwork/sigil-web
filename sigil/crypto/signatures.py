from typing import Tuple, Optional

from sigil.crypto.hashing import sha256, sha256d
from sigil.crypto.ecc import SECP256K1_ORDER, SECP256K1_HALF_ORDER


def parse_der_signature(sig: bytes) -> Tuple[int, int]:
    """Parse DER signature into (r, s) integers"""
    if sig[0] != 0x30:
        raise ValueError("Invalid DER signature")

    idx = 2

    if sig[idx] != 0x02:
        raise ValueError("Invalid DER signature")
    idx += 1
    r_len = sig[idx]
    idx += 1
    r = int.from_bytes(sig[idx:idx + r_len], 'big')
    idx += r_len

    if sig[idx] != 0x02:
        raise ValueError("Invalid DER signature")
    idx += 1
    s_len = sig[idx]
    idx += 1
    s = int.from_bytes(sig[idx:idx + s_len], 'big')

    return r, s


def encode_der_signature(r: int, s: int) -> bytes:
    """Encode (r, s) integers as DER signature"""
    def encode_int(n: int) -> bytes:
        b = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
        return bytes([0x02, len(b)]) + b

    r_enc = encode_int(r)
    s_enc = encode_int(s)
    payload = r_enc + s_enc
    return bytes([0x30, len(payload)]) + payload


def normalize_signature(sig_der: bytes) -> bytes:
    """Normalize signature to low-S form per BIP-62"""
    r, s = parse_der_signature(sig_der)

    if s > SECP256K1_HALF_ORDER:
        s = SECP256K1_ORDER - s

    return encode_der_signature(r, s)


def create_message_hash(message: str) -> bytes:
    """
    Create Bitcoin signed message hash.
    Format: SHA256(SHA256("\\x18Bitcoin Signed Message:\\n" + varint(len) + message))
    """
    prefix = b'\x18Bitcoin Signed Message:\n'
    msg_bytes = message.encode('utf-8')

    # Varint encode message length
    msg_len = len(msg_bytes)
    if msg_len < 0xfd:
        len_bytes = bytes([msg_len])
    elif msg_len <= 0xffff:
        len_bytes = b'\xfd' + msg_len.to_bytes(2, 'little')
    else:
        len_bytes = b'\xfe' + msg_len.to_bytes(4, 'little')

    full_msg = prefix + len_bytes + msg_bytes
    return sha256d(full_msg)


def sign_message_with_se050(key_id: str, message: str) -> Tuple[bytes, int]:
    """
    Sign a message using SE050 and return (signature, recovery_id).
    Returns compact signature format for Bitcoin message signing.
    """
    msg_hash = create_message_hash(message)

    # SE050 signs the hash directly (no second SHA256)
    # But for message signing we need the full double-SHA256
    # So we pass single-SHA256 of the message hash prefix+msg
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
    msg_hash = sha256(sha256(full_msg))  # Double SHA256 for Bitcoin

    # Sign using SE050
    from sigil.hardware.interface import se050_sign
    sig_der = se050_sign(key_id, msg_hash)
    r, s = parse_der_signature(sig_der)

    # Get our public key to determine recovery ID
    from sigil.wallet.core import Wallet
    wallet = Wallet()
    wallet.load()
    our_pubkey = wallet.pubkey_compressed

    # Try recovery IDs 0 and 1 to find the correct one
    from sigil.bitcoin.addresses import compress_pubkey
    recovery_id = 0
    for try_id in [0, 1]:
        try:
            recovered = _recover_pubkey(msg_hash, r, s, try_id)
            if recovered:
                # _recover_pubkey returns 64 bytes (x+y), compress_pubkey expects 65 (0x04+x+y)
                uncompressed = b'\x04' + recovered
                if compress_pubkey(uncompressed) == our_pubkey:
                    recovery_id = try_id
                    break
        except:
            pass

    return (r, s), recovery_id



def _recover_pubkey(msg_hash: bytes, r: int, s: int, recovery_id: int) -> Optional[bytes]:
    """Recover public key from ECDSA signature (secp256k1)"""
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    def modinv(a, m):
        def egcd(a, b):
            if a == 0: return b, 0, 1
            g, y, x = egcd(b % a, a)
            return g, x - (b // a) * y, y
        g, x, _ = egcd(a % m, m)
        return x % m

    def point_add(p1, p2):
        if p1 is None: return p2
        if p2 is None: return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2 and y1 != y2: return None
        if x1 == x2:
            lam = (3 * x1 * x1) * modinv(2 * y1, P) % P
        else:
            lam = (y2 - y1) * modinv(x2 - x1, P) % P
        x3 = (lam * lam - x1 - x2) % P
        y3 = (lam * (x1 - x3) - y1) % P
        return x3, y3

    def point_mul(k, point):
        result = None
        addend = point
        while k:
            if k & 1: result = point_add(result, addend)
            addend = point_add(addend, addend)
            k >>= 1
        return result

    x = r + (recovery_id >> 1) * N
    if x >= P: return None

    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if (y % 2) != (recovery_id & 1): y = P - y

    R = (x, y)
    e = int.from_bytes(msg_hash, 'big')
    r_inv = modinv(r, N)
    sR = point_mul(s, R)
    eG = point_mul(e, (Gx, Gy))
    neg_eG = (eG[0], P - eG[1]) if eG else None
    diff = point_add(sR, neg_eG)
    Q = point_mul(r_inv, diff)

    if Q is None: return None
    return b'' + Q[0].to_bytes(32, 'big') + Q[1].to_bytes(32, 'big')


def encode_signed_message(r: int, s: int, recovery_id: int, compressed: bool = True) -> str:
    """Encode signature as base64 string for Bitcoin signed message"""
    import base64

    # Header byte: 27 + recovery_id + (4 if compressed)
    header = 27 + recovery_id + (4 if compressed else 0)

    # Signature: 1 byte header + 32 bytes r + 32 bytes s = 65 bytes
    sig_bytes = bytes([header])
    sig_bytes += r.to_bytes(32, 'big')
    sig_bytes += s.to_bytes(32, 'big')

    return base64.b64encode(sig_bytes).decode('ascii')
