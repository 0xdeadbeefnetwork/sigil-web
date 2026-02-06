from typing import Tuple, List

from sigil.crypto.hashing import sha256d


B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def b58encode(data: bytes) -> str:
    """Base58 encode (no checksum)"""
    n = int.from_bytes(data, 'big')
    result = ''
    while n > 0:
        n, r = divmod(n, 58)
        result = B58_ALPHABET[r] + result
    for byte in data:
        if byte == 0:
            result = '1' + result
        else:
            break
    return result or '1'


def b58check_encode(version: bytes, payload: bytes) -> str:
    """Base58Check encode with version byte and checksum"""
    data = version + payload
    checksum = sha256d(data)[:4]
    return b58encode(data + checksum)


def b58check_decode(addr: str) -> Tuple[bytes, bytes]:
    """Base58Check decode, returns (version, payload)"""
    n = 0
    for c in addr:
        n = n * 58 + B58_ALPHABET.index(c)
    data = n.to_bytes(25, 'big')
    version, payload, checksum = data[0:1], data[1:21], data[21:]
    if sha256d(version + payload)[:4] != checksum:
        raise ValueError("Invalid Base58Check checksum")
    return version, payload


def bech32_polymod(values: List[int]) -> int:
    """Bech32 checksum computation"""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> List[int]:
    """Expand HRP for checksum computation"""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp: str, data: List[int]) -> List[int]:
    """Create Bech32 checksum"""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: List[int]) -> str:
    """Encode to Bech32"""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([BECH32_CHARSET[d] for d in combined])


def bech32_decode(addr: str) -> Tuple[str, int, bytes]:
    """Decode Bech32 address, returns (hrp, witness_version, witness_program)"""
    pos = addr.rfind('1')
    hrp = addr[:pos].lower()
    data = [BECH32_CHARSET.index(c) for c in addr[pos + 1:].lower()]
    witness_version = data[0]
    witness_program = convertbits(data[1:-6], 5, 8, pad=False)
    return hrp, witness_version, bytes(witness_program)


def convertbits(data: List[int], frombits: int, tobits: int, pad: bool = True) -> List[int]:
    """Convert between bit widths"""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    return ret
