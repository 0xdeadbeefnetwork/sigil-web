"""
High-level SE050 hardware interface.

Provides module-level wrapper functions around the SE050Session class,
managing a global session singleton for convenient access from wallet
operations.
"""

from pathlib import Path
from typing import Optional

from sigil.hardware.session import SE050Session, normalize_signature_low_s
from sigil.hardware.constants import (
    SE050_CURVE_SECP256K1, SE050_CURVE_NIST_P256, SE050E_KEY_VERSION,
)
from sigil.hardware.errors import SE050Error
from sigil.hardware.scp03 import _load_scp03_keys

# Check if native library is available (without opening a session)
_HAS_NATIVE_SE050 = True
try:
    import ctypes
    from pathlib import Path as _Path
    _lib_paths = [
        _Path(__file__).parent / "libse050.so",
        _Path.cwd() / "libse050.so",
        _Path("/usr/local/lib/libse050.so"),
        _Path("/opt/sigil/native/libse050.so"),
    ]
    _found = False
    for _p in _lib_paths:
        if _p.exists():
            _found = True
            break
    if not _found:
        # Try system path
        import shutil
        if not shutil.which("libse050.so"):
            # Check ldconfig
            import subprocess
            try:
                _ld = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True, timeout=5)
                if "libse050" not in _ld.stdout:
                    _HAS_NATIVE_SE050 = False
            except:
                _HAS_NATIVE_SE050 = False
except:
    _HAS_NATIVE_SE050 = False

# Global session holder
_se050_session: Optional['SE050Session'] = None


def se050_check_connection() -> bool:
    """Check if SE050 is connected and accessible"""
    global _se050_session
    return _se050_session is not None and _se050_session._connected


def se050_connect(retries: int = 3, debug: bool = False) -> bool:
    """Establish connection to SE050 with verification"""
    global _se050_session
    import time
    import os

    # Avoid circular import
    from sigil.bitcoin.config import Config

    # Force debug on if SE050_DEBUG env var is set
    if os.environ.get('SE050_DEBUG'):
        debug = True

    # Already connected?
    if _se050_session is not None and _se050_session._connected:
        return True

    port = Config.get_connection_port()
    enc_key, mac_key = _load_scp03_keys()

    for attempt in range(retries):
        try:
            _se050_session = SE050Session(
                device=port,
                enc_key=enc_key,
                mac_key=mac_key,
                key_version=SE050E_KEY_VERSION,
                debug=debug
            )
            _se050_session.connect()

            return True

        except SE050Error as e:
            if debug or attempt == retries - 1:
                print(f"  Connection error: {e}")
            if _se050_session:
                try:
                    _se050_session.disconnect()
                except:
                    pass
                _se050_session = None
            time.sleep(0.5)

        except Exception as e:
            if debug or attempt == retries - 1:
                print(f"  Connection error: {e}")
            time.sleep(0.5)

    return False


def se050_disconnect():
    """Disconnect from SE050"""
    global _se050_session
    if _se050_session is not None:
        try:
            _se050_session.disconnect()
        except:
            pass
        _se050_session = None


def se050_reconnect() -> bool:
    """Force disconnect and reconnect"""
    se050_disconnect()
    import time
    time.sleep(0.5)
    return se050_connect()


def se050_get_uid() -> Optional[str]:
    """Get SE050 unique identifier"""
    global _se050_session
    if _se050_session is None:
        return None
    try:
        uid = _se050_session.get_uid()
        return uid.hex()
    except:
        return None


def se050_read_state() -> Optional[dict]:
    """Read SE050 device state (lock, restrict, platform SCP)"""
    global _se050_session
    if _se050_session is None:
        return None
    try:
        return _se050_session.read_state()
    except:
        return None


def se050_get_random(num_bytes: int = 16) -> Optional[bytes]:
    """Get random bytes from SE050 TRNG"""
    global _se050_session
    if _se050_session is None:
        return None
    try:
        return _se050_session.get_random(num_bytes)
    except:
        return None


def se050_sha256(data: bytes) -> Optional[bytes]:
    """Compute SHA-256 hash on SE050 (on-chip, data never leaves SE)"""
    global _se050_session
    if _se050_session is None:
        return None
    try:
        return _se050_session.sha256(data)
    except:
        return None


def se050_pbkdf2(password: bytes, salt: bytes, iterations: int, key_len: int = 32) -> Optional[bytes]:
    """Compute PBKDF2-HMAC-SHA256 on SE050 (on-chip)"""
    global _se050_session
    if _se050_session is None:
        return None
    try:
        return _se050_session.pbkdf2(password, salt, iterations, key_len)
    except:
        return None


def se050_pbkdf2_sha512(password: bytes, salt: bytes, iterations: int, key_len: int = 64) -> Optional[bytes]:
    """
    Compute PBKDF2-HMAC-SHA512 equivalent on SE050.
    SE050 only supports HMAC-SHA256, so we derive two halves and concatenate.
    This provides 64-byte output compatible with BIP39 seed derivation.
    """
    global _se050_session
    if _se050_session is None:
        return None
    try:
        return _se050_session.pbkdf2_sha512(password, salt, iterations, key_len)
    except:
        return None


def se050_verify(key_id: str, hash_data: bytes, signature: bytes) -> Optional[bool]:
    """
    Verify ECDSA signature using SE050 hardware.
    Verification happens entirely on the secure element.

    Args:
        key_id: Key ID (hex string like "20000001")
        hash_data: 32-byte hash that was signed
        signature: DER-encoded ECDSA signature

    Returns:
        True if valid, False if invalid, None if SE050 unavailable
    """
    global _se050_session
    if _se050_session is None:
        return None
    try:
        key_id_int = int(key_id, 16)
        return _se050_session.verify(key_id_int, hash_data, signature)
    except:
        return None


def se050_write_binary(object_id: int, data: bytes) -> bool:
    """Write binary data to SE050 secure storage"""
    global _se050_session
    if _se050_session is None:
        return False
    try:
        _se050_session.write_binary(object_id, data)
        return True
    except:
        return False


def se050_read_binary(object_id: int, max_len: int = 800) -> Optional[bytes]:
    """Read binary data from SE050 secure storage"""
    global _se050_session
    if _se050_session is None:
        return None
    try:
        return _se050_session.read_binary(object_id, max_len)
    except:
        return None


def se050_write_hmac_key(object_id: int, key: bytes) -> bool:
    """Write HMAC key to SE050 (for PBKDF2 with stored entropy)"""
    global _se050_session
    if _se050_session is None:
        return False
    try:
        _se050_session.write_hmac_key(object_id, key)
        return True
    except:
        return False


def se050_pbkdf2_with_key(hmac_key_id: int, salt: bytes, iterations: int, key_len: int = 32) -> Optional[bytes]:
    """Compute PBKDF2 using HMAC key stored on SE050 (entropy never leaves chip)"""
    global _se050_session
    if _se050_session is None:
        return None
    try:
        return _se050_session.pbkdf2_with_key(hmac_key_id, salt, iterations, key_len)
    except:
        return None


def se050_delete_object(object_id: int) -> bool:
    """Delete object from SE050"""
    global _se050_session
    if _se050_session is None:
        return False
    try:
        _se050_session.delete_object(object_id)
        return True
    except:
        return False


def se050_generate_keypair(key_id: str, curve: str = "Secp256k1") -> bool:
    """Generate ECC keypair on SE050. Deletes existing key in slot if present."""
    global _se050_session
    if _se050_session is None:
        print("Not connected to SE050")
        return False
    try:
        key_id_int = int(key_id, 16)
        curve_id = SE050_CURVE_SECP256K1  # Only secp256k1 for Bitcoin
        # Delete existing key if present (needed for tumbler slot reuse)
        if _se050_session.object_exists(key_id_int):
            try:
                _se050_session.delete_object(key_id_int)
            except:
                pass  # Best effort
        _se050_session.generate_keypair(key_id_int, curve_id)
        return True
    except Exception as e:
        print(f"Key generation failed: {e}")
        return False


def _derive_pubkey_uncompressed(private_key: bytes) -> bytes:
    """
    Derive uncompressed public key (65 bytes: 0x04 + X + Y) from private key.
    Uses secp256k1 curve.
    """
    # secp256k1 parameters
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    A = 0
    B = 7
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    def modinv(a, m):
        if a < 0:
            a = m + a
        g, x, _ = extended_gcd(a, m)
        if g != 1:
            raise ValueError("No modular inverse")
        return x % m

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def point_add(p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2:
            if y1 != y2:
                return None
            # Point doubling
            s = (3 * x1 * x1 + A) * modinv(2 * y1, P) % P
        else:
            s = (y2 - y1) * modinv(x2 - x1, P) % P
        x3 = (s * s - x1 - x2) % P
        y3 = (s * (x1 - x3) - y1) % P
        return (x3, y3)

    def scalar_mult(k, point):
        result = None
        addend = point
        while k:
            if k & 1:
                result = point_add(result, addend)
            addend = point_add(addend, addend)
            k >>= 1
        return result

    k = int.from_bytes(private_key, 'big')
    pub_point = scalar_mult(k, (Gx, Gy))

    pub_x = pub_point[0].to_bytes(32, 'big')
    pub_y = pub_point[1].to_bytes(32, 'big')

    return b'\x04' + pub_x + pub_y


def se050_set_ecc_keypair(key_id: str, private_key: bytes, curve: str = "Secp256k1") -> bool:
    """
    Import/set an ECC keypair on SE050 from a private key.
    The private key is written to the SE050 - after this, the SE050 holds the key.

    Args:
        key_id: SE050 key slot ID (hex string like "20000001")
        private_key: 32-byte secp256k1 private key
        curve: Curve type (default Secp256k1)

    Returns:
        True if successful
    """
    global _se050_session

    if _se050_session is None:
        raise SE050Error("Not connected to SE050")

    if len(private_key) != 32:
        raise ValueError(f"Private key must be 32 bytes, got {len(private_key)}")

    key_id_int = int(key_id, 16)

    # First, ensure any existing key is deleted
    print(f"  Checking if key 0x{key_id} exists...")
    if se050_key_exists(key_id):
        print(f"  Key exists, deleting...")
        try:
            _se050_session.delete_object(key_id_int)
            print(f"  Existing key deleted")
            import time
            time.sleep(0.3)  # Give SE050 time to settle
        except Exception as e:
            print(f"  Warning: Delete failed: {e}")

    # Derive the public key from private key
    public_key = _derive_pubkey_uncompressed(private_key)

    # Import the full keypair to SE050
    try:
        print(f"  Writing keypair to SE050...")
        _se050_session.write_keypair(key_id_int, SE050_CURVE_SECP256K1, private_key, public_key)
        print(f"  Key written successfully")

        # Verify
        if se050_key_exists(key_id):
            return True
        else:
            print(f"  Warning: Key write succeeded but key not found")
            return False

    except Exception as e:
        raise SE050Error(f"Failed to write key to SE050: {e}")


def se050_export_pubkey(key_id: str, output_path: Path, format: str = "DER") -> bool:
    """Export public key from SE050 and save to file"""
    global _se050_session

    if _se050_session is None:
        print("Not connected to SE050")
        return False

    try:
        key_id_int = int(key_id, 16)
        pubkey = _se050_session.read_pubkey(key_id_int)

        if format == "DER":
            # Wrap in DER SubjectPublicKeyInfo
            der_pubkey = _build_pubkey_der(pubkey)
            output_path.write_bytes(der_pubkey)
        elif format == "PEM":
            import base64
            der_pubkey = _build_pubkey_der(pubkey)
            pem = b"-----BEGIN PUBLIC KEY-----\n"
            pem += base64.encodebytes(der_pubkey)
            pem += b"-----END PUBLIC KEY-----\n"
            output_path.write_bytes(pem)
        else:
            # Raw public key
            output_path.write_bytes(pubkey)

        return True
    except Exception as e:
        print(f"Public key export failed: {e}")
        return False


def _build_pubkey_der(pubkey: bytes) -> bytes:
    """Build DER SubjectPublicKeyInfo for EC public key"""
    # OID for ecPublicKey: 1.2.840.10045.2.1
    ec_oid = bytes([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])
    # OID for secp256k1: 1.3.132.0.10
    secp256k1_oid = bytes([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a])

    # AlgorithmIdentifier SEQUENCE
    algo_seq = bytes([0x30, len(ec_oid) + len(secp256k1_oid)]) + ec_oid + secp256k1_oid

    # BIT STRING containing the public key (0x00 = no unused bits)
    bitstring = bytes([0x03, len(pubkey) + 1, 0x00]) + pubkey

    # Outer SEQUENCE
    inner = algo_seq + bitstring
    return bytes([0x30, len(inner)]) + inner


def se050_delete_key(key_id: str) -> bool:
    """Delete key from SE050"""
    global _se050_session

    if _se050_session is None:
        print("Not connected to SE050")
        return False

    try:
        key_id_int = int(key_id, 16)
        _se050_session.delete_object(key_id_int)
        return True
    except Exception as e:
        print(f"Key deletion failed: {e}")
        return False


def se050_sign(key_id: str, data: bytes) -> bytes:
    """
    Sign data using SE050 key, returns normalized low-S DER signature.

    IMPORTANT: For our native library, 'data' should be the 32-byte hash
    that you want to sign. The SE050 signs this hash directly (no additional
    hashing). Apply double-SHA256 BEFORE calling this function if needed.
    """
    global _se050_session

    if _se050_session is None:
        raise SE050Error("Not connected to SE050")

    if len(data) != 32:
        raise SE050Error(f"Data must be 32-byte hash, got {len(data)} bytes")

    try:
        key_id_int = int(key_id, 16)
        signature = _se050_session.sign(key_id_int, data)

        # Normalize to low-S for Bitcoin BIP-62/BIP-146 compliance
        signature = normalize_signature_low_s(signature)

        return signature
    except Exception as e:
        raise SE050Error(f"Signing failed: {e}")


def se050_key_exists(key_id: str) -> bool:
    """Check if key exists in SE050"""
    global _se050_session

    if _se050_session is None:
        return False

    try:
        key_id_int = int(key_id, 16)
        return _se050_session.object_exists(key_id_int)
    except:
        return False
