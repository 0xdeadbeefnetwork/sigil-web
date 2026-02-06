"""
SE050 session management - ctypes bindings for the SE050 VCOM library.

This module provides the SE050Session class which manages authenticated
SCP03 sessions with the SE050 secure element via the native C library.
"""

import ctypes
from ctypes import c_int, c_uint8, c_uint32, c_size_t, c_char_p, POINTER, byref
from pathlib import Path
from typing import Optional
import glob as glob_module
import os
import time

from sigil.hardware.constants import (
    SE050_OK, SE050_ERR_PARAM, SE050_ERR_OPEN, SE050_ERR_TIMEOUT,
    SE050_CURVE_SECP256K1, SE050E_KEY_VERSION,
)
from sigil.hardware.errors import SE050Error
from sigil.hardware.locking import (
    _HAS_FCNTL, _SE050_LOCK_FILE, _SE050_LOCK_TIMEOUT,
    _SE050_LOCK_STALE_TIMEOUT, _check_stale_lock,
)

# Conditionally import fcntl for lock operations within session methods
try:
    import fcntl
except ImportError:
    pass


class SE050Session:
    """
    Context manager for SE050 session with SCP03 authentication.

    Example:
        with SE050Session("/dev/ttyACM0", enc_key, mac_key) as se:
            pubkey = se.read_pubkey(0x20000001)
    """

    # Session structure size (must match C struct)
    _SESSION_SIZE = 512  # Generous buffer for the session struct

    def __init__(self, device: str = None, enc_key: bytes = None, mac_key: bytes = None,
                 key_version: int = SE050E_KEY_VERSION, debug: bool = False,
                 dek_key: bytes = None, isd_mode: bool = False):
        """
        Initialize SE050 session.

        Args:
            device: Serial device path (e.g., "/dev/ttyACM0"), auto-detect if None
            enc_key: 16-byte SCP03 encryption key
            mac_key: 16-byte SCP03 MAC key
            key_version: SCP03 key version (default: 0x0B for SE050E)
            debug: Enable debug output
            dek_key: 16-byte SCP03 DEK key (required for key rotation)
            isd_mode: If True, open session for ISD operations (key rotation)
                      without selecting the SE05x applet. Required for PUT KEY.
        """
        self._lib = None
        self._session = None
        self._device = device
        self._enc_key = enc_key
        self._mac_key = mac_key
        self._dek_key = dek_key
        self._key_version = key_version
        self._debug = debug
        self._connected = False
        self._isd_mode = isd_mode
        self._lock_fd = None  # File lock handle

        # Load library
        self._load_library()

    def _load_library(self):
        """Load the native library"""
        # Try different library locations
        lib_paths = [
            Path(__file__).parent / "libse050.so",
            Path.cwd() / "libse050.so",
            "libse050.so",  # System path
            "/usr/local/lib/libse050.so",
        ]

        for path in lib_paths:
            try:
                self._lib = ctypes.CDLL(str(path))
                self._lib_path = str(path)
                break
            except OSError:
                continue

        if self._lib is None:
            raise SE050Error(SE050_ERR_OPEN, "Could not load libse050.so")

        # Debug: print which library was loaded
        import os
        if os.environ.get('SE050_DEBUG'):
            print(f"[DEBUG] Loaded library from: {self._lib_path}")

        # Define function signatures
        self._define_functions()

    def _define_functions(self):
        """Define ctypes function signatures"""
        lib = self._lib

        import os
        debug = os.environ.get('SE050_DEBUG')

        # void se050_set_debug(int enable)
        lib.se050_set_debug.argtypes = [c_int]
        lib.se050_set_debug.restype = None

        # int se050_open_session(session*, device, enc_key, mac_key, key_ver)
        lib.se050_open_session.argtypes = [
            POINTER(c_uint8),  # session buffer
            c_char_p,          # device
            POINTER(c_uint8),  # enc_key
            POINTER(c_uint8),  # mac_key
            c_uint8            # key_version
        ]
        lib.se050_open_session.restype = c_int

        # int se050_open_session_with_dek(session*, device, enc_key, mac_key, dek_key, key_ver)
        # This is optional - only needed for key rotation
        self._has_open_with_dek = False
        if hasattr(lib, 'se050_open_session_with_dek'):
            try:
                lib.se050_open_session_with_dek.argtypes = [
                    POINTER(c_uint8),  # session buffer
                    c_char_p,          # device
                    POINTER(c_uint8),  # enc_key
                    POINTER(c_uint8),  # mac_key
                    POINTER(c_uint8),  # dek_key
                    c_uint8            # key_version
                ]
                lib.se050_open_session_with_dek.restype = c_int
                self._has_open_with_dek = True
                if debug:
                    print("[DEBUG] se050_open_session_with_dek: AVAILABLE")
            except Exception as e:
                if debug:
                    print(f"[DEBUG] se050_open_session_with_dek: setup failed ({e})")
        else:
            if debug:
                print("[DEBUG] se050_open_session_with_dek: NOT FOUND in library")

        # int se050_open_session_isd(session*, dev, enc, mac, dek, key_ver)
        # For key rotation - authenticates to ISD without selecting applet
        self._has_open_isd = False
        if hasattr(lib, 'se050_open_session_isd'):
            try:
                lib.se050_open_session_isd.argtypes = [
                    POINTER(c_uint8), c_char_p,
                    POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8), c_uint8
                ]
                lib.se050_open_session_isd.restype = c_int
                self._has_open_isd = True
                if debug:
                    print("[DEBUG] se050_open_session_isd: AVAILABLE")
            except Exception as e:
                if debug:
                    print(f"[DEBUG] se050_open_session_isd: setup failed ({e})")
        else:
            if debug:
                print("[DEBUG] se050_open_session_isd: NOT FOUND in library")

        # void se050_close_session(session*)
        lib.se050_close_session.argtypes = [POINTER(c_uint8)]
        lib.se050_close_session.restype = None

        # int se050_get_random(session*, buffer, len)
        lib.se050_get_random.argtypes = [POINTER(c_uint8), POINTER(c_uint8), c_size_t]
        lib.se050_get_random.restype = c_int

        # int se050_generate_keypair(session*, key_id, curve_id)
        lib.se050_generate_keypair.argtypes = [POINTER(c_uint8), c_uint32, c_uint8]
        lib.se050_generate_keypair.restype = c_int

        # int se050_write_keypair(session*, key_id, curve_id, private_key, priv_len, public_key, pub_len)
        lib.se050_write_keypair.argtypes = [
            POINTER(c_uint8), c_uint32, c_uint8, POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t
        ]
        lib.se050_write_keypair.restype = c_int

        # int se050_read_pubkey(session*, key_id, pubkey, pubkey_len*)
        lib.se050_read_pubkey.argtypes = [
            POINTER(c_uint8), c_uint32, POINTER(c_uint8), POINTER(c_size_t)
        ]
        lib.se050_read_pubkey.restype = c_int

        # int se050_delete_object(session*, object_id)
        lib.se050_delete_object.argtypes = [POINTER(c_uint8), c_uint32]
        lib.se050_delete_object.restype = c_int

        # int se050_object_exists(session*, object_id)
        lib.se050_object_exists.argtypes = [POINTER(c_uint8), c_uint32]
        lib.se050_object_exists.restype = c_int

        # int se050_sign(session*, key_id, hash, hash_len, signature, sig_len*)
        lib.se050_sign.argtypes = [
            POINTER(c_uint8), c_uint32,
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8), POINTER(c_size_t)
        ]
        lib.se050_sign.restype = c_int

        # int se050_verify(session*, key_id, hash, hash_len, signature, sig_len)
        # Returns: 1=valid, 0=invalid, negative=error
        self._has_verify = False
        try:
            lib.se050_verify.argtypes = [
                POINTER(c_uint8), c_uint32,
                POINTER(c_uint8), c_size_t,
                POINTER(c_uint8), c_size_t
            ]
            lib.se050_verify.restype = c_int
            self._has_verify = True
        except AttributeError:
            pass

        # int se050_get_uid(session*, uid, uid_len*)
        lib.se050_get_uid.argtypes = [POINTER(c_uint8), POINTER(c_uint8), POINTER(c_size_t)]
        lib.se050_get_uid.restype = c_int

        # int se050_read_state(session*, state, state_len*)
        lib.se050_read_state.argtypes = [POINTER(c_uint8), POINTER(c_uint8), POINTER(c_size_t)]
        lib.se050_read_state.restype = c_int

        # Check for optional crypto functions (may not be in older library builds)
        self._has_crypto = False
        try:
            # int se050_sha256(session*, data, data_len, hash)
            lib.se050_sha256.argtypes = [POINTER(c_uint8), POINTER(c_uint8), c_size_t, POINTER(c_uint8)]
            lib.se050_sha256.restype = c_int

            # int se050_pbkdf2(session*, password, password_len, salt, salt_len, iterations, key_len, derived_key)
            lib.se050_pbkdf2.argtypes = [
                POINTER(c_uint8),
                POINTER(c_uint8), c_size_t,  # password, password_len
                POINTER(c_uint8), c_size_t,  # salt, salt_len
                c_uint32, c_size_t,          # iterations, key_len
                POINTER(c_uint8)             # derived_key
            ]
            lib.se050_pbkdf2.restype = c_int
            self._has_crypto = True
        except AttributeError:
            if debug:
                print("[SE050PY] Crypto functions (sha256/pbkdf2) not available in library")

        # Check for optional storage functions (may not be in older library builds)
        self._has_storage = False
        try:
            # int se050_write_binary(session*, object_id, data, data_len)
            lib.se050_write_binary.argtypes = [POINTER(c_uint8), c_uint32, POINTER(c_uint8), c_size_t]
            lib.se050_write_binary.restype = c_int

            # int se050_read_binary(session*, object_id, data, data_len*)
            lib.se050_read_binary.argtypes = [POINTER(c_uint8), c_uint32, POINTER(c_uint8), POINTER(c_size_t)]
            lib.se050_read_binary.restype = c_int

            # int se050_write_hmac_key(session*, object_id, key, key_len)
            lib.se050_write_hmac_key.argtypes = [POINTER(c_uint8), c_uint32, POINTER(c_uint8), c_size_t]
            lib.se050_write_hmac_key.restype = c_int

            # int se050_pbkdf2_with_key(session*, hmac_key_id, salt, salt_len, iterations, key_len, derived_key)
            lib.se050_pbkdf2_with_key.argtypes = [
                POINTER(c_uint8), c_uint32,
                POINTER(c_uint8), c_size_t,
                c_uint32, c_size_t,
                POINTER(c_uint8)
            ]
            lib.se050_pbkdf2_with_key.restype = c_int
            self._has_storage = True
        except AttributeError:
            if debug:
                print("[SE050PY] Storage functions not available in library")

        # Check for optional functions
        self._has_secure_transceive = False
        self._has_rotate_keys = False

        # int se050_secure_transceive(session*, cla, ins, p1, p2, data, data_len, resp, resp_len*)
        # First check if symbol exists using hasattr (more reliable than try/except)
        if hasattr(lib, 'se050_secure_transceive'):
            try:
                lib.se050_secure_transceive.argtypes = [
                    POINTER(c_uint8),  # session
                    c_uint8, c_uint8, c_uint8, c_uint8,  # CLA, INS, P1, P2
                    POINTER(c_uint8), c_size_t,  # data, data_len
                    POINTER(c_uint8), POINTER(c_size_t)  # response, response_len
                ]
                lib.se050_secure_transceive.restype = c_int
                self._has_secure_transceive = True
                if debug:
                    print("[DEBUG] se050_secure_transceive: AVAILABLE")
            except Exception as e:
                if debug:
                    print(f"[DEBUG] se050_secure_transceive: setup failed ({e})")
        else:
            if debug:
                print("[DEBUG] se050_secure_transceive: NOT FOUND in library")

        # int se050_rotate_platform_keys(session*, new_enc, new_mac, new_dek, new_ver)
        if hasattr(lib, 'se050_rotate_platform_keys'):
            try:
                lib.se050_rotate_platform_keys.argtypes = [
                    POINTER(c_uint8),  # session
                    POINTER(c_uint8),  # new_enc
                    POINTER(c_uint8),  # new_mac
                    POINTER(c_uint8),  # new_dek
                    c_uint8            # new_key_version
                ]
                lib.se050_rotate_platform_keys.restype = c_int
                self._has_rotate_keys = True
                if debug:
                    print("[DEBUG] se050_rotate_platform_keys: AVAILABLE")
            except Exception as e:
                if debug:
                    print(f"[DEBUG] se050_rotate_platform_keys: setup failed ({e})")
        else:
            if debug:
                print("[DEBUG] se050_rotate_platform_keys: NOT FOUND in library")

    def _check_error(self, ret: int, operation: str = "operation"):
        """Check return code and raise exception if error"""
        if ret < 0:
            raise SE050Error(ret, f"{operation} failed")

    def __enter__(self):
        """Context manager enter - open session"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close session"""
        self.disconnect()
        return False

    def _acquire_lock(self):
        """Acquire exclusive file lock for SE050 access"""
        if not _HAS_FCNTL:
            return  # No locking on Windows

        # First check for stale locks
        _check_stale_lock()

        start_time = time.time()
        while True:
            try:
                # Open/create lock file
                self._lock_fd = open(_SE050_LOCK_FILE, 'w')
                # Try to acquire exclusive lock (non-blocking)
                fcntl.flock(self._lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                # Write PID and timestamp for debugging/stale detection
                self._lock_fd.write(f"{os.getpid()} {time.time()}\n")
                self._lock_fd.flush()
                if self._debug:
                    print(f"  [SE050PY] Acquired lock (PID {os.getpid()})")
                return
            except (IOError, OSError) as e:
                # Lock held by another process
                if self._lock_fd:
                    self._lock_fd.close()
                    self._lock_fd = None

                elapsed = time.time() - start_time

                # Periodically check for stale lock
                if int(elapsed) % 5 == 0 and int(elapsed) > 0:
                    if _check_stale_lock():
                        continue  # Try again immediately after cleaning stale lock

                if elapsed >= _SE050_LOCK_TIMEOUT:
                    # One final stale check before giving up
                    if _check_stale_lock():
                        continue

                    raise SE050Error(SE050_ERR_TIMEOUT,
                        f"Timeout waiting for SE050 lock (another process has it). "
                        f"Check if desktop app or another web request is using the device.")

                if self._debug:
                    print(f"  [SE050PY] Waiting for lock... ({elapsed:.1f}s)")
                time.sleep(0.5)

    def _release_lock(self):
        """Release file lock"""
        if self._lock_fd is not None:
            try:
                if _HAS_FCNTL:
                    fcntl.flock(self._lock_fd.fileno(), fcntl.LOCK_UN)
                self._lock_fd.close()
                if self._debug:
                    print(f"  [SE050PY] Released lock")
            except:
                pass
            self._lock_fd = None

    def connect(self):
        """Open authenticated session with SE050"""
        if self._connected:
            return

        if self._enc_key is None or self._mac_key is None:
            raise SE050Error(SE050_ERR_PARAM, "SCP03 keys not provided")

        if len(self._enc_key) != 16 or len(self._mac_key) != 16:
            raise SE050Error(SE050_ERR_PARAM, "SCP03 keys must be 16 bytes")

        if self._dek_key is not None and len(self._dek_key) != 16:
            raise SE050Error(SE050_ERR_PARAM, "DEK key must be 16 bytes")

        # Acquire exclusive lock before accessing SE050
        self._acquire_lock()

        try:
            # Set debug mode
            if self._debug:
                print(f"  [SE050PY] Setting C debug mode: {1 if self._debug else 0}", flush=True)
            self._lib.se050_set_debug(1 if self._debug else 0)

            # Allocate session buffer
            self._session = (c_uint8 * self._SESSION_SIZE)()

            # Auto-detect device if not specified
            device = self._device
            if device is None:
                devices = glob_module.glob('/dev/ttyACM*') + glob_module.glob('/dev/ttyUSB*')
                if not devices:
                    raise SE050Error(SE050_ERR_OPEN, "No serial device found")
                device = devices[0]

            # Convert keys to ctypes
            enc_key = (c_uint8 * 16)(*self._enc_key)
            mac_key = (c_uint8 * 16)(*self._mac_key)

            # Open session (with or without DEK, and optionally for ISD mode)
            if self._dek_key is not None:
                dek_key = (c_uint8 * 16)(*self._dek_key)

                if self._isd_mode:
                    # ISD mode for key rotation - no applet selection
                    if not self._has_open_isd:
                        raise SE050Error(SE050_ERR_PARAM,
                            "Library doesn't support se050_open_session_isd. "
                            "Rebuild with latest source for key rotation support.")
                    ret = self._lib.se050_open_session_isd(
                        self._session,
                        device.encode('utf-8'),
                        enc_key,
                        mac_key,
                        dek_key,
                        self._key_version
                    )
                else:
                    # Normal DEK mode with applet selection
                    if not self._has_open_with_dek:
                        raise SE050Error(SE050_ERR_PARAM,
                            "Library doesn't support se050_open_session_with_dek. "
                            "Rebuild with latest source for key rotation support.")
                    ret = self._lib.se050_open_session_with_dek(
                        self._session,
                        device.encode('utf-8'),
                        enc_key,
                        mac_key,
                        dek_key,
                        self._key_version
                    )
            else:
                ret = self._lib.se050_open_session(
                    self._session,
                    device.encode('utf-8'),
                    enc_key,
                    mac_key,
                    self._key_version
                )
            self._check_error(ret, "Open session")
            self._connected = True

        except Exception:
            # Release lock on connection failure
            self._release_lock()
            raise

    def disconnect(self):
        """Close session and clean up"""
        if self._session is not None and self._connected:
            self._lib.se050_close_session(self._session)
        self._session = None
        self._connected = False
        # Release the file lock
        self._release_lock()

    def get_random(self, length: int) -> bytes:
        """Get random bytes from SE050 hardware RNG"""
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")

        buf = (c_uint8 * length)()
        ret = self._lib.se050_get_random(self._session, buf, length)
        self._check_error(ret, "Get random")
        return bytes(buf)

    def generate_keypair(self, key_id: int, curve_id: int = SE050_CURVE_SECP256K1):
        """Generate ECC keypair on SE050 (key never leaves chip)"""
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")

        ret = self._lib.se050_generate_keypair(self._session, key_id, curve_id)
        self._check_error(ret, "Generate keypair")

    def write_keypair(self, key_id: int, curve_id: int, private_key: bytes, public_key: bytes):
        """Import ECC keypair to SE050 (for BIP32 derived keys)"""
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")

        if len(private_key) != 32:
            raise SE050Error(SE050_ERR_PARAM, "Private key must be 32 bytes")

        if len(public_key) != 65:
            raise SE050Error(SE050_ERR_PARAM, "Public key must be 65 bytes (uncompressed)")

        priv = (c_uint8 * 32)(*private_key)
        pub = (c_uint8 * 65)(*public_key)
        ret = self._lib.se050_write_keypair(self._session, key_id, curve_id, priv, 32, pub, 65)
        self._check_error(ret, "Write keypair")

    def read_pubkey(self, key_id: int) -> bytes:
        """Read public key from SE050 (uncompressed, 65 bytes)"""
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")

        buf = (c_uint8 * 128)()
        buf_len = c_size_t(128)

        ret = self._lib.se050_read_pubkey(self._session, key_id, buf, byref(buf_len))
        self._check_error(ret, "Read public key")

        return bytes(buf[:buf_len.value])

    def read_state(self) -> dict:
        """
        Read SE050 device state (works even when locked/SCP required).

        Returns dict with:
            lock_state: 0=UNLOCKED, 1=TRANSIENT_LOCK, 2=PERSISTENT_LOCK
            restrict_mode: 0=NORMAL, 1=RESTRICTED
            platform_scp: 0=NOT_REQUIRED, 1=SCP_REQUIRED
        """
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")

        buf = (c_uint8 * 8)()
        buf_len = c_size_t(8)

        ret = self._lib.se050_read_state(self._session, buf, byref(buf_len))
        self._check_error(ret, "Read State")

        state = {
            "lock_state": buf[0] if buf_len.value > 0 else 0,
            "restrict_mode": buf[1] if buf_len.value > 1 else 0,
            "platform_scp": buf[2] if buf_len.value > 2 else 0,
            "lock_state_str": ["UNLOCKED", "TRANSIENT_LOCK", "PERSISTENT_LOCK"][buf[0]] if buf_len.value > 0 and buf[0] < 3 else "UNKNOWN",
            "restrict_mode_str": ["NORMAL", "RESTRICTED"][buf[1]] if buf_len.value > 1 and buf[1] < 2 else "UNKNOWN",
            "platform_scp_str": ["NOT_REQUIRED", "SCP_REQUIRED"][buf[2]] if buf_len.value > 2 and buf[2] < 2 else "UNKNOWN",
        }
        return state

    def delete_object(self, object_id: int):
        """Delete object from SE050"""
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")

        ret = self._lib.se050_delete_object(self._session, object_id)
        self._check_error(ret, "Delete object")

    def object_exists(self, object_id: int) -> bool:
        """Check if object exists in SE050"""
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")

        ret = self._lib.se050_object_exists(self._session, object_id)
        if ret < 0:
            self._check_error(ret, "Check object exists")
        return ret == 1

    def sign(self, key_id: int, hash_data: bytes) -> bytes:
        """
        Sign 32-byte hash using key on SE050.
        Returns DER-encoded ECDSA signature.

        Note: You should apply low-S normalization in Python after signing
        for Bitcoin compatibility.
        """
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")

        if len(hash_data) != 32:
            raise SE050Error(SE050_ERR_PARAM, "Hash must be 32 bytes")

        hash_buf = (c_uint8 * 32)(*hash_data)
        sig_buf = (c_uint8 * 128)()
        sig_len = c_size_t(128)

        ret = self._lib.se050_sign(
            self._session, key_id,
            hash_buf, 32,
            sig_buf, byref(sig_len)
        )
        self._check_error(ret, "Sign")

        return bytes(sig_buf[:sig_len.value])

    def verify(self, key_id: int, hash_data: bytes, signature: bytes) -> bool:
        """
        Verify ECDSA signature using key on SE050.
        Verification happens entirely on the secure element.

        Args:
            key_id: Key ID to verify with
            hash_data: 32-byte hash that was signed
            signature: DER-encoded ECDSA signature

        Returns:
            True if signature is valid, False otherwise

        Raises:
            SE050Error: If verification operation fails (not just invalid sig)
        """
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")

        if not self._has_verify:
            raise SE050Error(SE050_ERR_PARAM, "Verify not available - rebuild library")

        if len(hash_data) != 32:
            raise SE050Error(SE050_ERR_PARAM, "Hash must be 32 bytes")

        if len(signature) == 0 or len(signature) > 80:
            raise SE050Error(SE050_ERR_PARAM, "Invalid signature length")

        hash_buf = (c_uint8 * 32)(*hash_data)
        sig_buf = (c_uint8 * len(signature))(*signature)

        ret = self._lib.se050_verify(
            self._session, key_id,
            hash_buf, 32,
            sig_buf, len(signature)
        )

        if ret == 1:
            return True  # Valid
        elif ret == 0:
            return False  # Invalid
        else:
            self._check_error(ret, "Verify")
            return False  # Should not reach here

    def get_uid(self) -> bytes:
        """Get SE050 unique identifier"""
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")

        buf = (c_uint8 * 32)()
        buf_len = c_size_t(32)

        ret = self._lib.se050_get_uid(self._session, buf, byref(buf_len))
        self._check_error(ret, "Get UID")

        return bytes(buf[:buf_len.value])

    def sha256(self, data: bytes) -> bytes:
        """
        Compute SHA-256 hash on SE050 (data never leaves chip during hashing).
        Useful for BIP39 checksum and transaction hashes.

        Args:
            data: Input data to hash (max ~800 bytes)

        Returns:
            32-byte SHA-256 hash
        """
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")
        if not self._has_crypto:
            raise SE050Error(SE050_ERR_PARAM, "Crypto functions not available (rebuild library)")

        if len(data) > 800:
            raise SE050Error(SE050_ERR_PARAM, "Data too large for single hash (max 800 bytes)")

        data_buf = (c_uint8 * len(data))(*data)
        hash_buf = (c_uint8 * 32)()

        ret = self._lib.se050_sha256(self._session, data_buf, len(data), hash_buf)
        self._check_error(ret, "SHA256")

        return bytes(hash_buf)

    def pbkdf2(self, password: bytes, salt: bytes, iterations: int, key_len: int = 32) -> bytes:
        """
        Compute PBKDF2-HMAC-SHA256 on SE050 for key derivation.
        The computation happens entirely on the secure element.

        Note: SE050 uses HMAC-SHA256. For BIP39 (HMAC-SHA512), use pbkdf2_sha512()
        which calls this twice with different salts and concatenates.

        Args:
            password: Password/mnemonic bytes
            salt: Salt bytes
            iterations: Number of iterations (2048 for BIP39)
            key_len: Desired output length (max 32 bytes for single call)

        Returns:
            Derived key bytes
        """
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")
        if not self._has_crypto:
            raise SE050Error(SE050_ERR_PARAM, "Crypto functions not available (rebuild library)")

        if len(password) > 256 or len(salt) > 256:
            raise SE050Error(SE050_ERR_PARAM, "Password or salt too large (max 256 bytes)")

        if key_len > 32:
            raise SE050Error(SE050_ERR_PARAM, "Key length too large for single PBKDF2 call (max 32)")

        if iterations > 65535:
            raise SE050Error(SE050_ERR_PARAM, "Iterations too large (max 65535)")

        pwd_buf = (c_uint8 * len(password))(*password)
        salt_buf = (c_uint8 * len(salt))(*salt)
        key_buf = (c_uint8 * key_len)()

        ret = self._lib.se050_pbkdf2(
            self._session,
            pwd_buf, len(password),
            salt_buf, len(salt),
            iterations, key_len,
            key_buf
        )
        self._check_error(ret, "PBKDF2")

        return bytes(key_buf)

    def pbkdf2_sha512(self, password: bytes, salt: bytes, iterations: int, key_len: int = 64) -> bytes:
        """
        Emulate PBKDF2-HMAC-SHA512 using SE050's HMAC-SHA256.
        This derives two 32-byte keys and concatenates them.

        For BIP39 mnemonic-to-seed, use:
            seed = se050.pbkdf2_sha512(mnemonic.encode(), b"mnemonic" + passphrase.encode(), 2048, 64)

        Note: This is an approximation. For true SHA512-based PBKDF2, the internal
        PRF differs. This provides similar security but NOT bit-compatible output
        with standard BIP39. Use for experimental/custom wallets only.

        Args:
            password: Password/mnemonic bytes
            salt: Salt bytes (e.g., b"mnemonic" + passphrase for BIP39)
            iterations: Number of iterations (2048 for BIP39)
            key_len: Desired output length (max 64 bytes)

        Returns:
            Derived key bytes
        """
        if key_len > 64:
            raise SE050Error(SE050_ERR_PARAM, "Key length too large (max 64)")

        # Derive in two parts with different salt suffixes
        part1 = self.pbkdf2(password, salt + b'\x00\x00\x00\x01', iterations, min(32, key_len))

        if key_len <= 32:
            return part1

        part2 = self.pbkdf2(password, salt + b'\x00\x00\x00\x02', iterations, key_len - 32)
        return part1 + part2

    def write_binary(self, object_id: int, data: bytes):
        """
        Write binary data to SE050 secure storage.
        Data is encrypted at rest.

        Args:
            object_id: Unique ID (e.g., 0x30000001)
            data: Data to store (max ~800 bytes)
        """
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")
        if not self._has_storage:
            raise SE050Error(SE050_ERR_PARAM, "Storage functions not available (rebuild library)")

        if len(data) > 800:
            raise SE050Error(SE050_ERR_PARAM, "Data too large (max 800 bytes)")

        data_buf = (c_uint8 * len(data))(*data)
        ret = self._lib.se050_write_binary(self._session, object_id, data_buf, len(data))
        self._check_error(ret, "Write binary")

    def read_binary(self, object_id: int, max_len: int = 800) -> bytes:
        """
        Read binary data from SE050 secure storage.

        Args:
            object_id: ID of stored data
            max_len: Maximum expected data length

        Returns:
            Stored data bytes
        """
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")
        if not self._has_storage:
            raise SE050Error(SE050_ERR_PARAM, "Storage functions not available (rebuild library)")

        data_buf = (c_uint8 * max_len)()
        data_len = c_size_t(max_len)

        ret = self._lib.se050_read_binary(self._session, object_id, data_buf, byref(data_len))
        self._check_error(ret, "Read binary")

        return bytes(data_buf[:data_len.value])

    def write_hmac_key(self, object_id: int, key: bytes):
        """
        Write HMAC key to SE050 for use with PBKDF2.
        Store mnemonic entropy as HMAC key for maximum security.

        Args:
            object_id: Unique ID (e.g., 0x40000001)
            key: Key material (e.g., BIP39 entropy, 16-32 bytes)
        """
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")
        if not self._has_storage:
            raise SE050Error(SE050_ERR_PARAM, "Storage functions not available (rebuild library)")

        if len(key) > 256:
            raise SE050Error(SE050_ERR_PARAM, "Key too large (max 256 bytes)")

        key_buf = (c_uint8 * len(key))(*key)
        ret = self._lib.se050_write_hmac_key(self._session, object_id, key_buf, len(key))
        self._check_error(ret, "Write HMAC key")

    def pbkdf2_with_key(self, hmac_key_id: int, salt: bytes, iterations: int, key_len: int = 32) -> bytes:
        """
        PBKDF2 using stored HMAC key (entropy never leaves SE050).
        This is the most secure way - the key material is never exposed.

        Args:
            hmac_key_id: Object ID of stored HMAC key
            salt: Salt bytes
            iterations: Iteration count (2048 for BIP39)
            key_len: Desired output length (max 32 per call)

        Returns:
            Derived key bytes
        """
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")
        if not self._has_storage:
            raise SE050Error(SE050_ERR_PARAM, "Storage functions not available (rebuild library)")

        if len(salt) > 256:
            raise SE050Error(SE050_ERR_PARAM, "Salt too large (max 256 bytes)")

        if key_len > 32:
            raise SE050Error(SE050_ERR_PARAM, "Key length too large for single call (max 32)")

        salt_buf = (c_uint8 * len(salt))(*salt)
        key_buf = (c_uint8 * key_len)()

        ret = self._lib.se050_pbkdf2_with_key(
            self._session, hmac_key_id,
            salt_buf, len(salt),
            iterations, key_len,
            key_buf
        )
        self._check_error(ret, "PBKDF2 with key")

        return bytes(key_buf)

    def send_apdu(self, cla: int, ins: int, p1: int, p2: int, data: bytes = b'') -> bytes:
        """
        Send a raw APDU through the SCP03 secure channel.

        Args:
            cla: Class byte
            ins: Instruction byte
            p1: Parameter 1
            p2: Parameter 2
            data: Command data (optional)

        Returns:
            Response data including status word (last 2 bytes)

        Raises:
            SE050Error: If library doesn't support secure_transceive
        """
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")

        if not self._has_secure_transceive:
            raise SE050Error(SE050_ERR_PARAM,
                "Library doesn't support se050_secure_transceive. Rebuild with latest source.")

        data_buf = (c_uint8 * len(data))(*data) if data else None
        resp_buf = (c_uint8 * 256)()
        resp_len = c_size_t(256)

        ret = self._lib.se050_secure_transceive(
            self._session,
            cla, ins, p1, p2,
            data_buf, len(data),
            resp_buf, byref(resp_len)
        )
        self._check_error(ret, "Secure transceive")

        return bytes(resp_buf[:resp_len.value])

    def rotate_platform_keys(self, new_enc: bytes, new_mac: bytes, new_dek: bytes,
                             new_key_version: int) -> None:
        """
        Rotate SCP03 platform keys on SE050.

        CRITICAL: This is a one-way operation!
        - If this fails after partial completion, the device may be bricked
        - If you lose the new keys, the device is permanently locked
        - ALWAYS test on development hardware first
        - ALWAYS backup your new keys before calling this

        Args:
            new_enc: New 16-byte encryption key
            new_mac: New 16-byte MAC key
            new_dek: New 16-byte DEK key
            new_key_version: Key version to replace. For in-place replacement
                (recommended), use the current key version. This matches
                NXP's reference implementation behavior.

        Raises:
            SE050Error: If rotation fails or library doesn't support it
        """
        if not self._connected:
            raise SE050Error(SE050_ERR_PARAM, "Not connected")

        if len(new_enc) != 16 or len(new_mac) != 16 or len(new_dek) != 16:
            raise SE050Error(SE050_ERR_PARAM, "All keys must be 16 bytes")

        if not self._has_rotate_keys:
            raise SE050Error(SE050_ERR_PARAM,
                "Library doesn't support se050_rotate_platform_keys. Rebuild with latest source.")

        enc = (c_uint8 * 16)(*new_enc)
        mac = (c_uint8 * 16)(*new_mac)
        dek = (c_uint8 * 16)(*new_dek)

        ret = self._lib.se050_rotate_platform_keys(
            self._session, enc, mac, dek, new_key_version
        )
        self._check_error(ret, "Rotate platform keys")

    @staticmethod
    def compute_kcv(key: bytes) -> bytes:
        """
        Compute Key Check Value for a key.
        KCV = first 3 bytes of AES(key, 0x01 * 16)

        This can be used to verify keys without exposing them.
        """
        if len(key) != 16:
            raise SE050Error(SE050_ERR_PARAM, "Key must be 16 bytes")

        # Try to use the library if loaded, otherwise compute in Python
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            cipher = Cipher(algorithms.AES(key), modes.ECB())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(b'\x01' * 16) + encryptor.finalize()
            return ciphertext[:3]
        except ImportError:
            raise SE050Error(SE050_ERR_PARAM,
                "cryptography package required: pip install cryptography")


def normalize_signature_low_s(signature: bytes) -> bytes:
    """
    Normalize ECDSA signature to low-S form (BIP-62 / BIP-146).
    This should be called on signatures from SE050 for Bitcoin use.

    Args:
        signature: DER-encoded ECDSA signature

    Returns:
        DER-encoded signature with low-S value
    """
    # secp256k1 order
    SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    HALF_ORDER = SECP256K1_ORDER // 2

    # Parse DER signature
    if signature[0] != 0x30:
        raise ValueError("Invalid DER signature")

    idx = 2
    if signature[idx] != 0x02:
        raise ValueError("Invalid DER signature")
    idx += 1
    r_len = signature[idx]
    idx += 1
    r = int.from_bytes(signature[idx:idx + r_len], 'big')
    idx += r_len

    if signature[idx] != 0x02:
        raise ValueError("Invalid DER signature")
    idx += 1
    s_len = signature[idx]
    idx += 1
    s = int.from_bytes(signature[idx:idx + s_len], 'big')

    # Normalize S
    if s > HALF_ORDER:
        s = SECP256K1_ORDER - s

    # Re-encode DER
    def encode_int(val):
        b = val.to_bytes((val.bit_length() + 7) // 8, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
        return b

    r_bytes = encode_int(r)
    s_bytes = encode_int(s)

    content = b'\x02' + bytes([len(r_bytes)]) + r_bytes + b'\x02' + bytes([len(s_bytes)]) + s_bytes
    return b'\x30' + bytes([len(content)]) + content
