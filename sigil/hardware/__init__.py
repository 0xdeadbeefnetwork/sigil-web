"""
sigil.hardware - SE050 secure element hardware abstraction layer.

This package provides a complete interface to the NXP SE050 secure element
for cryptographic operations, key management, and secure storage.
"""

# Constants
from sigil.hardware.constants import (
    SE050_OK,
    SE050_ERR_PARAM,
    SE050_ERR_OPEN,
    SE050_ERR_I2C,
    SE050_ERR_TIMEOUT,
    SE050_ERR_BUFFER,
    SE050_ERR_SCP03,
    SE050_ERR_VERIFY,
    SE050_ERR_RESPONSE,
    SE050_ERR_NOT_FOUND,
    SE050_ERR_CRYPTO,
    SE050_CURVE_SECP256K1,
    SE050_CURVE_NIST_P256,
    SE050E_KEY_VERSION,
    _ERROR_MESSAGES,
)

# Errors
from sigil.hardware.errors import SE050Error

# Locking
from sigil.hardware.locking import (
    _HAS_FCNTL,
    _SE050_LOCK_FILE,
    _SE050_LOCK_TIMEOUT,
    _SE050_LOCK_STALE_TIMEOUT,
    _check_stale_lock,
)

# Session
from sigil.hardware.session import SE050Session, normalize_signature_low_s

# SCP03 key loading
from sigil.hardware.scp03 import _load_scp03_keys

# High-level interface
from sigil.hardware.interface import (
    se050_check_connection,
    se050_connect,
    se050_disconnect,
    se050_reconnect,
    se050_get_uid,
    se050_read_state,
    se050_get_random,
    se050_sha256,
    se050_pbkdf2,
    se050_pbkdf2_sha512,
    se050_verify,
    se050_write_binary,
    se050_read_binary,
    se050_write_hmac_key,
    se050_pbkdf2_with_key,
    se050_delete_object,
    se050_generate_keypair,
    se050_set_ecc_keypair,
    se050_export_pubkey,
    se050_delete_key,
    se050_sign,
    se050_key_exists,
    _derive_pubkey_uncompressed,
    _build_pubkey_der,
)

__all__ = [
    # Constants
    "SE050_OK",
    "SE050_ERR_PARAM",
    "SE050_ERR_OPEN",
    "SE050_ERR_I2C",
    "SE050_ERR_TIMEOUT",
    "SE050_ERR_BUFFER",
    "SE050_ERR_SCP03",
    "SE050_ERR_VERIFY",
    "SE050_ERR_RESPONSE",
    "SE050_ERR_NOT_FOUND",
    "SE050_ERR_CRYPTO",
    "SE050_CURVE_SECP256K1",
    "SE050_CURVE_NIST_P256",
    "SE050E_KEY_VERSION",
    "_ERROR_MESSAGES",
    # Errors
    "SE050Error",
    # Locking
    "_HAS_FCNTL",
    "_SE050_LOCK_FILE",
    "_SE050_LOCK_TIMEOUT",
    "_SE050_LOCK_STALE_TIMEOUT",
    "_check_stale_lock",
    # Session
    "SE050Session",
    "normalize_signature_low_s",
    # SCP03
    "_load_scp03_keys",
    # Interface
    "se050_check_connection",
    "se050_connect",
    "se050_disconnect",
    "se050_reconnect",
    "se050_get_uid",
    "se050_read_state",
    "se050_get_random",
    "se050_sha256",
    "se050_pbkdf2",
    "se050_pbkdf2_sha512",
    "se050_verify",
    "se050_write_binary",
    "se050_read_binary",
    "se050_write_hmac_key",
    "se050_pbkdf2_with_key",
    "se050_delete_object",
    "se050_generate_keypair",
    "se050_set_ecc_keypair",
    "se050_export_pubkey",
    "se050_delete_key",
    "se050_sign",
    "se050_key_exists",
    "_derive_pubkey_uncompressed",
    "_build_pubkey_der",
]
