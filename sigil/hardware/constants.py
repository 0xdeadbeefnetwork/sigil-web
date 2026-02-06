"""
Hardware constants for SE050 secure element.

Error codes, curve identifiers, and key version constants
matching the native C library (se050_scp03.h).
"""

# Error codes (must match se050_scp03.h)
SE050_OK = 0
SE050_ERR_PARAM = -1
SE050_ERR_OPEN = -2
SE050_ERR_I2C = -3
SE050_ERR_TIMEOUT = -4
SE050_ERR_BUFFER = -5
SE050_ERR_SCP03 = -6
SE050_ERR_VERIFY = -7
SE050_ERR_RESPONSE = -8
SE050_ERR_NOT_FOUND = -9
SE050_ERR_CRYPTO = -10

# Curve IDs
SE050_CURVE_SECP256K1 = 0x10
SE050_CURVE_NIST_P256 = 0x03

# SE050E default key version
SE050E_KEY_VERSION = 0x0B

# NXP OM-SE050ARD-E factory default SCP03 keys (PUBLIC — rotate immediately!)
# These are the well-known keys shipped on every dev board. Anyone with these
# keys can MITM the SE050 communication channel. Rotate on first use.
FACTORY_ENC = bytes.fromhex("D2DB63E7A0A5AED72A6460C4DFDCAF64")
FACTORY_MAC = bytes.fromhex("738D5B798ED241B0B24768514BFBA95B")
FACTORY_DEK = bytes.fromhex("6702DAC30942B2C85E7F47B42CED4E7F")

# Error messages
_ERROR_MESSAGES = {
    SE050_OK: "Success",
    SE050_ERR_PARAM: "Invalid parameter",
    SE050_ERR_OPEN: "Failed to open device",
    SE050_ERR_I2C: "I2C/communication error",
    SE050_ERR_TIMEOUT: "Timeout",
    SE050_ERR_BUFFER: "Buffer too small",
    SE050_ERR_SCP03: "SCP03 error",
    SE050_ERR_VERIFY: "Verification failed",
    SE050_ERR_RESPONSE: "Invalid response",
    SE050_ERR_NOT_FOUND: "Object not found",
    SE050_ERR_CRYPTO: "Crypto error",
}
