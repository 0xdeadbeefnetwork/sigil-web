/*
 * se050_scp03.h - SE050 via VCOM with SCP03 secure channel
 *
 * Minimal standalone library for Bitcoin wallet operations on SE050.
 * Uses VCOM protocol over USB serial (K64F bridge).
 */
#ifndef SE050_SCP03_H
#define SE050_SCP03_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 *                              ERROR CODES
 * ============================================================================ */
#define SE050_OK            0
#define SE050_ERR_PARAM     -1
#define SE050_ERR_OPEN      -2
#define SE050_ERR_I2C       -3
#define SE050_ERR_TIMEOUT   -4
#define SE050_ERR_BUFFER    -5
#define SE050_ERR_SCP03     -6
#define SE050_ERR_VERIFY    -7
#define SE050_ERR_RESPONSE  -8
#define SE050_ERR_NOT_FOUND -9
#define SE050_ERR_CRYPTO    -10

/* ============================================================================
 *                              CONSTANTS
 * ============================================================================ */
#define SE050_MAX_BUF       1024
#define SCP03_MAC_SIZE      8
#define SCP03_KEY_SIZE      16

/* SE050E default key version (OEF A921) */
#define SE050E_KEY_VERSION  0x0B

/* SE05x ECC Curve IDs (from se05x_enums.h) */
#define SE05X_CURVE_SECP256K1   0x10
#define SE05X_CURVE_NIST_P256   0x03

/* SE05x P1 values for key operations */
#define SE05X_P1_KEY_PAIR   0x60
#define SE05X_P1_PRIVATE    0x40
#define SE05X_P1_PUBLIC     0x20
#define SE05X_P1_EC         0x01
#define SE05X_P1_SIGNATURE  0x0C

/* SE05x P1 values for crypto operations */
#define SE05X_P1_DEFAULT    0x00
#define SE05X_P1_HMAC       0x05
#define SE05X_P1_BINARY     0x06

/* SE05x P2 values */
#define SE05X_P2_DEFAULT    0x00
#define SE05X_P2_GENERATE   0x03
#define SE05X_P2_SIGN       0x09
#define SE05X_P2_VERIFY     0x0A
#define SE05X_P2_ONESHOT    0x0E
#define SE05X_P2_PBKDF      0x2E
#define SE05X_P2_RANDOM     0x49

/* Digest modes for SHA operations */
#define SE05X_DIGEST_SHA1       0x01
#define SE05X_DIGEST_SHA256     0x04
#define SE05X_DIGEST_SHA384     0x05
#define SE05X_DIGEST_SHA512     0x06

/* SE05x INS values */
#define SE05X_INS_WRITE     0x01
#define SE05X_INS_READ      0x02
#define SE05X_INS_CRYPTO    0x03
#define SE05X_INS_MGMT      0x04

/* SE05x TLV Tags */
#define SE05X_TAG_1         0x41
#define SE05X_TAG_2         0x42
#define SE05X_TAG_3         0x43
#define SE05X_TAG_4         0x44
#define SE05X_TAG_5         0x45
#define SE05X_TAG_6         0x46
#define SE05X_TAG_POLICY    0x11  /* Policy object */
#define SE05X_TAG_MAX_ATTEMPTS 0x12  /* Max authentication attempts */
#define SE05X_TAG_SIGNATURE 0x43

/* Signature algorithm identifiers */
#define SE05X_ALGO_SHA256       0x11
#define SE05X_ALGO_ECDSA_SHA256 0x21

/* ============================================================================
 *                              STRUCTURES
 * ============================================================================ */

/* Low-level transport context */
typedef struct {
    int i2c_fd;
    uint8_t ifsc;
    int connected;
} se050_ctx_t;

/* SCP03 session context */
typedef struct {
    /* Static keys (from provisioning) */
    uint8_t static_enc[16];
    uint8_t static_mac[16];
    uint8_t static_dek[16];  /* Data Encryption Key - needed for PUT KEY */
    uint8_t key_version;
    int has_dek;             /* Whether DEK was provided */

    /* Session keys (derived during auth) */
    uint8_t session_enc[16];
    uint8_t session_mac[16];
    uint8_t session_rmac[16];

    /* Session state */
    uint8_t host_challenge[8];
    uint8_t card_challenge[8];
    uint8_t mcv[16];         /* MAC chaining value */
    uint8_t counter[16];     /* Command counter for encryption */
    int authenticated;
} scp03_ctx_t;

/* High-level session combining transport + SCP03 */
typedef struct {
    se050_ctx_t transport;
    scp03_ctx_t scp03;
} se050_session_t;

/* ============================================================================
 *                         LOW-LEVEL TRANSPORT API
 * ============================================================================ */

/* Open VCOM connection to SE050 */
int se050_open(se050_ctx_t *ctx, const char *dev);

/* Close connection */
void se050_close(se050_ctx_t *ctx);

/* Reset SE050 via T1oI2C reset */
int se050_reset(se050_ctx_t *ctx);

/* Get ATR (Answer To Reset) */
int se050_get_atr(se050_ctx_t *ctx, uint8_t *atr, size_t *atr_len);

/* Raw APDU transceive (no SCP03) */
int se050_transceive(se050_ctx_t *ctx, const uint8_t *tx, size_t tx_len,
                     uint8_t *rx, size_t *rx_len);

/* ============================================================================
 *                              SCP03 API
 * ============================================================================ */

/* Initialize SCP03 context with static keys */
int scp03_init(scp03_ctx_t *ctx, const uint8_t *enc_key, const uint8_t *mac_key,
               uint8_t key_ver);

/* Initialize SCP03 context with static keys including DEK (for key rotation) */
int scp03_init_with_dek(scp03_ctx_t *ctx, const uint8_t *enc_key,
                        const uint8_t *mac_key, const uint8_t *dek_key,
                        uint8_t key_ver);

/* Perform SCP03 mutual authentication */
int scp03_authenticate(scp03_ctx_t *scp03, se050_ctx_t *transport);

/* Wrap APDU with SCP03 encryption and MAC */
int scp03_wrap_apdu(scp03_ctx_t *ctx, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                    const uint8_t *data, size_t data_len,
                    uint8_t *wrapped, size_t *wrap_len);

/* Unwrap SCP03 response (verify MAC and decrypt) */
int scp03_unwrap_response(scp03_ctx_t *ctx, size_t cmd_data_len,
                          uint8_t *response, size_t *resp_len);

/* ============================================================================
 *                           HIGH-LEVEL SESSION API
 * ============================================================================ */

/* Open authenticated session with SE050 */
int se050_open_session(se050_session_t *session, const char *dev,
                       const uint8_t *enc_key, const uint8_t *mac_key,
                       uint8_t key_ver);

/* Open session with DEK for key rotation operations */
int se050_open_session_with_dek(se050_session_t *session, const char *dev,
                                const uint8_t *enc_key, const uint8_t *mac_key,
                                const uint8_t *dek_key, uint8_t key_ver);

/* Open session directly to ISD (no applet selection) for key rotation.
 * This is required because PUT KEY is a GlobalPlatform ISD command,
 * not an applet command. Using se050_open_session_with_dek() would
 * select the applet first, causing PUT KEY to fail with 6A80. */
int se050_open_session_isd(se050_session_t *session, const char *dev,
                           const uint8_t *enc_key, const uint8_t *mac_key,
                           const uint8_t *dek_key, uint8_t key_ver);

/* Close session */
void se050_close_session(se050_session_t *session);

/* Select SE05x applet */
int se050_select_applet(se050_session_t *session);

/* Secure transceive (with SCP03 wrapping) */
int se050_secure_transceive(se050_session_t *session,
                            uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                            const uint8_t *data, size_t data_len,
                            uint8_t *response, size_t *resp_len);

/* ============================================================================
 *                           SE05x CRYPTO OPERATIONS
 * ============================================================================ */

/* Get random bytes from SE050 hardware RNG */
int se050_get_random(se050_session_t *session, uint8_t *random, size_t len);

/* Generate ECC keypair on SE050 (key never leaves chip) */
int se050_generate_keypair(se050_session_t *session, uint32_t key_id,
                           uint8_t curve_id);

/* Import ECC keypair to SE050 (for BIP32 derived keys) */
int se050_write_keypair(se050_session_t *session, uint32_t key_id,
                        uint8_t curve_id, const uint8_t *private_key,
                        size_t priv_len, const uint8_t *public_key,
                        size_t pub_len);

/* Read public key from SE050 */
int se050_read_pubkey(se050_session_t *session, uint32_t key_id,
                      uint8_t *pubkey, size_t *pubkey_len);

/* Delete key from SE050 */
int se050_delete_object(se050_session_t *session, uint32_t object_id);

/* Check if object exists */
int se050_object_exists(se050_session_t *session, uint32_t object_id);

/* ECDSA sign - data should be 32-byte hash, returns DER signature */
int se050_sign(se050_session_t *session, uint32_t key_id,
               const uint8_t *hash, size_t hash_len,
               uint8_t *signature, size_t *sig_len);

/*
 * ECDSA verify - verify signature against hash using key on SE050.
 * Verification happens entirely on secure element.
 *
 * @param session    Active SE050 session
 * @param key_id     Key ID to verify with
 * @param hash       32-byte hash that was signed
 * @param hash_len   Must be 32
 * @param signature  DER-encoded signature to verify
 * @param sig_len    Length of signature
 * @return           1 if valid, 0 if invalid, negative on error
 */
int se050_verify(se050_session_t *session, uint32_t key_id,
                 const uint8_t *hash, size_t hash_len,
                 const uint8_t *signature, size_t sig_len);

/* Get SE050 UID (unique identifier) */
int se050_get_uid(se050_session_t *session, uint8_t *uid, size_t *uid_len);
int se050_read_state(se050_session_t *session, uint8_t *state, size_t *state_len);

/* ============================================================================
 *                           ON-CHIP HASH & KDF
 * ============================================================================ */

/*
 * Compute SHA-256 hash on SE050 (data never leaves chip during hashing).
 * Useful for BIP39 checksum and transaction hash before signing.
 *
 * @param session   Active SE050 session
 * @param data      Input data to hash
 * @param data_len  Length of input data (max ~1000 bytes per call)
 * @param hash      Output buffer for 32-byte SHA-256 hash
 * @return          SE050_OK on success
 */
int se050_sha256(se050_session_t *session,
                 const uint8_t *data, size_t data_len,
                 uint8_t *hash);

/*
 * Compute PBKDF2-HMAC-SHA256 on SE050 for BIP39 mnemonic-to-seed.
 * The key derivation happens entirely on the secure element.
 *
 * Note: SE050 PBKDF2 uses HMAC-SHA256, but BIP39 spec uses HMAC-SHA512.
 * For full BIP39 compliance, this would need two 32-byte derivations
 * concatenated, or use host-side PBKDF2 with SE050 TRNG entropy.
 *
 * @param session       Active SE050 session
 * @param password      Password/mnemonic bytes
 * @param password_len  Length of password
 * @param salt          Salt bytes ("mnemonic" + passphrase for BIP39)
 * @param salt_len      Length of salt
 * @param iterations    Number of PBKDF2 iterations (2048 for BIP39)
 * @param key_len       Desired output key length (max 64 bytes)
 * @param derived_key   Output buffer for derived key
 * @return              SE050_OK on success
 */
int se050_pbkdf2(se050_session_t *session,
                 const uint8_t *password, size_t password_len,
                 const uint8_t *salt, size_t salt_len,
                 uint32_t iterations, size_t key_len,
                 uint8_t *derived_key);

/* ============================================================================
 *                           SECURE STORAGE
 * ============================================================================ */

/*
 * Write binary data to SE050 secure storage.
 * Data is encrypted at rest and protected by SCP03 in transit.
 *
 * @param session    Active SE050 session
 * @param object_id  Unique ID for storing the data (e.g., 0x30000001)
 * @param data       Data to store
 * @param data_len   Length of data (max ~1000 bytes)
 * @return           SE050_OK on success
 */
int se050_write_binary(se050_session_t *session, uint32_t object_id,
                       const uint8_t *data, size_t data_len);

/*
 * Read binary data from SE050 secure storage.
 *
 * @param session    Active SE050 session
 * @param object_id  ID of stored data
 * @param data       Output buffer
 * @param data_len   In: buffer size, Out: actual data length
 * @return           SE050_OK on success
 */
int se050_read_binary(se050_session_t *session, uint32_t object_id,
                      uint8_t *data, size_t *data_len);

/*
 * Write HMAC key to SE050 (for use with PBKDF2).
 * Store mnemonic entropy as HMAC key, then PBKDF2 uses object ID.
 *
 * @param session    Active SE050 session
 * @param object_id  Unique ID for the key (e.g., 0x40000001)
 * @param key        Key material (e.g., BIP39 entropy)
 * @param key_len    Key length in bytes
 * @return           SE050_OK on success
 */
int se050_write_hmac_key(se050_session_t *session, uint32_t object_id,
                         const uint8_t *key, size_t key_len);

/*
 * PBKDF2 using stored HMAC key (entropy never leaves SE050).
 * This is the most secure way to derive seed from mnemonic entropy.
 *
 * @param session       Active SE050 session
 * @param hmac_key_id   Object ID of stored HMAC key
 * @param salt          Salt bytes
 * @param salt_len      Salt length
 * @param iterations    Iteration count (2048 for BIP39)
 * @param key_len       Desired output length
 * @param derived_key   Output buffer
 * @return              SE050_OK on success
 */
int se050_pbkdf2_with_key(se050_session_t *session, uint32_t hmac_key_id,
                          const uint8_t *salt, size_t salt_len,
                          uint32_t iterations, size_t key_len,
                          uint8_t *derived_key);

/* ============================================================================
 *                           SCP03 KEY ROTATION
 * ============================================================================ */

/*
 * Rotate SCP03 platform keys using GlobalPlatform PUT KEY command.
 *
 * CRITICAL: This is a one-way operation. If it fails after partially
 * completing, or if you lose the new keys, the device is PERMANENTLY LOCKED.
 *
 * Requirements:
 * - Session must be opened with se050_open_session_with_dek()
 * - New keys must be 16 bytes each (AES-128)
 * - new_key_version should be current_version + 1
 *
 * Returns SE050_OK on success, error code on failure.
 */
int se050_rotate_platform_keys(se050_session_t *session,
                               const uint8_t *new_enc, const uint8_t *new_mac,
                               const uint8_t *new_dek, uint8_t new_key_version);

/* Compute Key Check Value for verification (first 3 bytes of AES(key, 0x0101...)) */
int se050_compute_kcv(const uint8_t *key, uint8_t *kcv);

/* ============================================================================
 *                              DEBUG / UTILITY
 * ============================================================================ */

/* Enable/disable debug output */
void se050_set_debug(int enable);

/* Hex dump for debugging */
void se050_hex_dump(const char *label, const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SE050_SCP03_H */

/* ReadState P1 */
#define SE05X_P1_READ_STATE  0x07
