/*
 * se050_vcom.c - SE050 via VCOM (USB Serial) + SCP03
 * FIXED: Correct derivation data format per GP SCP03 spec
 */
#include "se050_scp03.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/cipher.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

/* VCOM Protocol Message Types */
#define MTY_WAIT_FOR_CARD   0x00
#define MTY_APDU_DATA       0x01
#define MTY_T1OI2C_RESET    0x60
#define VCOM_HEADER_LEN     4

static int g_debug = 0;
void se050_set_debug(int enable) { g_debug = enable; }

/* Constant-time comparison to prevent timing attacks */
static int secure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

/* Secure memory zeroing that won't be optimized away */
static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

void se050_hex_dump(const char *label, const uint8_t *data, size_t len) {
    if (!g_debug) return;
    printf("%s (%zu): ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
}
#define DBG(fmt, ...) do { if (g_debug) { printf("[SE050] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } } while(0)

/* Configure serial port for VCOM */
static int configure_serial(int fd) {
    struct termios tty;
    memset(&tty, 0, sizeof(tty));
    if (tcgetattr(fd, &tty) != 0) return -1;
    cfsetispeed(&tty, B115200);
    cfsetospeed(&tty, B115200);
    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CRTSCTS;
    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~(IXON | IXOFF | IXANY | IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);
    tty.c_oflag &= ~OPOST;
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 50;
    if (tcsetattr(fd, TCSANOW, &tty) != 0) return -1;
    tcflush(fd, TCIOFLUSH);
    return 0;
}

static int read_exact(int fd, uint8_t *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, buf + total, n - total);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        total += r;
    }
    return 0;
}

static int vcom_transceive(int fd, uint8_t mty, const uint8_t *tx, size_t tx_len,
                           uint8_t *rx, size_t *rx_len) {
    uint8_t header[VCOM_HEADER_LEN];
    header[0] = mty; header[1] = 0x00;
    header[2] = (tx_len >> 8) & 0xFF; header[3] = tx_len & 0xFF;
    se050_hex_dump("VCOM TX HDR", header, 4);
    if (tx_len > 0) se050_hex_dump("VCOM TX DATA", tx, tx_len);
    if (write(fd, header, 4) != 4) return SE050_ERR_I2C;
    if (tx_len > 0 && write(fd, tx, tx_len) != (ssize_t)tx_len) return SE050_ERR_I2C;
    if (read_exact(fd, header, 4) < 0) return SE050_ERR_TIMEOUT;
    se050_hex_dump("VCOM RX HDR", header, 4);
    size_t resp_len = (header[2] << 8) | header[3];
    if (resp_len > *rx_len) return SE050_ERR_BUFFER;
    if (resp_len > 0) {
        if (read_exact(fd, rx, resp_len) < 0) return SE050_ERR_TIMEOUT;
        se050_hex_dump("VCOM RX DATA", rx, resp_len);
    }
    *rx_len = resp_len;
    return SE050_OK;
}

int se050_open(se050_ctx_t *ctx, const char *dev) {
    if (!ctx) return SE050_ERR_PARAM;
    memset(ctx, 0, sizeof(se050_ctx_t));
    if (!dev) dev = "/dev/ttyACM0";
    ctx->i2c_fd = open(dev, O_RDWR | O_NOCTTY);
    if (ctx->i2c_fd < 0) { DBG("Failed to open %s", dev); return SE050_ERR_OPEN; }
    if (configure_serial(ctx->i2c_fd) < 0) { close(ctx->i2c_fd); return SE050_ERR_I2C; }
    ctx->ifsc = 254; ctx->connected = 1;
    DBG("Opened %s, fd=%d", dev, ctx->i2c_fd);
    return SE050_OK;
}

void se050_close(se050_ctx_t *ctx) {
    if (ctx && ctx->i2c_fd >= 0) { close(ctx->i2c_fd); ctx->i2c_fd = -1; }
}

int se050_reset(se050_ctx_t *ctx) {
    uint8_t rsp[64]; size_t rsp_len = sizeof(rsp);
    return vcom_transceive(ctx->i2c_fd, MTY_T1OI2C_RESET, NULL, 0, rsp, &rsp_len);
}

int se050_get_atr(se050_ctx_t *ctx, uint8_t *atr, size_t *atr_len) {
    uint8_t cmd[4] = {0, 0, 1, 0};
    return vcom_transceive(ctx->i2c_fd, MTY_WAIT_FOR_CARD, cmd, 4, atr, atr_len);
}

int se050_transceive(se050_ctx_t *ctx, const uint8_t *tx, size_t tx_len, uint8_t *rx, size_t *rx_len) {
    return vcom_transceive(ctx->i2c_fd, MTY_APDU_DATA, tx, tx_len, rx, rx_len);
}

/* ============ SCP03 with CORRECTED derivation ============ */

static int get_random(uint8_t *buf, size_t len) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret == 0) ret = mbedtls_ctr_drbg_random(&ctr_drbg, buf, len);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return (ret == 0) ? SE050_OK : SE050_ERR_SCP03;
}

static int aes_cmac(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *mac) {
    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);
    const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    int ret = mbedtls_cipher_setup(&ctx, info);
    if (ret == 0) ret = mbedtls_cipher_cmac_starts(&ctx, key, 128);
    if (ret == 0) ret = mbedtls_cipher_cmac_update(&ctx, data, data_len);
    if (ret == 0) ret = mbedtls_cipher_cmac_finish(&ctx, mac);
    mbedtls_cipher_free(&ctx);
    return (ret == 0) ? SE050_OK : SE050_ERR_SCP03;
}

static int aes_cbc_encrypt(const uint8_t *key, uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int ret = mbedtls_aes_setkey_enc(&ctx, key, 128);
    if (ret == 0) ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, iv, in, out);
    mbedtls_aes_free(&ctx);
    return (ret == 0) ? SE050_OK : SE050_ERR_SCP03;
}

static int aes_cbc_decrypt(const uint8_t *key, uint8_t *iv, const uint8_t *in, uint8_t *out, size_t len) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int ret = mbedtls_aes_setkey_dec(&ctx, key, 128);
    if (ret == 0) ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv, in, out);
    mbedtls_aes_free(&ctx);
    return (ret == 0) ? SE050_OK : SE050_ERR_SCP03;
}

/*
 * SCP03 Derivation Data format (32 bytes):
 * [0-10]  : Label (11 zeros)
 * [11]    : Derivation constant (0x00=card crypto, 0x01=host crypto, 0x04=SENC, 0x06=SMAC, 0x07=SRMAC)
 * [12]    : Separator (0x00)
 * [13-14] : L (output length in bits, big endian: 0x0040=64, 0x0080=128)
 * [15]    : i (KDF counter, always 0x01 for single block)
 * [16-23] : Host challenge
 * [24-31] : Card challenge
 */
static void build_derivation_data(uint8_t *dd, uint8_t constant, uint16_t L_bits,
                                   const uint8_t *host_challenge, const uint8_t *card_challenge) {
    memset(dd, 0, 32);
    /* Label: bytes 0-10 are zero */
    dd[11] = constant;           /* Derivation constant */
    dd[12] = 0x00;               /* Separator */
    dd[13] = (L_bits >> 8) & 0xFF;  /* L MSB */
    dd[14] = L_bits & 0xFF;         /* L LSB */
    dd[15] = 0x01;               /* i = 1 (KDF counter) */
    memcpy(&dd[16], host_challenge, 8);
    memcpy(&dd[24], card_challenge, 8);
}

#define DD_CARD_CRYPTOGRAM  0x00
#define DD_HOST_CRYPTOGRAM  0x01
#define DD_SENC             0x04
#define DD_SMAC             0x06
#define DD_SRMAC            0x07
#define L_64BIT             0x0040
#define L_128BIT            0x0080

/* Derive a session key (128-bit output) */
static int derive_session_key(const uint8_t *static_key, uint8_t constant,
                               const uint8_t *hc, const uint8_t *cc, uint8_t *out_key) {
    uint8_t dd[32], mac[16];
    build_derivation_data(dd, constant, L_128BIT, hc, cc);
    se050_hex_dump("DD for key", dd, 32);
    int ret = aes_cmac(static_key, dd, 32, mac);
    if (ret == SE050_OK) memcpy(out_key, mac, 16);
    /* Securely clear sensitive intermediate data */
    secure_zero(dd, sizeof(dd));
    secure_zero(mac, sizeof(mac));
    return ret;
}

/* Derive a cryptogram (64-bit output) */
static int derive_cryptogram(const uint8_t *session_mac_key, uint8_t constant,
                              const uint8_t *hc, const uint8_t *cc, uint8_t *out_crypto) {
    uint8_t dd[32], mac[16];
    build_derivation_data(dd, constant, L_64BIT, hc, cc);
    se050_hex_dump("DD for crypto", dd, 32);
    int ret = aes_cmac(session_mac_key, dd, 32, mac);
    if (ret == SE050_OK) memcpy(out_crypto, mac, 8);  /* Only first 8 bytes */
    /* Securely clear sensitive intermediate data */
    secure_zero(dd, sizeof(dd));
    secure_zero(mac, sizeof(mac));
    return ret;
}

int scp03_init(scp03_ctx_t *ctx, const uint8_t *enc_key, const uint8_t *mac_key, uint8_t key_ver) {
    if (!ctx || !enc_key || !mac_key) return SE050_ERR_PARAM;
    memset(ctx, 0, sizeof(scp03_ctx_t));
    memcpy(ctx->static_enc, enc_key, 16);
    memcpy(ctx->static_mac, mac_key, 16);
    ctx->key_version = key_ver;
    ctx->has_dek = 0;
    return SE050_OK;
}

int scp03_init_with_dek(scp03_ctx_t *ctx, const uint8_t *enc_key,
                        const uint8_t *mac_key, const uint8_t *dek_key,
                        uint8_t key_ver) {
    if (!ctx || !enc_key || !mac_key || !dek_key) return SE050_ERR_PARAM;
    memset(ctx, 0, sizeof(scp03_ctx_t));
    memcpy(ctx->static_enc, enc_key, 16);
    memcpy(ctx->static_mac, mac_key, 16);
    memcpy(ctx->static_dek, dek_key, 16);
    ctx->key_version = key_ver;
    ctx->has_dek = 1;
    return SE050_OK;
}

int scp03_authenticate(scp03_ctx_t *scp03, se050_ctx_t *transport) {
    uint8_t cmd[64], resp[64];
    size_t resp_len;
    int ret;
    
    if ((ret = get_random(scp03->host_challenge, 8)) != SE050_OK) return ret;
    se050_hex_dump("Host Challenge", scp03->host_challenge, 8);
    
    /* INITIALIZE UPDATE: 80 50 keyVer 00 08 [host_challenge] 00 */
    cmd[0] = 0x80; cmd[1] = 0x50; cmd[2] = scp03->key_version; cmd[3] = 0x00; cmd[4] = 0x08;
    memcpy(&cmd[5], scp03->host_challenge, 8);
    cmd[13] = 0x00;
    
    DBG("Sending INITIALIZE UPDATE...");
    resp_len = sizeof(resp);
    if ((ret = se050_transceive(transport, cmd, 14, resp, &resp_len)) != SE050_OK) return ret;
    se050_hex_dump("INIT UPDATE RSP", resp, resp_len);
    
    if (resp_len < 31 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("INIT UPDATE failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }
    
    /* Parse response:
     * [0-9]   Key diversification data (10 bytes)
     * [10]    Key version
     * [11]    SCP identifier (0x03)
     * [12]    i (sequence counter, usually 0x00)
     * [13-20] Card challenge (8 bytes)
     * [21-28] Card cryptogram (8 bytes)
     * [29-30] SW (9000)
     */
    memcpy(scp03->card_challenge, &resp[13], 8);
    uint8_t card_cryptogram[8];
    memcpy(card_cryptogram, &resp[21], 8);
    
    se050_hex_dump("Card Challenge", scp03->card_challenge, 8);
    se050_hex_dump("Card Cryptogram (received)", card_cryptogram, 8);
    
    /* Derive session keys using STATIC keys */
    DBG("Deriving session keys...");
    if ((ret = derive_session_key(scp03->static_enc, DD_SENC, 
                                   scp03->host_challenge, scp03->card_challenge, 
                                   scp03->session_enc)) != SE050_OK) return ret;
    if ((ret = derive_session_key(scp03->static_mac, DD_SMAC, 
                                   scp03->host_challenge, scp03->card_challenge, 
                                   scp03->session_mac)) != SE050_OK) return ret;
    if ((ret = derive_session_key(scp03->static_mac, DD_SRMAC, 
                                   scp03->host_challenge, scp03->card_challenge, 
                                   scp03->session_rmac)) != SE050_OK) return ret;
    
    se050_hex_dump("S-ENC", scp03->session_enc, 16);
    se050_hex_dump("S-MAC", scp03->session_mac, 16);
    se050_hex_dump("S-RMAC", scp03->session_rmac, 16);
    
    /* Verify card cryptogram using SESSION MAC key */
    uint8_t computed_card_crypto[8];
    if ((ret = derive_cryptogram(scp03->session_mac, DD_CARD_CRYPTOGRAM,
                                  scp03->host_challenge, scp03->card_challenge,
                                  computed_card_crypto)) != SE050_OK) return ret;
    
    se050_hex_dump("Card Cryptogram (computed)", computed_card_crypto, 8);
    
    if (!secure_compare(card_cryptogram, computed_card_crypto, 8)) {
        DBG("Card cryptogram verification FAILED!");
        return SE050_ERR_VERIFY;
    }
    DBG("Card cryptogram verified OK");
    
    /* Compute host cryptogram using SESSION MAC key */
    uint8_t host_cryptogram[8];
    if ((ret = derive_cryptogram(scp03->session_mac, DD_HOST_CRYPTOGRAM,
                                  scp03->host_challenge, scp03->card_challenge,
                                  host_cryptogram)) != SE050_OK) return ret;
    
    se050_hex_dump("Host Cryptogram", host_cryptogram, 8);
    
    /* EXTERNAL AUTHENTICATE: 84 82 33 00 10 [host_crypto][MAC] */
    memset(scp03->mcv, 0, 16);  /* Initialize MAC chaining value */
    
    /* Calculate MAC over: MCV || CLA INS P1 P2 Lc || host_cryptogram */
    uint8_t mac_input[32], mac[16];
    size_t mac_input_len = 0;
    memcpy(&mac_input[mac_input_len], scp03->mcv, 16); mac_input_len += 16;
    mac_input[mac_input_len++] = 0x84;  /* CLA with secure messaging */
    mac_input[mac_input_len++] = 0x82;  /* INS */
    mac_input[mac_input_len++] = 0x33;  /* P1: C-DECRYPTION, R-ENCRYPTION, C-MAC, R-MAC */
    mac_input[mac_input_len++] = 0x00;  /* P2 */
    mac_input[mac_input_len++] = 0x10;  /* Lc = 16 (8 bytes crypto + 8 bytes MAC) */
    memcpy(&mac_input[mac_input_len], host_cryptogram, 8); mac_input_len += 8;
    
    se050_hex_dump("MAC input", mac_input, mac_input_len);
    
    if ((ret = aes_cmac(scp03->session_mac, mac_input, mac_input_len, mac)) != SE050_OK) return ret;
    memcpy(scp03->mcv, mac, 16);  /* Update MCV */
    
    se050_hex_dump("EXT AUTH MAC", mac, 16);
    
    /* Build EXTERNAL AUTHENTICATE command */
    cmd[0] = 0x84; cmd[1] = 0x82; cmd[2] = 0x33; cmd[3] = 0x00; cmd[4] = 0x10;
    memcpy(&cmd[5], host_cryptogram, 8);
    memcpy(&cmd[13], mac, 8);  /* Only first 8 bytes of MAC */
    
    DBG("Sending EXTERNAL AUTHENTICATE...");
    resp_len = sizeof(resp);
    if ((ret = se050_transceive(transport, cmd, 21, resp, &resp_len)) != SE050_OK) return ret;
    
    se050_hex_dump("EXT AUTH RSP", resp, resp_len);
    
    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("EXTERNAL AUTHENTICATE failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_VERIFY;
    }
    
    /* Initialize command counter for encryption */
    memset(scp03->counter, 0, 16);
    scp03->counter[15] = 0x01;
    scp03->authenticated = 1;

    DBG("SCP03 authentication successful!");
    return SE050_OK;
}

static size_t pad_data(uint8_t *data, size_t len, size_t max_len) {
    /* Ensure we have room for at least 1 byte of padding (0x80) */
    if (len >= max_len) return 0;  /* Error - no room for padding */
    data[len++] = 0x80;
    /* Pad to 16-byte boundary */
    while (len % 16 != 0 && len < max_len) data[len++] = 0x00;
    if (len > max_len) return 0;  /* Error - exceeded max */
    return len;
}

static void inc_counter(uint8_t *counter) {
    for (int i = 15; i > 0; i--) {
        if (counter[i] < 0xFF) { counter[i]++; return; }
        counter[i] = 0;
    }
}

int scp03_wrap_apdu(scp03_ctx_t *ctx, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                    const uint8_t *data, size_t data_len, uint8_t *wrapped, size_t *wrap_len) {
    uint8_t work[SE050_MAX_BUF], encrypted[SE050_MAX_BUF], mac[16];
    size_t enc_len = 0;
    int ret;

    if (!ctx || !ctx->authenticated) return SE050_ERR_PARAM;

    /* Validate data length won't overflow */
    if (data_len > SE050_MAX_BUF - 16) return SE050_ERR_PARAM;  /* Leave room for padding */

    /* Encrypt data if present */
    if (data_len > 0) {
        memcpy(work, data, data_len);
        enc_len = pad_data(work, data_len, SE050_MAX_BUF);
        if (enc_len == 0) return SE050_ERR_PARAM;  /* Padding failed */
        uint8_t iv[16] = {0}, icv[16];
        /* ICV = AES-CBC(S-ENC, zeros, counter) */
        if ((ret = aes_cbc_encrypt(ctx->session_enc, iv, ctx->counter, icv, 16)) != SE050_OK) return ret;
        memcpy(iv, icv, 16);
        if ((ret = aes_cbc_encrypt(ctx->session_enc, iv, work, encrypted, enc_len)) != SE050_OK) return ret;
    }
    
    /* Calculate MAC */
    uint8_t lc = enc_len + SCP03_MAC_SIZE;
    uint8_t mac_buf[SE050_MAX_BUF];
    size_t mac_len = 0;
    memcpy(&mac_buf[mac_len], ctx->mcv, 16); mac_len += 16;
    mac_buf[mac_len++] = cla | 0x04;  /* Set secure messaging bit */
    mac_buf[mac_len++] = ins;
    mac_buf[mac_len++] = p1;
    mac_buf[mac_len++] = p2;
    mac_buf[mac_len++] = lc;
    if (enc_len > 0) {
        memcpy(&mac_buf[mac_len], encrypted, enc_len);
        mac_len += enc_len;
    }
    
    if ((ret = aes_cmac(ctx->session_mac, mac_buf, mac_len, mac)) != SE050_OK) return ret;
    memcpy(ctx->mcv, mac, 16);  /* Update MCV */

    /* Build wrapped APDU */
    size_t pos = 0;
    wrapped[pos++] = cla | 0x04;
    wrapped[pos++] = ins;
    wrapped[pos++] = p1;
    wrapped[pos++] = p2;
    wrapped[pos++] = lc;
    if (enc_len > 0) {
        memcpy(&wrapped[pos], encrypted, enc_len);
        pos += enc_len;
    }
    memcpy(&wrapped[pos], mac, 8);  /* Only first 8 bytes */
    pos += 8;
    wrapped[pos++] = 0x00;  /* Le */
    *wrap_len = pos;

    /* Securely clear sensitive working data */
    secure_zero(work, sizeof(work));
    secure_zero(encrypted, sizeof(encrypted));
    secure_zero(mac, sizeof(mac));
    secure_zero(mac_buf, mac_len);

    return SE050_OK;
}

int scp03_unwrap_response(scp03_ctx_t *ctx, size_t cmd_data_len, uint8_t *response, size_t *resp_len) {
    uint8_t mac[16], comp_mac[16], sw[2];
    size_t len = *resp_len;
    int ret;
    (void)cmd_data_len;

    if (!ctx || !ctx->authenticated) return SE050_ERR_PARAM;

    /* If response is just 2 bytes, it's a raw status word (no SCP03 wrapping).
     * This happens when SE050 rejects the command before processing.
     * Don't increment counter - the SE050 didn't process the secure message. */
    if (len == 2) {
        DBG("Raw SW response (no SCP03): %02X%02X", response[0], response[1]);
        /* Return the status as-is, but signal error so caller knows */
        return SE050_ERR_RESPONSE;
    }

    if (len < 10) return SE050_ERR_PARAM;  /* At least MAC(8) + SW(2) */
    
    /* Extract SW and MAC */
    sw[0] = response[len-2];
    sw[1] = response[len-1];
    memcpy(mac, &response[len-10], 8);
    size_t data_len = len - 10;
    
    /* Verify MAC: CMAC(S-RMAC, MCV || encrypted_data || SW) */
    uint8_t mac_buf[SE050_MAX_BUF];
    size_t mac_buf_len = 0;
    memcpy(&mac_buf[mac_buf_len], ctx->mcv, 16); mac_buf_len += 16;
    if (data_len > 0) {
        memcpy(&mac_buf[mac_buf_len], response, data_len);
        mac_buf_len += data_len;
    }
    memcpy(&mac_buf[mac_buf_len], sw, 2); mac_buf_len += 2;
    
    if ((ret = aes_cmac(ctx->session_rmac, mac_buf, mac_buf_len, comp_mac)) != SE050_OK) return ret;
    
    if (!secure_compare(mac, comp_mac, 8)) {
        DBG("Response MAC verification failed!");
        return SE050_ERR_VERIFY;
    }
    
    /* Decrypt data if present */
    if (data_len > 0) {
        uint8_t counter_block[16], iv[16] = {0}, icv[16], decrypted[SE050_MAX_BUF];
        memcpy(counter_block, ctx->counter, 16);
        counter_block[0] = 0x80;  /* Response indicator */
        
        if ((ret = aes_cbc_encrypt(ctx->session_enc, iv, counter_block, icv, 16)) != SE050_OK) return ret;
        memcpy(iv, icv, 16);
        if ((ret = aes_cbc_decrypt(ctx->session_enc, iv, response, decrypted, data_len)) != SE050_OK) return ret;
        
        /* Remove padding */
        int unpad_len = -1;
        for (int i = data_len - 1; i >= (int)data_len - 16 && i >= 0; i--) {
            if (decrypted[i] == 0x00) continue;
            if (decrypted[i] == 0x80) { unpad_len = i; break; }
            break;
        }
        if (unpad_len < 0) return SE050_ERR_RESPONSE;
        
        memcpy(response, decrypted, unpad_len);
        response[unpad_len] = sw[0];
        response[unpad_len+1] = sw[1];
        *resp_len = unpad_len + 2;
        /* Securely clear decryption buffers */
        secure_zero(decrypted, sizeof(decrypted));
        secure_zero(icv, sizeof(icv));
        secure_zero(counter_block, sizeof(counter_block));
    } else {
        response[0] = sw[0];
        response[1] = sw[1];
        *resp_len = 2;
    }

    inc_counter(ctx->counter);
    return SE050_OK;
}

/* High-level API */
static const uint8_t SE05X_AID[] = {0xA0,0x00,0x00,0x03,0x96,0x54,0x53,0x00,0x00,0x00,0x01,0x03,0x00,0x00,0x00,0x00};

/* SSD (Supplementary Security Domain) AID for key rotation
 * This is the security domain that manages the SCP03 platform keys.
 * Must be selected before PUT KEY command. */
static const uint8_t SE05X_SSD_AID[] = {0xD2,0x76,0x00,0x00,0x85,0x30,0x4A,0x43,0x4F,0x90,0x03};

/*
 * Select the SSD (Supplementary Security Domain) for key rotation.
 * Per NXP reference, this must be done before SCP03 authentication
 * when performing platform key operations like PUT KEY.
 */
static int se050_select_ssd(se050_session_t *session) {
    uint8_t cmd[32], resp[64];
    size_t pos = 0, resp_len = sizeof(resp);

    cmd[pos++] = 0x00;  /* CLA */
    cmd[pos++] = 0xA4;  /* INS = SELECT */
    cmd[pos++] = 0x04;  /* P1 = Select by DF name */
    cmd[pos++] = 0x00;  /* P2 */
    cmd[pos++] = sizeof(SE05X_SSD_AID);  /* Lc */
    memcpy(&cmd[pos], SE05X_SSD_AID, sizeof(SE05X_SSD_AID));
    pos += sizeof(SE05X_SSD_AID);
    cmd[pos++] = 0x00;  /* Le */

    DBG("Selecting SSD for key rotation (AID: D2760000853049434F9003)...");
    int ret = se050_transceive(&session->transport, cmd, pos, resp, &resp_len);
    if (ret != SE050_OK) return ret;

    if (resp_len < 2) {
        DBG("SELECT SSD: no response");
        return SE050_ERR_RESPONSE;
    }

    uint8_t sw1 = resp[resp_len-2], sw2 = resp[resp_len-1];
    if (sw1 != 0x90 || sw2 != 0x00) {
        DBG("SELECT SSD failed: SW=%02X%02X", sw1, sw2);
        return SE050_ERR_RESPONSE;
    }

    DBG("SSD selected OK");
    se050_hex_dump("SSD SELECT response", resp, resp_len - 2);
    return SE050_OK;
}

int se050_select_applet(se050_session_t *session) {
    uint8_t cmd[32], resp[64];
    size_t pos = 0, resp_len = sizeof(resp);
    cmd[pos++] = 0x00; cmd[pos++] = 0xA4; cmd[pos++] = 0x04; cmd[pos++] = 0x00;
    cmd[pos++] = sizeof(SE05X_AID);
    memcpy(&cmd[pos], SE05X_AID, sizeof(SE05X_AID)); pos += sizeof(SE05X_AID);
    cmd[pos++] = 0x00;
    
    DBG("Selecting SE05x applet...");
    int ret = se050_transceive(&session->transport, cmd, pos, resp, &resp_len);
    if (ret != SE050_OK) return ret;
    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("SELECT failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }
    DBG("Applet selected OK");
    return SE050_OK;
}

int se050_open_session(se050_session_t *session, const char *dev,
                       const uint8_t *enc_key, const uint8_t *mac_key, uint8_t key_ver) {
    int ret;
    if (!session || !enc_key || !mac_key) return SE050_ERR_PARAM;
    memset(session, 0, sizeof(se050_session_t));

    if ((ret = se050_open(&session->transport, dev)) != SE050_OK) return ret;

    uint8_t atr[64];
    size_t atr_len = sizeof(atr);
    if ((ret = se050_get_atr(&session->transport, atr, &atr_len)) == SE050_OK) {
        se050_hex_dump("ATR", atr, atr_len);
    }

    if ((ret = se050_select_applet(session)) != SE050_OK) { se050_close(&session->transport); return ret; }
    if ((ret = scp03_init(&session->scp03, enc_key, mac_key, key_ver)) != SE050_OK) { se050_close(&session->transport); return ret; }
    if ((ret = scp03_authenticate(&session->scp03, &session->transport)) != SE050_OK) { se050_close(&session->transport); return ret; }
    return SE050_OK;
}

int se050_open_session_with_dek(se050_session_t *session, const char *dev,
                                const uint8_t *enc_key, const uint8_t *mac_key,
                                const uint8_t *dek_key, uint8_t key_ver) {
    int ret;
    if (!session || !enc_key || !mac_key || !dek_key) return SE050_ERR_PARAM;
    memset(session, 0, sizeof(se050_session_t));

    if ((ret = se050_open(&session->transport, dev)) != SE050_OK) return ret;

    uint8_t atr[64];
    size_t atr_len = sizeof(atr);
    if ((ret = se050_get_atr(&session->transport, atr, &atr_len)) == SE050_OK) {
        se050_hex_dump("ATR", atr, atr_len);
    }

    if ((ret = se050_select_applet(session)) != SE050_OK) { se050_close(&session->transport); return ret; }
    if ((ret = scp03_init_with_dek(&session->scp03, enc_key, mac_key, dek_key, key_ver)) != SE050_OK) { se050_close(&session->transport); return ret; }
    if ((ret = scp03_authenticate(&session->scp03, &session->transport)) != SE050_OK) { se050_close(&session->transport); return ret; }
    return SE050_OK;
}

/*
 * Open session for platform-level operations like key rotation.
 * Per NXP reference (SELECT_SSD mode), we select the SSD (Supplementary Security
 * Domain) before authenticating. This is required for PUT KEY command.
 * Use this for GlobalPlatform commands like PUT KEY.
 */
int se050_open_session_isd(se050_session_t *session, const char *dev,
                           const uint8_t *enc_key, const uint8_t *mac_key,
                           const uint8_t *dek_key, uint8_t key_ver) {
    int ret;
    if (!session || !enc_key || !mac_key || !dek_key) return SE050_ERR_PARAM;
    memset(session, 0, sizeof(se050_session_t));

    if ((ret = se050_open(&session->transport, dev)) != SE050_OK) return ret;

    uint8_t atr[64];
    size_t atr_len = sizeof(atr);
    if ((ret = se050_get_atr(&session->transport, atr, &atr_len)) == SE050_OK) {
        se050_hex_dump("ATR", atr, atr_len);
    }

    /*
     * Select the SSD (Supplementary Security Domain) for key rotation.
     * Per NXP's reference (sm_connect.c SELECT_SSD mode), the SSD must be
     * selected before SCP03 authentication for platform key operations.
     * SSD AID: D2 76 00 00 85 30 4A 43 4F 90 03
     */
    DBG("Opening SSD session for key rotation");
    if ((ret = se050_select_ssd(session)) != SE050_OK) {
        DBG("SSD selection failed: %d", ret);
        se050_close(&session->transport);
        return ret;
    }

    if ((ret = scp03_init_with_dek(&session->scp03, enc_key, mac_key, dek_key, key_ver)) != SE050_OK) { se050_close(&session->transport); return ret; }
    if ((ret = scp03_authenticate(&session->scp03, &session->transport)) != SE050_OK) { se050_close(&session->transport); return ret; }
    return SE050_OK;
}

int se050_secure_transceive(se050_session_t *session, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                            const uint8_t *data, size_t data_len, uint8_t *response, size_t *resp_len) {
    uint8_t wrapped[SE050_MAX_BUF];
    size_t wrap_len = sizeof(wrapped);
    int ret;

    if ((ret = scp03_wrap_apdu(&session->scp03, cla, ins, p1, p2, data, data_len, wrapped, &wrap_len)) != SE050_OK) return ret;
    se050_hex_dump("Wrapped APDU", wrapped, wrap_len);
    if ((ret = se050_transceive(&session->transport, wrapped, wrap_len, response, resp_len)) != SE050_OK) return ret;
    se050_hex_dump("Raw response", response, *resp_len);
    if ((ret = scp03_unwrap_response(&session->scp03, data_len, response, resp_len)) != SE050_OK) return ret;
    se050_hex_dump("Unwrapped response", response, *resp_len);
    return SE050_OK;
}

void se050_close_session(se050_session_t *session) {
    if (session) {
        /* Use secure_zero to ensure keys are cleared even with compiler optimizations */
        secure_zero(&session->scp03, sizeof(scp03_ctx_t));
        se050_close(&session->transport);
    }
}

/* ============================================================================
 *                           TLV HELPER FUNCTIONS
 * ============================================================================ */

/*
 * Add TLV to buffer, returns new position.
 * IMPORTANT: Caller must ensure buf has at least (pos + 4 + len) bytes available.
 * For SE050 commands, SE050_MAX_BUF (1024) is always used which is sufficient
 * for all supported operations (max ~200 bytes for key import).
 */
static size_t tlv_add(uint8_t *buf, size_t pos, uint8_t tag, const uint8_t *data, size_t len) {
    /* Calculate required space: tag(1) + length(1-3) + data(len) */
    size_t header_len = 1 + ((len < 0x80) ? 1 : (len < 0x100) ? 2 : 3);
    size_t required = pos + header_len + len;
    if (required > SE050_MAX_BUF) {
        return 0;  /* Buffer overflow - return 0 to signal error */
    }

    buf[pos++] = tag;
    if (len < 0x80) {
        buf[pos++] = len;
    } else if (len < 0x100) {
        buf[pos++] = 0x81;
        buf[pos++] = len;
    } else {
        buf[pos++] = 0x82;
        buf[pos++] = (len >> 8) & 0xFF;
        buf[pos++] = len & 0xFF;
    }
    if (data && len > 0) {
        memcpy(&buf[pos], data, len);
        pos += len;
    }
    return pos;
}

/* Add 4-byte object ID as TLV */
static size_t tlv_add_u32(uint8_t *buf, size_t pos, uint8_t tag, uint32_t val) {
    uint8_t data[4] = {(val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF};
    return tlv_add(buf, pos, tag, data, 4);
}

/* Add 1-byte value as TLV */
static size_t tlv_add_u8(uint8_t *buf, size_t pos, uint8_t tag, uint8_t val) {
    return tlv_add(buf, pos, tag, &val, 1);
}

/* Add 2-byte value as TLV (big-endian) */
static size_t tlv_add_u16(uint8_t *buf, size_t pos, uint8_t tag, uint16_t val) {
    uint8_t data[2];
    data[0] = (val >> 8) & 0xFF;
    data[1] = val & 0xFF;
    return tlv_add(buf, pos, tag, data, 2);
}

/* Parse TLV, returns pointer to value and sets len. Returns NULL if not found */
static const uint8_t *tlv_find(const uint8_t *buf, size_t buf_len, uint8_t tag, size_t *out_len) {
    size_t pos = 0;
    while (pos < buf_len) {
        uint8_t t = buf[pos++];
        if (pos >= buf_len) return NULL;
        size_t len;
        if (buf[pos] < 0x80) {
            len = buf[pos++];
        } else if (buf[pos] == 0x81) {
            pos++;
            if (pos >= buf_len) return NULL;
            len = buf[pos++];
        } else if (buf[pos] == 0x82) {
            pos++;
            if (pos + 2 > buf_len) return NULL;  /* Need 2 bytes for length */
            len = (buf[pos] << 8) | buf[pos + 1];
            pos += 2;
        } else {
            return NULL;  /* Invalid length encoding */
        }
        /* Bounds check: ensure value fits within buffer */
        if (pos + len > buf_len) return NULL;
        if (t == tag) {
            *out_len = len;
            return &buf[pos];
        }
        pos += len;
    }
    return NULL;
}

/* ============================================================================
 *                           SE05x CRYPTO OPERATIONS
 * ============================================================================ */

int se050_get_random(se050_session_t *session, uint8_t *random, size_t len) {
    /* SE05x GetRandom: CLA=0x80, INS=0x04 (MGMT), P1=0x00 (DEFAULT), P2=0x49 (RANDOM)
       TLV: 41 02 [length BE] - Tag 0x41, length as 2-byte value

       SE050 may return fewer bytes than requested per call, so we loop until
       we have the full amount needed for cryptographic security. */
    size_t total = 0;

    while (total < len) {
        size_t request = len - total;
        uint8_t cmd_data[4] = {0x41, 0x02, (request >> 8) & 0xFF, request & 0xFF};
        uint8_t resp[SE050_MAX_BUF];
        size_t resp_len = sizeof(resp);

        int ret = se050_secure_transceive(session, 0x80, 0x04, 0x00, 0x49, cmd_data, 4, resp, &resp_len);
        if (ret != SE050_OK) return ret;

        if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
            return SE050_ERR_RESPONSE;
        }

        /* Parse TLV response: 41 [len] [data] 90 00 */
        if (resp_len > 4 && resp[0] == 0x41) {
            size_t rlen = (resp[1] == 0x82) ? ((resp[2] << 8) | resp[3]) : resp[1];
            int off = (resp[1] == 0x82) ? 4 : 2;
            if (rlen == 0) return SE050_ERR_RESPONSE;  /* No progress - error */
            size_t to_copy = (rlen > (len - total)) ? (len - total) : rlen;
            memcpy(random + total, &resp[off], to_copy);
            total += to_copy;
            DBG("TRNG: got %zu bytes, total %zu/%zu", to_copy, total, len);
        } else {
            return SE050_ERR_RESPONSE;
        }
    }
    return SE050_OK;
}

int se050_generate_keypair(se050_session_t *session, uint32_t key_id, uint8_t curve_id) {
    /*
     * WriteECKey for generation (per NXP middleware spec):
     * CLA=0x80, INS=0x01 (WRITE), P1=0x60|0x01 (KEY_PAIR|EC), P2=0x00 (DEFAULT)
     * TLV order: TAG_POLICY, TAG_1 (key_id), TAG_2 (curve_id)
     * When generating, no private/public key data (TAG_3/TAG_4) is sent.
     */
    uint8_t cmd_data[32];
    size_t pos = 0;

    /* Default policy: ALLOW_SIGN | ALLOW_VERIFY | ALLOW_READ | ALLOW_DELETE, no auth */
    static const uint8_t default_policy[] = {
        0x08,                         /* policy length (8 bytes follow) */
        0x00, 0x00, 0x00, 0x00,       /* auth object ID = 0 (no auth required) */
        0x18, 0x24, 0x00, 0x00        /* SIGN|VERIFY|READ|DELETE = 0x18240000 BE */
    };
    pos = tlv_add(cmd_data, pos, SE05X_TAG_POLICY, default_policy, sizeof(default_policy));

    pos = tlv_add_u32(cmd_data, pos, SE05X_TAG_1, key_id);
    pos = tlv_add_u8(cmd_data, pos, SE05X_TAG_2, curve_id);

    uint8_t resp[64];
    size_t resp_len = sizeof(resp);

    DBG("Generating keypair: key_id=0x%08X, curve=0x%02X", key_id, curve_id);
    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_WRITE,
                                       SE05X_P1_KEY_PAIR | SE05X_P1_EC, SE05X_P2_DEFAULT,
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) return ret;

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("Generate keypair failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }

    DBG("Keypair generated successfully");
    return SE050_OK;
}

int se050_write_keypair(se050_session_t *session, uint32_t key_id, uint8_t curve_id,
                        const uint8_t *private_key, size_t priv_len,
                        const uint8_t *public_key, size_t pub_len) {
    /*
     * WriteECKey for import (per NXP middleware spec):
     * CLA=0x80, INS=0x01 (WRITE), P1=0x60|0x01 (KEY_PAIR|EC), P2=0x00 (DEFAULT)
     * TLV order: TAG_POLICY, TAG_1 (key_id), TAG_2 (curve_id),
     *            TAG_3 (private key), TAG_4 (public key)
     */
    if (!private_key || priv_len != 32) return SE050_ERR_PARAM;
    if (!public_key || pub_len != 65) return SE050_ERR_PARAM;

    uint8_t cmd_data[144];
    size_t pos = 0;

    /* Default policy: ALLOW_SIGN | ALLOW_VERIFY | ALLOW_READ | ALLOW_DELETE, no auth */
    static const uint8_t default_policy[] = {
        0x08,                         /* policy length (8 bytes follow) */
        0x00, 0x00, 0x00, 0x00,       /* auth object ID = 0 (no auth required) */
        0x18, 0x24, 0x00, 0x00        /* SIGN|VERIFY|READ|DELETE = 0x18240000 BE */
    };
    pos = tlv_add(cmd_data, pos, SE05X_TAG_POLICY, default_policy, sizeof(default_policy));

    pos = tlv_add_u32(cmd_data, pos, SE05X_TAG_1, key_id);
    pos = tlv_add_u8(cmd_data, pos, SE05X_TAG_2, curve_id);
    pos = tlv_add(cmd_data, pos, SE05X_TAG_3, private_key, priv_len);
    pos = tlv_add(cmd_data, pos, SE05X_TAG_4, public_key, pub_len);

    uint8_t resp[64];
    size_t resp_len = sizeof(resp);

    DBG("Writing keypair: key_id=0x%08X, curve=0x%02X", key_id, curve_id);
    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_WRITE,
                                       SE05X_P1_KEY_PAIR | SE05X_P1_EC, SE05X_P2_DEFAULT,
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) return ret;

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("Write keypair failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }

    DBG("Keypair written successfully");
    return SE050_OK;
}

int se050_read_pubkey(se050_session_t *session, uint32_t key_id,
                      uint8_t *pubkey, size_t *pubkey_len) {
    /*
     * ReadObject for public key from keypair:
     * CLA=0x80, INS=0x02 (READ), P1=0x00 (DEFAULT), P2=0x00 (DEFAULT)
     * When reading a KEY_PAIR object, SE050 returns the public key automatically.
     * TLV: TAG_1 (41) = key_id (4 bytes)
     * Response: TAG_1 (41) = public key (65 bytes uncompressed, 33 compressed)
     */
    uint8_t cmd_data[8];
    size_t pos = 0;
    pos = tlv_add_u32(cmd_data, pos, SE05X_TAG_1, key_id);

    uint8_t resp[128];
    size_t resp_len = sizeof(resp);

    DBG("Reading public key: key_id=0x%08X", key_id);
    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_READ,
                                       0x00, SE05X_P2_DEFAULT,  /* P1=DEFAULT for keypair read */
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) return ret;

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("Read pubkey failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }

    /* Parse response - find TAG_1 */
    size_t pk_len;
    const uint8_t *pk = tlv_find(resp, resp_len - 2, SE05X_TAG_1, &pk_len);
    if (!pk) {
        DBG("Public key not found in response");
        return SE050_ERR_RESPONSE;
    }

    if (pk_len > *pubkey_len) {
        DBG("Public key too large: %zu > %zu", pk_len, *pubkey_len);
        return SE050_ERR_BUFFER;
    }

    memcpy(pubkey, pk, pk_len);
    *pubkey_len = pk_len;

    DBG("Public key read: %zu bytes", pk_len);
    return SE050_OK;
}

int se050_delete_object(se050_session_t *session, uint32_t object_id) {
    /*
     * DeleteSecureObject:
     * CLA=0x80, INS=0x04 (MGMT), P1=0x00 (DEFAULT), P2=0x26 (DELETE_OBJECT)
     * TLV: TAG_1 (41) = object_id (4 bytes)
     */
    uint8_t cmd_data[8];
    size_t pos = 0;
    pos = tlv_add_u32(cmd_data, pos, SE05X_TAG_1, object_id);

    uint8_t resp[32];
    size_t resp_len = sizeof(resp);

    DBG("Deleting object: 0x%08X", object_id);
    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_MGMT,
                                       0x00, 0x28,  /* P2=DELETE_OBJECT */
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) return ret;

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("Delete object failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }

    DBG("Object deleted successfully");
    return SE050_OK;
}

int se050_object_exists(se050_session_t *session, uint32_t object_id) {
    /*
     * CheckObjectExists:
     * CLA=0x80, INS=0x04 (MGMT), P1=0x00 (DEFAULT), P2=0x27 (EXIST)
     * TLV: TAG_1 (41) = object_id (4 bytes)
     * Response: TAG_1 (41) = result (1 byte: 0x01=exists, 0x02=not exists)
     */
    uint8_t cmd_data[8];
    size_t pos = 0;
    pos = tlv_add_u32(cmd_data, pos, SE05X_TAG_1, object_id);

    uint8_t resp[32];
    size_t resp_len = sizeof(resp);

    DBG("Checking object exists: 0x%08X", object_id);
    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_MGMT,
                                       0x00, 0x27,  /* P2=EXIST */
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) {
        DBG("CheckObjectExists transceive failed: %d", ret);
        return ret;
    }

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("CheckObjectExists bad SW: %02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }

    /* Parse response - look for result in TAG_1 */
    size_t result_len;
    const uint8_t *result = tlv_find(resp, resp_len - 2, SE05X_TAG_1, &result_len);
    DBG("CheckObjectExists result: ptr=%p, len=%zu, val=%02X",
        (void*)result, result_len, result ? result[0] : 0xFF);

    if (result && result_len >= 1) {
        if (result[0] == 0x01) {
            DBG("Object 0x%08X EXISTS", object_id);
            return 1;  /* Exists */
        } else if (result[0] == 0x02) {
            DBG("Object 0x%08X does not exist", object_id);
            return 0;  /* Does not exist */
        }
    }

    DBG("CheckObjectExists: unexpected response format");
    return 0;  /* Default: does not exist */
}

int se050_sign(se050_session_t *session, uint32_t key_id,
               const uint8_t *hash, size_t hash_len,
               uint8_t *signature, size_t *sig_len) {
    /*
     * ECDSASign:
     * CLA=0x80, INS=0x03 (CRYPTO), P1=0x0C (SIGNATURE), P2=0x09 (SIGN)
     * TLV: TAG_1 (41) = key_id (4 bytes)
     *      TAG_2 (42) = algorithm (1 byte: 0x21 = ECDSA_SHA256)
     *      TAG_3 (43) = data to sign (32-byte hash)
     * Response: TAG_1 (41) = signature (DER encoded)
     */
    if (!hash || hash_len != 32) return SE050_ERR_PARAM;

    uint8_t cmd_data[64];
    size_t pos = 0;
    pos = tlv_add_u32(cmd_data, pos, SE05X_TAG_1, key_id);
    pos = tlv_add_u8(cmd_data, pos, SE05X_TAG_2, 0x21);  /* ECDSA_SHA256 (0x21=33) */
    pos = tlv_add(cmd_data, pos, SE05X_TAG_3, hash, hash_len);

    uint8_t resp[128];
    size_t resp_len = sizeof(resp);

    DBG("Signing with key: 0x%08X", key_id);
    se050_hex_dump("Hash to sign", hash, hash_len);

    /* Per NXP: P1=SIGNATURE (0x0C), not P1=EC (0x01) */
    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_CRYPTO,
                                       SE05X_P1_SIGNATURE, SE05X_P2_SIGN,
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) {
        DBG("Sign transceive failed: ret=%d", ret);
        return ret;
    }

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("Sign failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }

    /* Parse response - find signature in TAG_1 */
    size_t sig_data_len;
    const uint8_t *sig_data = tlv_find(resp, resp_len - 2, SE05X_TAG_1, &sig_data_len);
    if (!sig_data) {
        DBG("Signature not found in response");
        return SE050_ERR_RESPONSE;
    }

    if (sig_data_len > *sig_len) {
        DBG("Signature too large: %zu > %zu", sig_data_len, *sig_len);
        return SE050_ERR_BUFFER;
    }

    memcpy(signature, sig_data, sig_data_len);
    *sig_len = sig_data_len;

    se050_hex_dump("Signature (DER)", signature, *sig_len);
    DBG("Signing successful: %zu bytes", *sig_len);
    return SE050_OK;
}

int se050_verify(se050_session_t *session, uint32_t key_id,
                 const uint8_t *hash, size_t hash_len,
                 const uint8_t *signature, size_t sig_len) {
    /*
     * ECDSAVerify:
     * CLA=0x80, INS=0x03 (CRYPTO), P1=0x0C (SIGNATURE), P2=0x0A (VERIFY)
     * TLV: TAG_1 (41) = key_id (4 bytes)
     *      TAG_2 (42) = algorithm (1 byte: 0x21 = ECDSA_SHA256)
     *      TAG_3 (43) = data (32-byte hash)
     *      TAG_5 (45) = signature (DER encoded)
     * Response: TAG_1 (41) = result (1 byte: 0x01 = valid)
     */
    if (!hash || hash_len != 32) return SE050_ERR_PARAM;
    if (!signature || sig_len == 0 || sig_len > 80) return SE050_ERR_PARAM;

    uint8_t cmd_data[128];
    size_t pos = 0;
    pos = tlv_add_u32(cmd_data, pos, SE05X_TAG_1, key_id);
    pos = tlv_add_u8(cmd_data, pos, SE05X_TAG_2, 0x21);  /* ECDSA_SHA256 */
    pos = tlv_add(cmd_data, pos, SE05X_TAG_3, hash, hash_len);
    pos = tlv_add(cmd_data, pos, SE05X_TAG_5, signature, sig_len);

    uint8_t resp[64];
    size_t resp_len = sizeof(resp);

    DBG("Verifying with key: 0x%08X", key_id);
    se050_hex_dump("Hash to verify", hash, hash_len);
    se050_hex_dump("Signature to verify", signature, sig_len);

    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_CRYPTO,
                                       SE05X_P1_SIGNATURE, SE05X_P2_VERIFY,
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) {
        DBG("Verify transceive failed: ret=%d", ret);
        return ret;
    }

    if (resp_len < 2) {
        DBG("Verify response too short");
        return SE050_ERR_RESPONSE;
    }

    uint8_t sw1 = resp[resp_len-2];
    uint8_t sw2 = resp[resp_len-1];

    if (sw1 == 0x90 && sw2 == 0x00) {
        /* Parse response - look for result in TAG_1 */
        size_t result_len;
        const uint8_t *result = tlv_find(resp, resp_len - 2, SE05X_TAG_1, &result_len);
        if (result && result_len >= 1 && result[0] == 0x01) {
            DBG("Signature VALID");
            return 1;  /* Valid */
        }
        DBG("Signature INVALID (result byte)");
        return 0;  /* Invalid */
    }

    /* 6985 = Conditions not satisfied (signature invalid) */
    if (sw1 == 0x69 && sw2 == 0x85) {
        DBG("Signature INVALID (SW 6985)");
        return 0;
    }

    DBG("Verify failed: SW=%02X%02X", sw1, sw2);
    return SE050_ERR_RESPONSE;
}

int se050_get_uid(se050_session_t *session, uint8_t *uid, size_t *uid_len) {
    /*
     * ReadObject for UID:
     * CLA=0x80, INS=0x02 (READ), P1=0x00 (DEFAULT), P2=0x00 (DEFAULT)
     * TLV: TAG_1 (41) = object_id = 0x7FFF0206 (UNIQUE_ID)
     *
     * Note: Factory objects like UID use P1=DEFAULT, not P1=BINARY
     */
    uint8_t cmd_data[8];
    size_t pos = 0;
    pos = tlv_add_u32(cmd_data, pos, SE05X_TAG_1, 0x7FFF0206);

    uint8_t resp[64];
    size_t resp_len = sizeof(resp);

    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_READ,
                                       0x00, SE05X_P2_DEFAULT,  /* P1=DEFAULT for factory objects */
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) return ret;

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        return SE050_ERR_RESPONSE;
    }

    /* Parse response - find TAG_1 */
    size_t uid_data_len;
    const uint8_t *uid_data = tlv_find(resp, resp_len - 2, SE05X_TAG_1, &uid_data_len);
    if (!uid_data) {
        return SE050_ERR_RESPONSE;
    }

    if (uid_data_len > *uid_len) {
        return SE050_ERR_BUFFER;
    }

    memcpy(uid, uid_data, uid_data_len);
    *uid_len = uid_data_len;
    return SE050_OK;
}

/* ============================================================================
 *                           ON-CHIP HASH & KDF
 * ============================================================================ */

int se050_sha256(se050_session_t *session,
                 const uint8_t *data, size_t data_len,
                 uint8_t *hash) {
    /*
     * DigestOneShot:
     * CLA=0x80, INS=0x03 (CRYPTO), P1=0x00 (DEFAULT), P2=0x0E (ONESHOT)
     * TLV: TAG_1 (41) = digest mode (1 byte: 0x04 = SHA256)
     *      TAG_2 (42) = input data
     * Response: TAG_1 (41) = hash output (32 bytes for SHA256)
     */
    if (!session || !data || !hash) return SE050_ERR_PARAM;
    if (data_len > 800) return SE050_ERR_PARAM;  /* SE050 has ~1KB buffer limit */

    uint8_t cmd_data[SE050_MAX_BUF];
    size_t pos = 0;
    pos = tlv_add_u8(cmd_data, pos, SE05X_TAG_1, SE05X_DIGEST_SHA256);
    pos = tlv_add(cmd_data, pos, SE05X_TAG_2, data, data_len);

    uint8_t resp[64];
    size_t resp_len = sizeof(resp);

    DBG("SHA256 digest: %zu bytes input", data_len);

    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_CRYPTO,
                                       SE05X_P1_DEFAULT, SE05X_P2_ONESHOT,
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) {
        DBG("SHA256 transceive failed: ret=%d", ret);
        return ret;
    }

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("SHA256 failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }

    /* Parse response - find hash in TAG_1 */
    size_t hash_len;
    const uint8_t *hash_data = tlv_find(resp, resp_len - 2, SE05X_TAG_1, &hash_len);
    if (!hash_data || hash_len != 32) {
        DBG("SHA256 response invalid: hash_len=%zu", hash_len);
        return SE050_ERR_RESPONSE;
    }

    memcpy(hash, hash_data, 32);
    se050_hex_dump("SHA256 hash", hash, 32);
    return SE050_OK;
}

int se050_pbkdf2(se050_session_t *session,
                 const uint8_t *password, size_t password_len,
                 const uint8_t *salt, size_t salt_len,
                 uint32_t iterations, size_t key_len,
                 uint8_t *derived_key) {
    /*
     * PBKDF2:
     * CLA=0x80, INS=0x03 (CRYPTO), P1=0x05 (HMAC), P2=0x2E (PBKDF)
     * TLV: TAG_1 (41) = password (input key material)
     *      TAG_2 (42) = salt
     *      TAG_3 (43) = iteration count (2 bytes, big-endian)
     *      TAG_4 (44) = requested output length (2 bytes)
     * Response: TAG_1 (41) = derived key
     *
     * Note: SE050 PBKDF2 uses HMAC-SHA256 internally.
     * For BIP39 (HMAC-SHA512), we need to derive twice and concatenate.
     */
    if (!session || !password || !salt || !derived_key) return SE050_ERR_PARAM;
    if (password_len > 256 || salt_len > 256) return SE050_ERR_PARAM;
    if (key_len > 64) return SE050_ERR_PARAM;
    if (iterations > 65535) return SE050_ERR_PARAM;  /* 2-byte limit in TLV */

    uint8_t cmd_data[SE050_MAX_BUF];
    size_t pos = 0;

    /* TAG_1: password/key material */
    pos = tlv_add(cmd_data, pos, SE05X_TAG_1, password, password_len);
    /* TAG_2: salt */
    pos = tlv_add(cmd_data, pos, SE05X_TAG_2, salt, salt_len);
    /* TAG_3: iteration count (2 bytes BE) */
    uint8_t iter_bytes[2] = { (iterations >> 8) & 0xFF, iterations & 0xFF };
    pos = tlv_add(cmd_data, pos, SE05X_TAG_3, iter_bytes, 2);
    /* TAG_4: requested output length (2 bytes BE) */
    uint8_t len_bytes[2] = { (key_len >> 8) & 0xFF, key_len & 0xFF };
    pos = tlv_add(cmd_data, pos, SE05X_TAG_4, len_bytes, 2);

    uint8_t resp[128];
    size_t resp_len = sizeof(resp);

    DBG("PBKDF2: password=%zu bytes, salt=%zu bytes, iterations=%u, key_len=%zu",
        password_len, salt_len, iterations, key_len);

    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_CRYPTO,
                                       SE05X_P1_HMAC, SE05X_P2_PBKDF,
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) {
        DBG("PBKDF2 transceive failed: ret=%d", ret);
        return ret;
    }

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("PBKDF2 failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }

    /* Parse response - find derived key in TAG_1 */
    size_t dk_len;
    const uint8_t *dk_data = tlv_find(resp, resp_len - 2, SE05X_TAG_1, &dk_len);
    if (!dk_data) {
        DBG("PBKDF2 response invalid: no derived key");
        return SE050_ERR_RESPONSE;
    }

    if (dk_len < key_len) {
        DBG("PBKDF2 returned less than requested: %zu < %zu", dk_len, key_len);
        return SE050_ERR_RESPONSE;
    }

    memcpy(derived_key, dk_data, key_len);
    se050_hex_dump("PBKDF2 derived key", derived_key, key_len);
    return SE050_OK;
}

/* ============================================================================
 *                           SECURE STORAGE
 * ============================================================================ */

int se050_write_binary(se050_session_t *session, uint32_t object_id,
                       const uint8_t *data, size_t data_len) {
    /*
     * WriteBinary:
     * CLA=0x80, INS=0x01 (WRITE), P1=0x06 (BINARY), P2=0x00 (DEFAULT)
     * TLV: TAG_1 (41) = object_id (4 bytes)
     *      TAG_4 (44) = data
     */
    if (!session || !data) return SE050_ERR_PARAM;
    if (data_len > 800) return SE050_ERR_PARAM;

    uint8_t cmd_data[SE050_MAX_BUF];
    size_t pos = 0;
    pos = tlv_add_u32(cmd_data, pos, SE05X_TAG_1, object_id);
    pos = tlv_add(cmd_data, pos, SE05X_TAG_4, data, data_len);

    uint8_t resp[32];
    size_t resp_len = sizeof(resp);

    DBG("WriteBinary: object_id=0x%08X, len=%zu", object_id, data_len);

    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_WRITE,
                                       SE05X_P1_BINARY, SE05X_P2_DEFAULT,
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) return ret;

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("WriteBinary failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }

    return SE050_OK;
}

int se050_read_binary(se050_session_t *session, uint32_t object_id,
                      uint8_t *data, size_t *data_len) {
    /*
     * ReadObject:
     * CLA=0x80, INS=0x02 (READ), P1=0x00 (DEFAULT), P2=0x00 (DEFAULT)
     * TLV: TAG_1 (41) = object_id (4 bytes)
     * Response: TAG_1 (41) = data
     */
    if (!session || !data || !data_len) return SE050_ERR_PARAM;

    uint8_t cmd_data[8];
    size_t pos = 0;
    pos = tlv_add_u32(cmd_data, pos, SE05X_TAG_1, object_id);

    uint8_t resp[SE050_MAX_BUF];
    size_t resp_len = sizeof(resp);

    DBG("ReadBinary: object_id=0x%08X", object_id);

    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_READ,
                                       SE05X_P1_DEFAULT, SE05X_P2_DEFAULT,
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) return ret;

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("ReadBinary failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }

    /* Parse response - find data in TAG_1 */
    size_t obj_len;
    const uint8_t *obj_data = tlv_find(resp, resp_len - 2, SE05X_TAG_1, &obj_len);
    if (!obj_data) {
        DBG("ReadBinary: no data in response");
        return SE050_ERR_RESPONSE;
    }

    if (obj_len > *data_len) {
        DBG("ReadBinary: buffer too small %zu > %zu", obj_len, *data_len);
        return SE050_ERR_BUFFER;
    }

    memcpy(data, obj_data, obj_len);
    *data_len = obj_len;
    se050_hex_dump("ReadBinary data", data, obj_len);
    return SE050_OK;
}

int se050_write_hmac_key(se050_session_t *session, uint32_t object_id,
                         const uint8_t *key, size_t key_len) {
    /*
     * WriteSymmKey for HMAC (from NXP middleware):
     * CLA=0x80, INS=0x01 (WRITE), P1=0x05 (HMAC), P2=0x00 (DEFAULT)
     * TLV: TAG_1 (41) = object_id (4 bytes)
     *      TAG_3 (43) = key value (key length is implicit from TLV length)
     * Note: TAG_2 is for KEK ID (key encryption key), not key length!
     */
    if (!session || !key) return SE050_ERR_PARAM;
    if (key_len > 256) return SE050_ERR_PARAM;

    uint8_t cmd_data[512];
    size_t pos = 0;
    pos = tlv_add_u32(cmd_data, pos, SE05X_TAG_1, object_id);
    pos = tlv_add(cmd_data, pos, SE05X_TAG_3, key, key_len);

    uint8_t resp[32];
    size_t resp_len = sizeof(resp);

    DBG("WriteHMACKey: object_id=0x%08X, len=%zu bytes", object_id, key_len);

    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_WRITE,
                                       SE05X_P1_HMAC, SE05X_P2_DEFAULT,
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) return ret;

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("WriteHMACKey failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }

    return SE050_OK;
}

int se050_pbkdf2_with_key(se050_session_t *session, uint32_t hmac_key_id,
                          const uint8_t *salt, size_t salt_len,
                          uint32_t iterations, size_t key_len,
                          uint8_t *derived_key) {
    /*
     * PBKDF2 with stored key:
     * CLA=0x80, INS=0x03 (CRYPTO), P1=0x05 (HMAC), P2=0x2E (PBKDF)
     * TLV: TAG_1 (41) = hmac_key_id (4 bytes, object reference)
     *      TAG_2 (42) = salt
     *      TAG_3 (43) = iteration count (2 bytes BE)
     *      TAG_4 (44) = requested output length (2 bytes BE)
     * Response: TAG_1 (41) = derived key
     */
    if (!session || !salt || !derived_key) return SE050_ERR_PARAM;
    if (salt_len > 256 || key_len > 64) return SE050_ERR_PARAM;
    if (iterations > 65535) return SE050_ERR_PARAM;

    uint8_t cmd_data[SE050_MAX_BUF];
    size_t pos = 0;

    /* TAG_1: HMAC key object ID (reference to stored key) */
    pos = tlv_add_u32(cmd_data, pos, SE05X_TAG_1, hmac_key_id);
    /* TAG_2: salt */
    pos = tlv_add(cmd_data, pos, SE05X_TAG_2, salt, salt_len);
    /* TAG_3: iteration count (2 bytes BE) */
    uint8_t iter_bytes[2] = { (iterations >> 8) & 0xFF, iterations & 0xFF };
    pos = tlv_add(cmd_data, pos, SE05X_TAG_3, iter_bytes, 2);
    /* TAG_4: requested output length (2 bytes BE) */
    uint8_t len_bytes[2] = { (key_len >> 8) & 0xFF, key_len & 0xFF };
    pos = tlv_add(cmd_data, pos, SE05X_TAG_4, len_bytes, 2);

    uint8_t resp[128];
    size_t resp_len = sizeof(resp);

    DBG("PBKDF2 with key 0x%08X: salt=%zu bytes, iter=%u, key_len=%zu",
        hmac_key_id, salt_len, iterations, key_len);

    int ret = se050_secure_transceive(session, 0x80, SE05X_INS_CRYPTO,
                                       SE05X_P1_HMAC, SE05X_P2_PBKDF,
                                       cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) {
        DBG("PBKDF2 with key transceive failed: ret=%d", ret);
        return ret;
    }

    if (resp_len < 2 || resp[resp_len-2] != 0x90 || resp[resp_len-1] != 0x00) {
        DBG("PBKDF2 with key failed: SW=%02X%02X", resp[resp_len-2], resp[resp_len-1]);
        return SE050_ERR_RESPONSE;
    }

    /* Parse response - find derived key in TAG_1 */
    size_t dk_len;
    const uint8_t *dk_data = tlv_find(resp, resp_len - 2, SE05X_TAG_1, &dk_len);
    if (!dk_data || dk_len < key_len) {
        DBG("PBKDF2 with key response invalid");
        return SE050_ERR_RESPONSE;
    }

    memcpy(derived_key, dk_data, key_len);
    se050_hex_dump("PBKDF2 derived key (from stored HMAC)", derived_key, key_len);
    return SE050_OK;
}

/* ============================================================================
 *                           SCP03 KEY ROTATION
 * ============================================================================ */

/*
 * Compute Key Check Value (KCV) per GlobalPlatform spec.
 * KCV = first 3 bytes of AES-ECB(key, 0x01 0x01 ... 0x01)
 */
int se050_compute_kcv(const uint8_t *key, uint8_t *kcv) {
    mbedtls_aes_context aes;
    uint8_t plaintext[16], ciphertext[16];
    int ret;

    if (!key || !kcv) return SE050_ERR_PARAM;

    /* KCV input is 16 bytes of 0x01 for AES keys (GP spec) */
    memset(plaintext, 0x01, 16);

    mbedtls_aes_init(&aes);
    ret = mbedtls_aes_setkey_enc(&aes, key, 128);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return SE050_ERR_CRYPTO;
    }

    ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plaintext, ciphertext);
    mbedtls_aes_free(&aes);

    if (ret != 0) return SE050_ERR_CRYPTO;

    /* KCV is first 3 bytes */
    memcpy(kcv, ciphertext, 3);
    return SE050_OK;
}

/*
 * Encrypt a key with DEK using AES-CBC with zero IV.
 * This is used to protect keys in the PUT KEY command.
 */
static int encrypt_key_with_dek(const uint8_t *dek, const uint8_t *key,
                                uint8_t *encrypted) {
    mbedtls_aes_context aes;
    uint8_t iv[16] = {0};
    int ret;

    mbedtls_aes_init(&aes);
    ret = mbedtls_aes_setkey_enc(&aes, dek, 128);
    if (ret != 0) {
        mbedtls_aes_free(&aes);
        return SE050_ERR_CRYPTO;
    }

    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, iv, key, encrypted);
    mbedtls_aes_free(&aes);

    return (ret == 0) ? SE050_OK : SE050_ERR_CRYPTO;
}

/*
 * Build key data block for PUT KEY command.
 * Format: [key_type(1)] [len(1)] [encrypted_key(16)] [kcv_len(1)] [kcv(3)]
 * Returns number of bytes written.
 */
static size_t build_key_block(uint8_t *buf, const uint8_t *dek,
                              const uint8_t *key) {
    uint8_t encrypted[16], kcv[3];
    size_t pos = 0;

    /* Encrypt key with DEK */
    if (encrypt_key_with_dek(dek, key, encrypted) != SE050_OK) return 0;

    /* Compute KCV */
    if (se050_compute_kcv(key, kcv) != SE050_OK) return 0;

    /* Key type = 0x88 (AES) */
    buf[pos++] = 0x88;

    /* Length = 0x11 (17 bytes: 1 + 16 encrypted key) */
    buf[pos++] = 0x11;

    /* Key length byte */
    buf[pos++] = 0x10;

    /* Encrypted key */
    memcpy(&buf[pos], encrypted, 16);
    pos += 16;

    /* KCV length */
    buf[pos++] = 0x03;

    /* KCV */
    memcpy(&buf[pos], kcv, 3);
    pos += 3;

    return pos;
}

int se050_rotate_platform_keys(se050_session_t *session,
                               const uint8_t *new_enc, const uint8_t *new_mac,
                               const uint8_t *new_dek, uint8_t new_key_version) {
    /*
     * GlobalPlatform PUT KEY command for SCP03 key rotation.
     *
     * APDU: 80 D8 P1 P2 Lc [data] Le
     *   P1 = current key version (for decryption)
     *   P2 = 0x81 (key ID 1 with "more keys" flag)
     *
     * Data format:
     *   [new_key_version] (1 byte)
     *   [key_block_ENC]   (22 bytes: type + len + encrypted + kcv_len + kcv)
     *   [key_block_MAC]   (22 bytes)
     *   [key_block_DEK]   (22 bytes)
     *
     * Total data: 1 + 22*3 = 67 bytes
     */
    uint8_t cmd_data[128];
    uint8_t resp[64];
    size_t resp_len = sizeof(resp);
    size_t pos = 0;
    size_t block_len;
    int ret;

    if (!session || !new_enc || !new_mac || !new_dek) {
        DBG("rotate_platform_keys: invalid parameters");
        return SE050_ERR_PARAM;
    }

    if (!session->scp03.has_dek) {
        DBG("rotate_platform_keys: session opened without DEK");
        return SE050_ERR_PARAM;
    }

    if (!session->scp03.authenticated) {
        DBG("rotate_platform_keys: not authenticated");
        return SE050_ERR_PARAM;
    }

    DBG("Rotating platform keys: current version=0x%02X, new version=0x%02X",
        session->scp03.key_version, new_key_version);

    /* New key version */
    cmd_data[pos++] = new_key_version;

    /* ENC key block */
    block_len = build_key_block(&cmd_data[pos], session->scp03.static_dek, new_enc);
    if (block_len == 0) {
        DBG("Failed to build ENC key block");
        return SE050_ERR_CRYPTO;
    }
    se050_hex_dump("ENC key block", &cmd_data[pos], block_len);
    pos += block_len;

    /* MAC key block */
    block_len = build_key_block(&cmd_data[pos], session->scp03.static_dek, new_mac);
    if (block_len == 0) {
        DBG("Failed to build MAC key block");
        return SE050_ERR_CRYPTO;
    }
    se050_hex_dump("MAC key block", &cmd_data[pos], block_len);
    pos += block_len;

    /* DEK key block */
    block_len = build_key_block(&cmd_data[pos], session->scp03.static_dek, new_dek);
    if (block_len == 0) {
        DBG("Failed to build DEK key block");
        return SE050_ERR_CRYPTO;
    }
    se050_hex_dump("DEK key block", &cmd_data[pos], block_len);
    pos += block_len;

    se050_hex_dump("PUT KEY command data", cmd_data, pos);

    /*
     * Send PUT KEY command.
     * CLA=0x80, INS=0xD8 (PUT KEY)
     * P1 = current key version
     * P2 = 0x81 (key ID 1, multiple keys flag set)
     */
    ret = se050_secure_transceive(session, 0x80, 0xD8,
                                   session->scp03.key_version, 0x81,
                                   cmd_data, pos, resp, &resp_len);
    if (ret != SE050_OK) {
        DBG("PUT KEY transceive failed: %d", ret);
        return ret;
    }

    /* Check response status word */
    if (resp_len < 2) {
        DBG("PUT KEY response too short");
        return SE050_ERR_RESPONSE;
    }

    uint8_t sw1 = resp[resp_len - 2];
    uint8_t sw2 = resp[resp_len - 1];

    if (sw1 != 0x90 || sw2 != 0x00) {
        DBG("PUT KEY failed: SW=%02X%02X", sw1, sw2);
        /* Common error codes:
         * 6982 = Security status not satisfied
         * 6985 = Conditions of use not satisfied
         * 6A80 = Incorrect data
         * 6A88 = Key not found
         */
        return SE050_ERR_RESPONSE;
    }

    /* Parse response - should contain new key version confirmation */
    if (resp_len >= 3 && resp[0] == new_key_version) {
        DBG("Key rotation successful! New version: 0x%02X", resp[0]);
    } else {
        DBG("Key rotation response: %zu bytes", resp_len);
        se050_hex_dump("PUT KEY response", resp, resp_len);
    }

    DBG("=== KEY ROTATION COMPLETE ===");
    DBG("CRITICAL: Update your configuration to use the new keys!");
    DBG("New ENC: (provided by caller)");
    DBG("New MAC: (provided by caller)");
    DBG("New DEK: (provided by caller)");
    DBG("New Version: 0x%02X", new_key_version);

    return SE050_OK;
}


/**
 * Read SE050 device state (LockState, RestrictMode, PlatformSCPRequest)
 * This command works even when device is locked or SCP required.
 * MUST be sent WITHOUT SCP03 encryption.
 *
 * Returns:
 *   state[0] = LockState: 0x00=UNLOCKED, 0x01=TRANSIENT_LOCK, 0x02=PERSISTENT_LOCK
 *   state[1] = RestrictMode: 0x00=NORMAL, 0x01=RESTRICTED  
 *   state[2] = PlatformSCPRequest: 0x00=NOT_REQUIRED, 0x01=SCP_REQUIRED
 */
int se050_read_state(se050_session_t *session, uint8_t *state, size_t *state_len) {
    if (!session || !state || !state_len || *state_len < 3) {
        return SE050_ERR_PARAM;
    }

    /*
     * ReadState APDU (sent WITHOUT SCP03 encryption):
     * CLA = 0x80
     * INS = 0x02 (READ)
     * P1  = 0x07 (READ_STATE)
     * P2  = 0x00
     * Lc  = 0x00 (no data)
     * Le  = 0x00 (expect response)
     */
    uint8_t resp[64];
    size_t resp_len = sizeof(resp);
    int ret;

    /* Send via SCP03 channel */
    ret = se050_secure_transceive(session, 0x80, SE05X_INS_READ,
                                   SE05X_P1_READ_STATE, SE05X_P2_DEFAULT,
                                   NULL, 0, resp, &resp_len);
    if (ret != SE050_OK) {
        DBG("ReadState transceive failed: %d", ret);
        return ret;
    }

    /* Response: TLV with TAG=0x41 (STATE), followed by SW 9000 */
    if (resp_len < 5) {
        DBG("ReadState response too short: %zu", resp_len);
        return SE050_ERR_RESPONSE;
    }

    /* Check status word */
    uint8_t sw1 = resp[resp_len - 2];
    uint8_t sw2 = resp[resp_len - 1];
    if (sw1 != 0x90 || sw2 != 0x00) {
        DBG("ReadState failed: SW=%02X%02X", sw1, sw2);
        return SE050_ERR_RESPONSE;
    }

    /* Parse TLV - expect TAG 0x41 */
    if (resp[0] != 0x41) {
        DBG("ReadState unexpected tag: 0x%02X", resp[0]);
        /* Try to extract raw bytes anyway */
        size_t copy_len = resp_len - 2;
        if (copy_len > *state_len) copy_len = *state_len;
        memcpy(state, resp, copy_len);
        *state_len = copy_len;
        return SE050_OK;
    }

    uint8_t len = resp[1];
    if ((size_t)(len + 4) > resp_len) {
        DBG("ReadState TLV length mismatch");
        return SE050_ERR_RESPONSE;
    }

    size_t copy_len = len;
    if (copy_len > *state_len) copy_len = *state_len;
    memcpy(state, &resp[2], copy_len);
    *state_len = copy_len;

    DBG("ReadState: Lock=0x%02X Restrict=0x%02X SCP=0x%02X",
        state[0], (copy_len > 1) ? state[1] : 0, (copy_len > 2) ? state[2] : 0);

    return SE050_OK;
}
