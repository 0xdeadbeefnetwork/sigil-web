# SIGIL Threat Model

## Overview

SIGIL is a Bitcoin hardware wallet using the NXP SE050 secure element. This document describes the security assumptions, attack vectors, and mitigations.

## Security Goals

1. **Private key protection** - Keys never leave the SE050
2. **Transaction integrity** - Only user-authorized transactions are signed
3. **Channel integrity** - SCP03 prevents tampering on the host-to-SE050 bus
4. **Network privacy** - Optional Tor routing for all network requests

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                     UNTRUSTED ZONE                          │
│  - Internet / Mempool APIs / Electrum servers               │
│  - Remote attackers                                         │
└─────────────────────────────────────────────────────────────┘
                            │
                    ┌───────▼───────┐
                    │   Tor Proxy   │  (optional, port 9050)
                    └───────┬───────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    HOST SYSTEM (Pi)                          │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Flask Web App (sigil.web)                             │ │
│  │  12 Blueprints: auth, dashboard, wallet_mgmt,          │ │
│  │  settings, signing, logs, honeypot, tumbler,           │ │
│  │  privacy, pubkeys, gui_api, qr                         │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │  sigil.bitcoin    sigil.crypto    sigil.privacy        │ │
│  │  sigil.wallet     sigil.network   sigil.hardware       │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │  libse050.so (C) — USB VCOM / I2C driver               │ │
│  └────────────────────────────────────────────────────────┘ │
│  Partially trusted - has access to:                         │
│     - Transaction data before signing                       │
│     - Public keys and addresses                             │
│     - SCP03 session keys (in RAM during session)            │
│     - Session cookies, signing PIN hash                     │
└─────────────────────────────────────────────────────────────┘
                            │
                    ┌───────▼───────┐
                    │ SCP03 Channel │ (AES-128 encrypted + CMAC)
                    └───────┬───────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    TRUSTED ZONE                             │
│                   NXP SE050/SE051                           │
│  - Private key storage (non-exportable)                     │
│  - ECDSA secp256k1 signing                                  │
│  - Hardware TRNG                                            │
│  - Tamper-resistant (CC EAL6+)                              │
│  - SCP03 platform keys (rotatable)                          │
└─────────────────────────────────────────────────────────────┘
```

## Attack Vectors & Mitigations

### 1. Remote Network Attacks

| Attack | Mitigation |
|--------|------------|
| API response manipulation | Transaction data verified before signing; Electrum uses multiple servers |
| Traffic analysis / IP leak | Tor integration via SOCKS5 proxy on all outbound connections |
| MITM on API calls | Tor onion routing provides end-to-end encryption; Electrum uses TLS but with `CERT_NONE` (no verification) |
| Malicious Electrum server | Amount/script verification before signing; server rotation |

### 2. Host System Compromise

| Attack | Mitigation |
|--------|------------|
| Malware stealing keys | Private keys are non-exportable from SE050 hardware |
| Transaction tampering | User verifies transaction details on screen before signing |
| Session hijacking | CSRF tokens, session timeout, `HttpOnly`/`SameSite` cookies |
| Brute force login | Rate limiting: 5 attempts per 5 minutes (sigil.web.security) |
| Password theft | Passwords hashed with SHA-256; stored in `~/.sigil/` with `0o600` perms |

**Limitation**: If the host is fully compromised, an attacker could:
- Display fake transaction details while signing a different transaction
- Exfiltrate public keys and derived addresses
- Intercept signing PIN from web form submission
- Read SCP03 keys from disk (enables bus-level MITM)

**Recommendation**: For high-value operations, verify transactions independently. Keep the host system updated and minimize its attack surface.

### 3. SCP03 Channel Attacks

| Attack | Mitigation |
|--------|------------|
| Bus sniffing (USB/I2C) | SCP03 encrypts all APDU traffic with AES-128 |
| APDU replay | SCP03 CMAC prevents replay and tampering |
| Factory key exploitation | Web UI warns on factory keys; one-click rotation to random keys |
| Key rotation brick | Pending key file written before PUT KEY command; recovery path documented |
| Key file theft | `chmod 0o600` on key files; systemd `ProtectHome=read-only` |

**SCP03 Key Rotation Flow**:
1. New 16-byte AES keys generated via `os.urandom()` (kernel CSPRNG)
2. Pending key file written to disk (pre-rotation safety net)
3. ISD-mode SCP03 session opened with current keys
4. GlobalPlatform PUT KEY command sends new keys (encrypted with current DEK)
5. SE050 replaces platform keys atomically
6. Active key files updated; pending file deleted

**Risk**: If rotation succeeds on the SE050 but the host crashes before saving the active key files, the pending file (`~/.se050-wallet/scp03_pending.json`) contains the new keys for manual recovery. Without either file, the device is permanently bricked.

### 4. Physical Attacks

| Attack | Mitigation |
|--------|------------|
| SE050 physical extraction | Tamper-resistant packaging (CC EAL6+) |
| Side-channel (power/EM) | SE050 built-in countermeasures (shielding, noise injection) |
| Cold boot / RAM dump | Private keys never in host RAM; SCP03 session keys are transient |
| USB/I2C bus probing | SCP03 encryption (requires rotating from factory keys) |

### 5. Web Interface Attacks

| Attack | Mitigation |
|--------|------------|
| XSS | Content Security Policy headers; Jinja2 auto-escaping |
| CSRF | Token validation on all POST/state-changing requests |
| Session fixation | Session regeneration on login |
| Clickjacking | `X-Frame-Options: DENY` header |
| Information leakage | Custom error pages; no stack traces in production |
| Path traversal | Flask routing; no direct file serving from user input |
| Honeypot evasion | Fake `/admin`, `/debug`, `/export`, `/backup` routes log attacker IPs |

### 6. Tumbler Privacy

The built-in tumbler provides **basic** privacy through transaction graph obfuscation using temporary SE050 key slots.

**How it works**:
1. Temporary keypairs generated in SE050 slots (up to 5 hop wallets)
2. User deposits to first hop address
3. Automated chain of transactions through hop wallets with configurable delays
4. Final hop sends to user's main wallet
5. Temporary key slots are wiped after completion

**Limitations**:
- 3-5 hops may not be sufficient against sophisticated chain analysis
- Timing correlation possible if delays are too short or predictable
- Amount correlation if tumbling exact/round amounts
- All hops use the same SE050 (single device fingerprint in timing)

**Not designed for**:
- Evading law enforcement with subpoena power over exchanges
- Mixing large amounts (>0.1 BTC recommended max per job)
- Adversaries with full mempool visibility and timing analysis

### 7. Signing PIN

The optional signing PIN provides a second factor for transaction authorization.

| Property | Detail |
|----------|--------|
| Storage | SHA-256 hash in `~/.sigil/signing_pin.hash` (`0o600`) |
| Required for | Transaction signing, message signing, key rotation, key wipe |
| Not required for | Login, viewing balances, receiving addresses |
| Bypass | Host compromise could intercept PIN from web form |

The signing PIN protects against unauthorized signing if the web session is hijacked but the attacker doesn't know the PIN. It does **not** protect against a fully compromised host.

## SE050 Security Features

- **CC EAL6+** certified secure element (Common Criteria)
- **SCP03** encrypted and authenticated communication channel (AES-128-CBC + CMAC)
- **Non-exportable keys** - private keys cannot be read out via any interface
- **Hardware TRNG** - true random number generation for key generation
- **Secure key storage** - protected against physical extraction and fault injection
- **Key policies** - ALLOW_DELETE policy set on all new keys for slot management
- **Multiple key slots** - 16 independent secp256k1 key slots available

## Known Limitations

### Bricked Key Slots
Some SE050 key slots may become permanently unusable if created without the `ALLOW_DELETE` policy. SIGIL now includes this policy by default, but early test keys may be unrecoverable.
This happened to me while writing the code. Hence the locked keyslots in the released version as nostalgia.

### No Seed Phrase Backup (Hardware-Generated Keys)
When keys are generated directly on the SE050, they are non-exportable:
- Keys cannot be stolen via software
- Keys cannot be backed up or migrated
- If the SE050 is lost/damaged, funds are lost

**Alternative**: SIGIL supports BIP39 seed phrase import, where the seed is used to derive keys that are then loaded onto the SE050. This allows seed-based backup while still using the SE050 for signing.

**Recommendation**: Only store amounts you can afford to lose, or use imported seed phrases with proper backup.

### Display Trust
SIGIL relies on the host system's display. Unlike dedicated hardware wallets (Ledger, Trezor), there is no trusted display on the SE050 itself. A compromised host could show different transaction details than what is actually being signed.

### Single-Device Architecture
Unlike multi-sig setups, SIGIL uses a single SE050 for all signing. There is no geographic or device-level redundancy.

## Systemd Hardening

The production systemd service includes:

| Directive | Purpose |
|-----------|---------|
| `NoNewPrivileges=true` | Prevents privilege escalation |
| `PrivateTmp=true` | Isolated /tmp namespace |
| `ProtectSystem=strict` | Read-only filesystem except allowed paths |
| `ProtectHome=read-only` | Cannot modify home directory (except `ReadWritePaths`) |
| `ReadWritePaths=` | Only `~/.sigil`, `~/.se050-wallet`, `/var/log/sigil` are writable |

## Recommendations

1. **Rotate SCP03 keys** immediately after first setup (Settings > SCP03 Key Security)
2. **Enable Tor** for network privacy
3. **Set a signing PIN** for transaction authorization (2FA)
4. **Back up SCP03 keys** after rotation (shown once, loss = bricked device)
5. **Verify transactions** independently for large amounts
6. **Keep host system updated** and minimize attack surface
7. **Physical security** - secure the Raspberry Pi and SE050
8. **Don't store life savings** - this is experimental software

## Responsible Disclosure

Report security issues to: _SiCk @ afflicted.sh

---

*"Security is a process, not a product."* - Bruce Schneier
