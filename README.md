# SIGIL - SE050 Hardware Bitcoin Wallet

**Privacy-focused Bitcoin hardware wallet using NXP SE050 secure element.**

```
███████╗██╗ ██████╗ ██╗██╗
██╔════╝██║██╔════╝ ██║██║
███████╗██║██║  ███╗██║██║
╚════██║██║██║   ██║██║██║
███████║██║╚██████╔╝██║███████╗
╚══════╝╚═╝ ╚═════╝ ╚═╝╚══════╝
```

## Features

### Core Wallet
- **Hardware Security** - Private keys never leave the SE050 secure element
- **Tor Integration** - All network requests routed through Tor (SOCKS5 proxy)
- **Electrum Backend** - Decentralized Electrum servers (no single API dependency)
- **Air-gapped Signing** - Transaction signing happens entirely on the secure element
- **BIP84 Native SegWit** - Modern `bc1q` addresses with lower fees
- **Multi-Slot** - 16 independent key slots on a single SE050

### Privacy Tools
- **Tumbler** - Break transaction graph with automated coin mixing (deposit > hops > main wallet)
- **Privacy Analyzer** - Analyze address clustering and transaction graph patterns
- **Pubkeys Monitor** - Live SSE stream of public keys exposed in mempool transactions
- **Warrant Canary** - Cryptographically signed canary using SE050 ECDSA

### Security
- **SCP03 Key Rotation** - Web UI to rotate factory default platform keys (prevents MITM on SE050 bus)
- **Signing PIN (2FA)** - Optional PIN required before any signing operation
- **CSRF Protection** - Token validation on all state-changing requests
- **Rate Limiting** - Brute-force protection on login and sensitive endpoints
- **Honeypots** - Fake admin panels, debug endpoints, and export routes that log attacker IPs
- **Hardened Systemd** - `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`

### Interfaces
- **Web Interface** - Hacker-themed UI accessible via Tor hidden service
- **CLI Wallet** - Full command-line wallet (`sigil-wallet`)
- **Remote Server** - SE050 signing oracle API over Tor
- **Remote Client** - CLI client for remote wallet access
- **Desktop GUI** - Tkinter interface for VNC/local access

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     SIGIL Web Interface                      │
│              Flask + Gunicorn (12 Blueprints)                │
├──────────────────────────────────────────────────────────────┤
│   sigil.bitcoin       │   sigil.crypto    │   sigil.privacy  │
│   Transaction build   │   BIP32/39/84     │   Tumbler        │
│   Network/Electrum    │   secp256k1       │   Analyzer       │
│   Address derivation  │   Signatures      │   Canary         │
├───────────────────────┼───────────────────┼──────────────────┤
│             sigil.hardware                │  sigil.wallet    │
│   SE050Session (ctypes + SCP03)           │  Wallet core     │
│   Key management, locking, interface      │  Slot management │
├───────────────────────────────────────────┴──────────────────┤
│     Tor SOCKS Proxy (opt)      │       libse050.so (C)       │
│     Port 9050                  │      USB VCOM / I2C         │
└────────────────────────────────┴─────────────────────────────┘
                                          │
                               ┌──────────▼──────────┐
                               │   NXP SE050/SE051   │
                               │  Secure Element     │
                               │  (ECDSA secp256k1)  │
                               │  CC EAL6+ certified │
                               └─────────────────────┘
```

## Hardware

SIGIL uses the **NXP SE050/SE051** secure element. For development:

- **OM-SE050ARD** - Arduino-compatible SE050 dev board
- **FRDM-K64F** - NXP Freedom board (provides VCOM USB interface)

The FRDM-K64F runs NXP's VCOM firmware, exposing the SE050 as a USB serial device. This lets any host (Raspberry Pi, laptop, etc.) communicate with the SE050 over USB.

### Supported Configurations

| Setup | Interface | Notes |
|-------|-----------|-------|
| SE050ARD + FRDM-K64F | USB (VCOM) | Dev kit setup, portable |
| SE050 EdgeLock | I2C | Direct I2C on Pi GPIO |
| SE051 | I2C/USB | Higher security variant |

## Requirements

- Raspberry Pi (tested on Pi 4/5) or any Linux host
- NXP SE050/SE051 secure element (USB via FRDM-K64F or I2C)
- Python 3.10+
- Tor (optional, for network privacy)

## Quick Start

```bash
# Clone
git clone https://github.com/0xdeadbeefnetwork/sigil-web.git
cd sigil-web

# Install (handles everything: deps, I2C, systemd, Tor, credentials)
sudo ./install.sh

# Access
# Local: http://127.0.0.1:5000
# Tor:   http://<your-onion-address>.onion
```

The installer will prompt for a web login password and optional signing PIN.

## Project Structure

```
sigil-web/
├── sigil/                      # Main Python package
│   ├── crypto/                 # Pure crypto (no hardware deps)
│   │   ├── hashing.py          #   SHA256, RIPEMD160, HASH160
│   │   ├── encoding.py         #   Base58, Bech32
│   │   ├── ecc.py              #   secp256k1 point math
│   │   ├── bip39.py            #   Mnemonic generation/validation
│   │   ├── bip32.py            #   HD key derivation (BIP44/84)
│   │   └── signatures.py       #   DER encode/decode, message signing
│   ├── hardware/               # SE050 communication
│   │   ├── constants.py        #   Error codes, curve IDs, factory keys
│   │   ├── errors.py           #   SE050Error exception
│   │   ├── session.py          #   SE050Session (ctypes, SCP03, APDU)
│   │   ├── scp03.py            #   Key loading, saving, rotation support
│   │   ├── locking.py          #   File-based SE050 access locking
│   │   └── interface.py        #   High-level se050_* wrapper functions
│   ├── bitcoin/                # Bitcoin protocol
│   │   ├── config.py           #   Config class (network, paths, key IDs)
│   │   ├── addresses.py        #   Public key compression, address derivation
│   │   ├── transaction.py      #   Transaction building, sighash, signing
│   │   ├── network.py          #   API calls, Tor, UTXO, fees, broadcast
│   │   ├── local_node.py       #   Bitcoin Core RPC interface
│   │   └── amount.py           #   Sat/BTC/USD amount parsing
│   ├── wallet/                 # Wallet management
│   │   ├── core.py             #   Wallet class
│   │   ├── slots.py            #   SE050 slot scanning, locked slots
│   │   └── qr.py               #   ASCII QR code generation
│   ├── privacy/                # Privacy tools
│   │   ├── tumbler.py          #   Coin mixing engine (deposit > hops > collect)
│   │   ├── analyzer.py         #   Transaction privacy scoring
│   │   ├── canary.py           #   Warrant canary (SE050-signed)
│   │   └── verify.py           #   Message signature verification
│   ├── network/                # Protocol clients
│   │   └── electrum.py         #   Electrum protocol (TCP/SSL/Tor)
│   ├── web/                    # Flask web application
│   │   ├── __init__.py         #   create_app() factory
│   │   ├── security.py         #   Headers, CSRF, rate limiting
│   │   ├── session_mgmt.py     #   SE050 session context manager
│   │   ├── helpers.py          #   Auth, constants, network helpers
│   │   ├── blueprints/         #   12 Flask blueprints
│   │   │   ├── auth.py         #     /login, /logout
│   │   │   ├── dashboard.py    #     /, /receive, /send, /history
│   │   │   ├── wallet_mgmt.py  #     /create, /import, /verify, /wipe
│   │   │   ├── settings.py     #     /settings, /password, /pin, /network, /rotate-keys
│   │   │   ├── signing.py      #     /sign-message
│   │   │   ├── logs.py         #     /logs
│   │   │   ├── honeypot.py     #     Fake admin/debug/export traps
│   │   │   ├── tumbler_bp.py   #     /tumbler/*
│   │   │   ├── privacy_bp.py   #     /canary, /privacy
│   │   │   ├── pubkeys.py      #     /pubkeys, /pubkeys/stream (SSE)
│   │   │   ├── gui_api.py      #     /api/gui/* (desktop GUI backend)
│   │   │   └── qr.py           #     /qr (QR code image generation)
│   │   ├── templates/          #   21 Jinja2 HTML templates
│   │   └── static/             #   CSS + JS assets
│   ├── server/                 # Remote signing oracle
│   │   ├── app.py              #   Flask API server
│   │   └── auth.py             #   API key + rate limiting
│   ├── client/                 # Remote client
│   │   ├── client.py           #   SigilClient HTTP class
│   │   └── cli.py              #   CLI entry point
│   ├── gui/                    # Desktop GUI
│   │   ├── api_client.py       #   SigilAPI HTTP client
│   │   └── desktop.py          #   Tkinter interface
│   └── cli/                    # CLI wallet
│       ├── main.py             #   Entry point + argparse
│       └── commands.py         #   All wallet commands
├── native/                     # C library
│   ├── se050_vcom.c            #   SE050 USB VCOM communication
│   ├── se050_scp03.h           #   SCP03 protocol headers
│   └── Makefile                #   Build libse050.so
├── tools/
│   └── scp03_keygen.py         #   SCP03 key generation utility
├── docs/
│   ├── README.md               #   This file
│   ├── SETUP.md                #   Detailed setup guide
│   └── THREAT_MODEL.md         #   Security analysis
├── install.sh                  #   Production installer
├── wsgi.py                     #   Gunicorn WSGI entry point
├── run.py                      #   Dev server entry point
├── gunicorn.conf.py            #   Gunicorn configuration
├── pyproject.toml              #   Python packaging
├── requirements.txt            #   Pip dependencies
└── LICENSE                     #   FUCK YOU PAY ME License
```

## Configuration

Settings are stored in `~/.sigil/network_settings.json`:

```json
{
  "network": "mainnet",
  "use_tor": true,
  "api_backend": "electrum"
}
```

### API Backends

| Backend | Description |
|---------|-------------|
| `electrum` | Connects to decentralized Electrum servers (recommended, more private) |
| `mempool` | Uses mempool.space API (simpler, less private) |

### SCP03 Keys

SCP03 keys are stored in `~/.se050-wallet/`:
- `scp03.key` - Text format (`ENC <hex>\nMAC <hex>\nDEK <hex>`)
- `scp03_keys.json` - JSON format with metadata

**First-time setup**: Use `tools/scp03_keygen.py init` or rotate from factory keys via the web UI at **Settings > SCP03 Key Security > Rotate Keys**.

## Security Model

1. **Private keys** are generated and stored exclusively on the SE050
2. **Signing** operations happen on the SE050 - keys never enter host RAM
3. **SCP03** encrypted/authenticated channel between host and SE050
4. **Optional Tor** for network privacy (all API calls, Electrum connections)
5. **Signing PIN** adds a second factor before any signing operation

See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed security analysis.

## SCP03 Key Rotation

The SE050 ships with publicly known NXP factory default SCP03 keys. These **must** be rotated for production use — anyone with the factory keys can intercept and modify all communication between the host and SE050.

SIGIL provides a web UI for key rotation at `/settings/rotate-keys`:

1. Generates 3 new 16-byte AES keys (ENC, MAC, DEK) using `os.urandom()`
2. Opens an ISD-mode SCP03 session with current keys
3. Sends GlobalPlatform PUT KEY command (new keys encrypted with current DEK)
4. SE050 replaces stored keys atomically
5. New keys are saved to `~/.se050-wallet/` and displayed **once** for backup

**Safety**: New keys are pre-written to a pending file before the rotation command is sent to the SE050. If rotation succeeds but the active key file write fails, the pending file provides recovery.

## CLI Wallet

```bash
# Direct invocation
python -m sigil.cli.main --help

# Commands
python -m sigil.cli.main balance
python -m sigil.cli.main receive
python -m sigil.cli.main send <address> <amount>
python -m sigil.cli.main history
python -m sigil.cli.main sign <message>
```

## Development

```bash
# Run dev server (debug mode, auto-reload)
python run.py

# Or with gunicorn
gunicorn -c gunicorn.conf.py wsgi:app
```

## License

FUCK YOU PAY ME License - See [LICENSE](LICENSE)

## Disclaimer

This is experimental software. Use at your own risk. Always verify transactions before signing. Not responsible for lost funds.

If you like this or find it useful, send some sats:

`bc1qtt02xk5qwgt9qsrz9gwuksqejrh7z5d2e6ny3k`

---

*"Privacy is necessary for an open society in the electronic age."* - A Cypherpunk's Manifesto
