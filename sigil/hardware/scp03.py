"""
SCP03 key loading and management for SE050 authentication.

Loads SCP03 encryption and MAC keys from environment variables,
config files, or JSON configuration. Also provides key saving
and factory key detection for the key rotation UI.
"""

import os
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

from sigil.hardware.constants import FACTORY_ENC, FACTORY_MAC, FACTORY_DEK


def _load_scp03_keys() -> Tuple[bytes, bytes]:
    """
    Load SCP03 keys from environment, config file, or use defaults.

    Key sources (checked in order):
    1. Environment variables: SE050_ENC_KEY and SE050_MAC_KEY (hex strings)
    2. JSON config: ~/.se050-wallet/scp03_keys.json
    3. Binary file: ~/.se050-wallet/scp03.key (32 bytes: ENC || MAC)
    4. Factory defaults (for development only!)

    For production, ALWAYS rotate keys and store securely!
    Generate new keys with: ./scp03_keygen.py generate -o keys.json
    """
    # Avoid circular import - Config is needed for WALLET_DIR
    from sigil.bitcoin.config import Config

    # 1. Check environment variables first (highest priority)
    env_enc = os.environ.get('SE050_ENC_KEY')
    env_mac = os.environ.get('SE050_MAC_KEY')
    if env_enc and env_mac:
        try:
            enc = bytes.fromhex(env_enc.strip())
            mac = bytes.fromhex(env_mac.strip())
            if len(enc) == 16 and len(mac) == 16:
                return enc, mac
        except ValueError:
            pass  # Invalid hex, try other sources

    # 2. Check JSON config file
    json_file = Config.WALLET_DIR / 'scp03_keys.json'
    if json_file.exists():
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            enc = bytes.fromhex(data['enc'])
            mac = bytes.fromhex(data['mac'])
            if len(enc) == 16 and len(mac) == 16:
                return enc, mac
        except (json.JSONDecodeError, KeyError, ValueError):
            pass  # Invalid JSON or missing keys

    # 3. Check key file (supports multiple formats)
    key_file = Config.WALLET_DIR / 'scp03.key'
    if key_file.exists():
        try:
            text = key_file.read_text()
            # Try text format: "ENC <hex>\nMAC <hex>\n..."
            keys = {}
            for line in text.strip().split('\n'):
                line = line.strip()
                if line.startswith('ENC '):
                    keys['enc'] = bytes.fromhex(line[4:].strip())
                elif line.startswith('MAC '):
                    keys['mac'] = bytes.fromhex(line[4:].strip())
            if 'enc' in keys and 'mac' in keys:
                if len(keys['enc']) == 16 and len(keys['mac']) == 16:
                    return keys['enc'], keys['mac']
            # Try raw hex format (64 chars = ENC + MAC)
            text = text.strip().replace(' ', '').replace('\n', '')
            if len(text) >= 64:
                return bytes.fromhex(text[:32]), bytes.fromhex(text[32:64])
        except Exception:
            pass
        # Try binary format (32 bytes)
        try:
            data = key_file.read_bytes()
            if len(data) >= 32:
                return data[:16], data[16:32]
        except Exception:
            pass

    # 3b. Check local scp03.key in script directory (fallback)
    local_key_file = Path(__file__).parent / 'scp03.key'
    if local_key_file.exists() and local_key_file != key_file:
        try:
            text = local_key_file.read_text()
            keys = {}
            for line in text.strip().split('\n'):
                line = line.strip()
                if line.startswith('ENC '):
                    keys['enc'] = bytes.fromhex(line[4:].strip())
                elif line.startswith('MAC '):
                    keys['mac'] = bytes.fromhex(line[4:].strip())
            if 'enc' in keys and 'mac' in keys:
                if len(keys['enc']) == 16 and len(keys['mac']) == 16:
                    return keys['enc'], keys['mac']
        except Exception:
            pass

    # 4. No keys found - FAIL SECURE
    # NEVER silently fall back to factory defaults - they are PUBLIC!
    # An attacker knowing the SCP03 keys can intercept and modify all SE050 communication.
    print("", file=sys.stderr)
    print("  +================================================================+", file=sys.stderr)
    print("  |  CRITICAL: No SCP03 keys found! Cannot connect to SE050.       |", file=sys.stderr)
    print("  |                                                                |", file=sys.stderr)
    print("  |  Create keys in ONE of these locations:                        |", file=sys.stderr)
    print("  |    ~/.se050-wallet/scp03.key     (text: ENC <hex>\\nMAC <hex>)  |", file=sys.stderr)
    print("  |    ~/.se050-wallet/scp03_keys.json  (JSON: {enc, mac})         |", file=sys.stderr)
    print("  |    Environment: SE050_ENC_KEY, SE050_MAC_KEY                   |", file=sys.stderr)
    print("  |                                                                |", file=sys.stderr)
    print("  |  For NEW device with factory keys, run:                        |", file=sys.stderr)
    print("  |    python3 scp03_keygen.py init                                |", file=sys.stderr)
    print("  +================================================================+", file=sys.stderr)
    print("", file=sys.stderr)
    raise RuntimeError("SCP03 keys not configured - refusing to use factory defaults")


def _load_scp03_dek() -> Optional[bytes]:
    """
    Load SCP03 DEK (Data Encryption Key) from config files.

    The DEK is needed for key rotation (encrypts new keys in PUT KEY command).
    If the current ENC+MAC match factory defaults, returns the factory DEK
    (safe assumption: if ENC/MAC are factory, DEK hasn't been rotated either).

    Returns None if DEK is not available and keys aren't factory defaults.
    """
    from sigil.bitcoin.config import Config

    # 1. Check environment variable
    env_dek = os.environ.get('SE050_DEK_KEY')
    if env_dek:
        try:
            dek = bytes.fromhex(env_dek.strip())
            if len(dek) == 16:
                return dek
        except ValueError:
            pass

    # 2. Check JSON config
    json_file = Config.WALLET_DIR / 'scp03_keys.json'
    if json_file.exists():
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            if 'dek' in data:
                dek = bytes.fromhex(data['dek'])
                if len(dek) == 16:
                    return dek
        except (json.JSONDecodeError, KeyError, ValueError):
            pass

    # 3. Check scp03.key text file for DEK line
    key_file = Config.WALLET_DIR / 'scp03.key'
    if key_file.exists():
        try:
            for line in key_file.read_text().strip().split('\n'):
                line = line.strip()
                if line.startswith('DEK '):
                    dek = bytes.fromhex(line[4:].strip())
                    if len(dek) == 16:
                        return dek
        except Exception:
            pass

    # 4. If current keys are factory defaults, DEK is also factory
    try:
        enc, mac = _load_scp03_keys()
        if enc == FACTORY_ENC and mac == FACTORY_MAC:
            return FACTORY_DEK
    except RuntimeError:
        # No keys configured at all — might be first setup with factory defaults
        return FACTORY_DEK

    return None


def is_using_factory_keys() -> bool:
    """Check if the currently loaded SCP03 keys are the factory defaults."""
    try:
        enc, mac = _load_scp03_keys()
        return enc == FACTORY_ENC and mac == FACTORY_MAC
    except RuntimeError:
        # No keys configured — device is likely on factory defaults
        return True


def save_scp03_keys(enc: bytes, mac: bytes, dek: bytes) -> None:
    """
    Save SCP03 keys to both file formats with secure permissions.

    Writes:
    - ~/.se050-wallet/scp03.key  (text format)
    - ~/.se050-wallet/scp03_keys.json  (JSON format with metadata)

    Both files are set to 0o600 (owner read/write only).
    """
    from sigil.bitcoin.config import Config

    wallet_dir = Config.WALLET_DIR
    wallet_dir.mkdir(parents=True, exist_ok=True)

    # Write text format
    key_file = wallet_dir / 'scp03.key'
    key_file.write_text(
        f"ENC {enc.hex().upper()}\n"
        f"MAC {mac.hex().upper()}\n"
        f"DEK {dek.hex().upper()}\n"
    )
    try:
        key_file.chmod(0o600)
    except OSError:
        pass  # Windows doesn't support Unix permissions

    # Write JSON format with metadata
    json_file = wallet_dir / 'scp03_keys.json'
    json_file.write_text(json.dumps({
        'enc': enc.hex().upper(),
        'mac': mac.hex().upper(),
        'dek': dek.hex().upper(),
        'key_version': 11,
        'rotated_at': datetime.now().isoformat()
    }, indent=2))
    try:
        json_file.chmod(0o600)
    except OSError:
        pass
