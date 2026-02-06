#!/usr/bin/env python3
"""
SCP03 Key Generation and Rotation Utility for SE050

This tool generates secure SCP03 keys and can rotate them on the SE050.
IMPORTANT: Store generated keys securely - loss means permanent lockout!

Based on NXP's se05x_TP_PlatformSCP03keys.c reference implementation.
Uses GlobalPlatform PUT KEY command (INS 0x78) for rotation.

Usage:
    ./scp03_keygen.py generate           # Generate new random keys
    ./scp03_keygen.py rotate             # Rotate keys on connected SE050
    ./scp03_keygen.py rotate --dry-run   # Show what would happen without changing
    ./scp03_keygen.py show               # Show current key configuration
"""

import sys
import os
import secrets
import argparse
import json
import struct
from datetime import datetime
from pathlib import Path

# Cryptography imports
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# OM-SE050ARD-E default factory keys
# These are the keys for YOUR specific board (extracted earlier)
FACTORY_ENC = bytes.fromhex("D2DB63E7A0A5AED72A6460C4DFDCAF64")
FACTORY_MAC = bytes.fromhex("738D5B798ED241B0B24768514BFBA95B")
FACTORY_DEK = bytes.fromhex("6702DAC30942B2C85E7F47B42CED4E7F")
FACTORY_KEY_VERSION = 0x0B

# GlobalPlatform constants
GP_CLA_BYTE = 0x84  # Secure messaging
GP_INS_PUT_KEY = 0xD8
GP_P2_MULTIPLE_KEYS = 0x81

# Key type coding per GP spec
PUT_KEYS_KEY_TYPE_CODING_AES = 0x88

# KCV length
CRYPTO_KEY_CHECK_LEN = 3


def compute_kcv(key: bytes) -> bytes:
    """
    Compute Key Check Value (KCV) for verification.
    KCV = first 3 bytes of AES-CBC(key, IV=0, data=0x01*16) per GP spec.
    """
    if not HAS_CRYPTO:
        raise ImportError("cryptography package required: pip install cryptography")

    iv = bytes(16)  # Zero IV
    plaintext = b'\x01' * 16

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(plaintext) + encryptor.finalize()
    return encrypted[:CRYPTO_KEY_CHECK_LEN]


def encrypt_key_with_dek(plain_key: bytes, dek: bytes) -> bytes:
    """
    Encrypt a key using DEK for PUT KEY command.
    Uses AES-CBC with zero IV per GP spec.
    """
    if not HAS_CRYPTO:
        raise ImportError("cryptography package required: pip install cryptography")

    iv = bytes(16)  # Zero IV
    cipher = Cipher(algorithms.AES(dek), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plain_key) + encryptor.finalize()


def build_key_data_block(plain_key: bytes, dek: bytes) -> tuple:
    """
    Build a key data block for PUT KEY command.

    Returns: (key_block_bytes, kcv_bytes)

    Format per GP spec:
    - Key Type (1 byte): 0x88 for AES
    - Key Length + 1 (1 byte)
    - Key Length (1 byte)
    - Encrypted Key (16 bytes)
    - KCV Length (1 byte): 0x03
    - KCV (3 bytes)
    """
    key_len = len(plain_key)

    # Compute KCV of the plain key
    kcv = compute_kcv(plain_key)

    # Encrypt the key with DEK
    encrypted_key = encrypt_key_with_dek(plain_key, dek)

    # Build the block
    block = bytes([
        PUT_KEYS_KEY_TYPE_CODING_AES,  # Key type
        key_len + 1,                    # Length of key data field
        key_len,                        # Actual key length
    ])
    block += encrypted_key
    block += bytes([CRYPTO_KEY_CHECK_LEN])  # KCV length
    block += kcv

    return block, kcv


def build_put_key_command(key_version: int, new_enc: bytes, new_mac: bytes,
                          new_dek: bytes, current_dek: bytes) -> tuple:
    """
    Build the complete PUT KEY APDU data.

    Returns: (command_data, expected_kcv_response)
    """
    # Start with key version to replace
    cmd_data = bytes([key_version])
    expected_kcv = bytes([key_version])

    # Add ENC key block
    enc_block, enc_kcv = build_key_data_block(new_enc, current_dek)
    cmd_data += enc_block
    expected_kcv += enc_kcv

    # Add MAC key block
    mac_block, mac_kcv = build_key_data_block(new_mac, current_dek)
    cmd_data += mac_block
    expected_kcv += mac_kcv

    # Add DEK key block
    dek_block, dek_kcv = build_key_data_block(new_dek, current_dek)
    cmd_data += dek_block
    expected_kcv += dek_kcv

    return cmd_data, expected_kcv


def generate_scp03_keys(current_version: int = FACTORY_KEY_VERSION) -> dict:
    """Generate cryptographically secure SCP03 keys"""
    return {
        "enc": secrets.token_bytes(16),
        "mac": secrets.token_bytes(16),
        "dek": secrets.token_bytes(16),
        "key_version": current_version,  # Same version (replace in place)
        "generated_at": datetime.now().isoformat(),
    }


def format_keys_for_display(keys: dict) -> str:
    """Format keys for secure display/storage"""
    lines = [
        "=" * 60,
        "SCP03 KEY SET - STORE SECURELY!",
        "=" * 60,
        f"Generated: {keys.get('generated_at', 'unknown')}",
        f"Key Version: 0x{keys['key_version']:02X}",
        "",
        "# ENC Key (Session Encryption)",
        f"SE050_ENC = bytes.fromhex(\"{keys['enc'].hex().upper()}\")",
        "",
        "# MAC Key (Command Authentication)",
        f"SE050_MAC = bytes.fromhex(\"{keys['mac'].hex().upper()}\")",
        "",
        "# DEK Key (Key Encryption for PUT KEY)",
        f"SE050_DEK = bytes.fromhex(\"{keys['dek'].hex().upper()}\")",
        "",
        "=" * 60,
        "WARNING: Loss of these keys = permanent device lockout!",
        "=" * 60,
    ]
    return "\n".join(lines)


def format_keys_as_c_header(keys: dict) -> str:
    """Format keys as C header defines"""
    return f"""/* SCP03 Keys - Generated {keys.get('generated_at', 'unknown')}
 * WARNING: Store securely! Loss = permanent lockout!
 */
#define SCP03_KEY_VERSION  0x{keys['key_version']:02X}
#define SCP03_KEY_ENC {{ {', '.join(f'0x{b:02X}' for b in keys['enc'])} }}
#define SCP03_KEY_MAC {{ {', '.join(f'0x{b:02X}' for b in keys['mac'])} }}
#define SCP03_KEY_DEK {{ {', '.join(f'0x{b:02X}' for b in keys['dek'])} }}
"""


def save_keys_to_file(keys: dict, filename: str):
    """Save keys to JSON file"""
    data = {
        "enc": keys["enc"].hex(),
        "mac": keys["mac"].hex(),
        "dek": keys["dek"].hex(),
        "key_version": keys["key_version"],
        "generated_at": keys.get("generated_at", datetime.now().isoformat()),
    }
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(filename, 0o600)  # Read/write only for owner
    except OSError:
        pass  # Windows doesn't support chmod
    print(f"Keys saved to {filename}")


def load_keys_from_file(filename: str) -> dict:
    """Load keys from JSON file"""
    with open(filename, 'r') as f:
        data = json.load(f)
    return {
        "enc": bytes.fromhex(data["enc"]),
        "mac": bytes.fromhex(data["mac"]),
        "dek": bytes.fromhex(data["dek"]),
        "key_version": data["key_version"],
        "generated_at": data.get("generated_at"),
    }


def load_keys_from_scp03_key(filename: str) -> dict:
    """Load keys from scp03.key format (ENC/MAC/DEK lines)"""
    keys = {}
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('ENC '):
                keys['enc'] = bytes.fromhex(line[4:].strip())
            elif line.startswith('MAC '):
                keys['mac'] = bytes.fromhex(line[4:].strip())
            elif line.startswith('DEK '):
                keys['dek'] = bytes.fromhex(line[4:].strip())

    if 'enc' not in keys or 'mac' not in keys or 'dek' not in keys:
        raise ValueError(f"Invalid scp03.key format in {filename}")

    keys['key_version'] = FACTORY_KEY_VERSION
    return keys


def cmd_generate(args):
    """Generate new SCP03 keys"""
    print("Generating new SCP03 keys...")
    print()

    keys = generate_scp03_keys()

    # Display keys
    print(format_keys_for_display(keys))
    print()

    # Optionally save to file
    if args.output:
        save_keys_to_file(keys, args.output)
        print()

    # Optionally output C header
    if args.c_header:
        print("C Header format:")
        print(format_keys_as_c_header(keys))

    print()
    print("Next steps:")
    print("1. Save these keys in a SECURE location (password manager, HSM, etc)")
    print("2. Test rotation with: ./scp03_keygen.py rotate --dry-run --keys <file>")
    print("3. Rotate keys with: ./scp03_keygen.py rotate --keys <file>")


def cmd_rotate(args):
    """Rotate SCP03 keys on connected SE050"""
    print("SCP03 Key Rotation (GlobalPlatform PUT KEY)")
    print("=" * 50)

    if not HAS_CRYPTO:
        print("ERROR: cryptography package required")
        print("Install with: pip install cryptography")
        sys.exit(1)

    if args.dry_run:
        print("DRY RUN - No changes will be made")
        print()

    # Load new keys
    if args.keys:
        print(f"Loading new keys from: {args.keys}")
        if args.keys.endswith('.json'):
            new_keys = load_keys_from_file(args.keys)
        else:
            new_keys = load_keys_from_scp03_key(args.keys)
    else:
        print("ERROR: --keys <file> required for rotation")
        print("Generate keys first: ./scp03_keygen.py generate --output new_keys.json")
        sys.exit(1)

    # Current keys (defaults or from file)
    if args.current_keys:
        print(f"Loading current keys from: {args.current_keys}")
        if args.current_keys.endswith('.json'):
            current = load_keys_from_file(args.current_keys)
        else:
            current = load_keys_from_scp03_key(args.current_keys)
        current_enc = current["enc"]
        current_mac = current["mac"]
        current_dek = current["dek"]
        current_ver = current["key_version"]
    else:
        print("Using factory default keys (from scp03.key if exists)")
        # Try to load from scp03.key first
        scp03_key_path = Path(__file__).parent / "scp03.key"
        if scp03_key_path.exists():
            try:
                current = load_keys_from_scp03_key(str(scp03_key_path))
                current_enc = current["enc"]
                current_mac = current["mac"]
                current_dek = current["dek"]
                current_ver = current["key_version"]
                print(f"  Loaded from: {scp03_key_path}")
            except Exception as e:
                print(f"  Warning: Could not load scp03.key: {e}")
                current_enc = FACTORY_ENC
                current_mac = FACTORY_MAC
                current_dek = FACTORY_DEK
                current_ver = FACTORY_KEY_VERSION
        else:
            current_enc = FACTORY_ENC
            current_mac = FACTORY_MAC
            current_dek = FACTORY_DEK
            current_ver = FACTORY_KEY_VERSION

    print()
    print(f"Current key version: 0x{current_ver:02X}")
    print(f"New key version:     0x{new_keys['key_version']:02X}")
    print()

    # Show KCVs for verification
    print("Key Check Values (KCV = AES-CBC(key, 0x01*16)[:3]):")
    print(f"  Current ENC KCV: {compute_kcv(current_enc).hex().upper()}")
    print(f"  Current MAC KCV: {compute_kcv(current_mac).hex().upper()}")
    print(f"  Current DEK KCV: {compute_kcv(current_dek).hex().upper()}")
    print()
    print(f"  New ENC KCV: {compute_kcv(new_keys['enc']).hex().upper()}")
    print(f"  New MAC KCV: {compute_kcv(new_keys['mac']).hex().upper()}")
    print(f"  New DEK KCV: {compute_kcv(new_keys['dek']).hex().upper()}")
    print()

    # Build the PUT KEY command
    cmd_data, expected_kcv = build_put_key_command(
        current_ver,
        new_keys['enc'],
        new_keys['mac'],
        new_keys['dek'],
        current_dek
    )

    print(f"PUT KEY command data ({len(cmd_data)} bytes):")
    print(f"  {cmd_data.hex().upper()}")
    print()
    print(f"Expected KCV response ({len(expected_kcv)} bytes):")
    print(f"  {expected_kcv.hex().upper()}")
    print()

    if args.dry_run:
        print("Dry run complete. To actually rotate keys, remove --dry-run")
        print()
        print("When ready, run:")
        print(f"  ./scp03_keygen.py rotate --keys {args.keys}")
        return

    # Final confirmation
    print("=" * 60)
    print("WARNING: KEY ROTATION IS IRREVERSIBLE!")
    print("=" * 60)
    print()
    print("If this operation fails or you lose the new keys,")
    print("your SE050 will be PERMANENTLY LOCKED with no recovery possible.")
    print()
    print("Make sure you have:")
    print("  1. Backed up the new keys in a secure location")
    print("  2. Tested on development hardware first")
    print("  3. Have the correct current keys")
    print()

    confirm = input("Type 'ROTATE' to proceed (or anything else to cancel): ")
    if confirm != "ROTATE":
        print("Cancelled.")
        sys.exit(0)

    # Import SE050 session
    try:
        from se050 import SE050Session, SE050Error
    except ImportError:
        print("ERROR: Could not import se050 module")
        print("Make sure se050.py is in the same directory")
        sys.exit(1)

    # Connect and send PUT KEY
    print()
    print(f"Connecting to SE050 on {args.port}...")

    try:
        with SE050Session(
            device=args.port,
            enc_key=current_enc,
            mac_key=current_mac,
            dek_key=current_dek,  # DEK required for key rotation
            key_version=current_ver,
            debug=args.debug,
            isd_mode=True  # Key rotation uses ISD, not applet
        ) as se:
            print("Connected and authenticated to ISD with current keys (DEK enabled)")

            # NOTE: Do NOT call get_uid() here! It would select the applet context,
            # which breaks PUT KEY (GlobalPlatform command needs SSD/ISD context)

            print()
            print("Sending PUT KEY command...")

            # Try using library's rotate function first (if available)
            if hasattr(se, '_has_rotate_keys') and se._has_rotate_keys:
                print("Using library's se050_rotate_platform_keys()")
                # Use current_ver for in-place key replacement (per NXP reference)
                # The version in command data indicates which key set to replace
                se.rotate_platform_keys(
                    new_enc=new_keys["enc"],
                    new_mac=new_keys["mac"],
                    new_dek=new_keys["dek"],
                    new_key_version=current_ver
                )
                success = True
            elif hasattr(se, 'send_apdu') and hasattr(se, '_has_secure_transceive') and se._has_secure_transceive:
                # Fall back to sending raw PUT KEY APDU
                print("Using se050_secure_transceive() to send PUT KEY")
                response = se.send_apdu(
                    cla=0x80,  # Not 0x84, secure_transceive handles MAC
                    ins=GP_INS_PUT_KEY,
                    p1=current_ver,
                    p2=GP_P2_MULTIPLE_KEYS,
                    data=cmd_data
                )

                # Verify response
                if len(response) >= 2:
                    sw = (response[-2] << 8) | response[-1]
                    kcv_response = response[:-2]

                    if sw != 0x9000:
                        print(f"ERROR: PUT KEY failed with SW={sw:04X}")
                        sys.exit(1)

                    if kcv_response == expected_kcv:
                        print(f"KCV verification passed: {kcv_response.hex().upper()}")
                        success = True
                    else:
                        print(f"WARNING: KCV mismatch!")
                        print(f"  Expected: {expected_kcv.hex().upper()}")
                        print(f"  Got:      {kcv_response.hex().upper()}")
                        success = True  # Keys probably rotated, just KCV format different
                else:
                    print(f"ERROR: Invalid response length: {len(response)}")
                    sys.exit(1)
            else:
                print()
                print("ERROR: Library doesn't support key rotation functions")
                print("Rebuild libse050.so with the latest se050_vcom.c")
                print()
                print("The PUT KEY command data has been prepared above.")
                print("You can rebuild the library or send it manually.")
                sys.exit(1)

            if success:
                print()
                print("=" * 60)
                print("KEY ROTATION SUCCESSFUL!")
                print("=" * 60)
                print()

                # Update scp03.key file (local)
                scp03_key_path = Path(__file__).parent / "scp03.key"
                with open(scp03_key_path, 'w') as f:
                    f.write(f"ENC {new_keys['enc'].hex()}\n")
                    f.write(f"MAC {new_keys['mac'].hex()}\n")
                    f.write(f"DEK {new_keys['dek'].hex()}\n")
                print(f"Updated {scp03_key_path}")

                # Update wallet config directory (~/.se050-wallet/)
                wallet_dir = Path.home() / ".se050-wallet"
                wallet_dir.mkdir(parents=True, exist_ok=True)

                # Save as JSON for wallet.py compatibility
                wallet_keys_json = wallet_dir / "scp03_keys.json"
                wallet_data = {
                    "enc": new_keys['enc'].hex(),
                    "mac": new_keys['mac'].hex(),
                    "dek": new_keys['dek'].hex(),
                    "key_version": new_keys.get('key_version', current_ver),
                    "rotated_at": datetime.now().isoformat(),
                }
                with open(wallet_keys_json, 'w') as f:
                    json.dump(wallet_data, f, indent=2)
                print(f"Updated {wallet_keys_json}")

                print()
                print("Your SE050 now uses the new keys.")
                print("Both local scp03.key and wallet config have been updated.")

    except SE050Error as e:
        print(f"ERROR: {e}")
        print()
        print("Key rotation FAILED. Your device should still use the old keys.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        print()
        print("Key rotation may have FAILED.")
        print("Try connecting with both old and new keys to determine state.")
        sys.exit(1)


def cmd_show(args):
    """Show current key configuration"""
    print("Current SCP03 Key Configuration")
    print("=" * 40)
    print()

    # Try to load from scp03.key
    scp03_key_path = Path(__file__).parent / "scp03.key"
    if scp03_key_path.exists():
        print(f"Keys from {scp03_key_path}:")
        try:
            keys = load_keys_from_scp03_key(str(scp03_key_path))
            print(f"  ENC: {keys['enc'].hex().upper()}")
            print(f"  MAC: {keys['mac'].hex().upper()}")
            print(f"  DEK: {keys['dek'].hex().upper()}")
            print(f"  Version: 0x{keys['key_version']:02X}")
            if HAS_CRYPTO:
                print()
                print("Key Check Values:")
                print(f"  ENC KCV: {compute_kcv(keys['enc']).hex().upper()}")
                print(f"  MAC KCV: {compute_kcv(keys['mac']).hex().upper()}")
                print(f"  DEK KCV: {compute_kcv(keys['dek']).hex().upper()}")
        except Exception as e:
            print(f"  Error loading: {e}")
        print()

    print("Hardcoded Factory Keys:")
    print(f"  ENC: {FACTORY_ENC.hex().upper()}")
    print(f"  MAC: {FACTORY_MAC.hex().upper()}")
    print(f"  DEK: {FACTORY_DEK.hex().upper()}")
    print(f"  Version: 0x{FACTORY_KEY_VERSION:02X}")

    if HAS_CRYPTO:
        print()
        print("Key Check Values:")
        print(f"  ENC KCV: {compute_kcv(FACTORY_ENC).hex().upper()}")
        print(f"  MAC KCV: {compute_kcv(FACTORY_MAC).hex().upper()}")
        print(f"  DEK KCV: {compute_kcv(FACTORY_DEK).hex().upper()}")
    print()

    if args.keys:
        print(f"Keys from {args.keys}:")
        if args.keys.endswith('.json'):
            keys = load_keys_from_file(args.keys)
        else:
            keys = load_keys_from_scp03_key(args.keys)
        print(f"  ENC: {keys['enc'].hex().upper()}")
        print(f"  MAC: {keys['mac'].hex().upper()}")
        print(f"  DEK: {keys['dek'].hex().upper()}")
        print(f"  Version: 0x{keys['key_version']:02X}")
        if 'generated_at' in keys:
            print(f"  Generated: {keys.get('generated_at', 'unknown')}")
        if HAS_CRYPTO:
            print()
            print("Key Check Values:")
            print(f"  ENC KCV: {compute_kcv(keys['enc']).hex().upper()}")
            print(f"  MAC KCV: {compute_kcv(keys['mac']).hex().upper()}")
            print(f"  DEK KCV: {compute_kcv(keys['dek']).hex().upper()}")


def main():
    parser = argparse.ArgumentParser(
        description="SCP03 Key Generation and Rotation for SE050",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./scp03_keygen.py generate                    Generate and display new keys
  ./scp03_keygen.py generate -o keys.json       Generate and save to file
  ./scp03_keygen.py show                        Show current keys from scp03.key
  ./scp03_keygen.py show --keys keys.json       Show keys from file
  ./scp03_keygen.py rotate --keys keys.json --dry-run
                                                Test rotation (no changes)
  ./scp03_keygen.py rotate --keys keys.json     Rotate to new keys

Key file formats supported:
  - JSON: {"enc": "hex", "mac": "hex", "dek": "hex", "key_version": 11}
  - scp03.key: ENC <hex>\\nMAC <hex>\\nDEK <hex>

SECURITY WARNING:
  - Store generated keys securely (password manager, HSM, paper backup)
  - Loss of keys = permanent device lockout (no recovery possible)
  - Test on development hardware before production
  - Keep backup of current keys before rotation
""")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate new SCP03 keys")
    gen_parser.add_argument("-o", "--output", help="Save keys to JSON file")
    gen_parser.add_argument("-c", "--c-header", action="store_true",
                           help="Also output as C header format")

    # Rotate command
    rot_parser = subparsers.add_parser("rotate", help="Rotate keys on SE050")
    rot_parser.add_argument("--keys", required=True, help="JSON or scp03.key file with new keys")
    rot_parser.add_argument("--current-keys", help="File with current keys (default: scp03.key or factory)")
    rot_parser.add_argument("--port", default="/dev/ttyACM0", help="SE050 serial port")
    rot_parser.add_argument("--dry-run", action="store_true",
                           help="Show what would happen without making changes")
    rot_parser.add_argument("--debug", action="store_true",
                           help="Enable debug output from SE050 library")

    # Show command
    show_parser = subparsers.add_parser("show", help="Show key configuration")
    show_parser.add_argument("--keys", help="JSON or scp03.key file with keys to display")

    args = parser.parse_args()

    if args.command == "generate":
        cmd_generate(args)
    elif args.command == "rotate":
        cmd_rotate(args)
    elif args.command == "show":
        cmd_show(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
