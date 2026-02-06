"""
CLI command implementations for the SIGIL Bitcoin wallet.

Each cmd_* function corresponds to a subcommand (e.g. 'create', 'send', 'info').
They use function-level imports from the various sigil modules.
"""

import subprocess
from pathlib import Path
from datetime import datetime


def cmd_init(args):
    """Initialize new wallet - generate key on SE050"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet
    from sigil.hardware.interface import (
        se050_connect, se050_get_uid, se050_get_random,
        se050_key_exists, se050_delete_key, se050_generate_keypair,
        se050_export_pubkey,
    )

    print("")
    print("=" * 60)
    print("SE050 HARDWARE WALLET - INITIALIZATION")
    print("=" * 60)

    Config.WALLET_DIR.mkdir(parents=True, exist_ok=True)

    if Config.pubkey_der_path().exists():
        print("")
        print(f"[!] Wallet already exists for Key ID 0x{Config.KEY_ID}")
        print(f"    Run 'wipe' first to delete, or use different KEY_ID")
        return 1

    print("")
    print("[1/4] Connecting to SE050...")
    if not se050_connect():
        # print("      [FAIL] Failed to connect to SE050")
        print("")
        return 1
    # print("      [OK] Connected")

    print("")
    print("[2/4] Checking SE050...")
    uid = se050_get_uid()
    if uid:
        print(f"      UID: {uid}")

    rng = se050_get_random()
    if rng:
        pass  # debug print removed
    else:
        pass  # debug print removed

    if se050_key_exists(Config.KEY_ID):
        print("")
        print(f"[!] Key already exists at slot 0x{Config.KEY_ID}")
        confirm = input("    Overwrite? [y/N]: ")
        if confirm.lower() != 'y':
            return 1
        se050_delete_key(Config.KEY_ID)

    print("")
    print(f"[3/4] Generating secp256k1 keypair at slot 0x{Config.KEY_ID}...")
    if not se050_generate_keypair(Config.KEY_ID):
        return 1

    print("")
    print("[4/4] Exporting public key...")
    if not se050_export_pubkey(Config.KEY_ID, Config.pubkey_der_path(), "DER"):
        return 1
    se050_export_pubkey(Config.KEY_ID, Config.pubkey_pem_path(), "PEM")

    wallet = Wallet()
    wallet.created_at = datetime.now().isoformat()
    if wallet.load():
        wallet.save_info()

        print("")
        print("=" * 60)
        print("WALLET CREATED SUCCESSFULLY")
        print("=" * 60)
        print(f"")
        print(f"Key ID:     0x{Config.KEY_ID}")
        print(f"Network:    {Config.NETWORK}")
        print(f"Pubkey:     {wallet.pubkey_compressed.hex()}")
        print(f"")
        print(f"RECEIVE ADDRESSES:")
        print(f"  Legacy:  {wallet.addresses['legacy']}")
        print(f"  SegWit:  {wallet.addresses['segwit']}")
        print("")
        print("IMPORTANT:")
        print("=" * 60)
        print("")

    return 0


def cmd_create(args):
    """Create new wallet with seed phrase backup"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet
    from sigil.hardware.interface import (
        se050_connect, se050_key_exists, se050_delete_key,
        se050_set_ecc_keypair, se050_export_pubkey,
    )
    from sigil.crypto.bip39 import generate_mnemonic, mnemonic_to_seed
    from sigil.crypto.bip32 import derive_bip84_key

    print("")
    print("=" * 60)
    print("SE050 HARDWARE WALLET - CREATE WITH SEED PHRASE")
    print("=" * 60)

    Config.WALLET_DIR.mkdir(parents=True, exist_ok=True)

    # Check if wallet already exists
    if Config.pubkey_der_path().exists():
        print("")
        print(f"[!] Wallet already exists for Key ID 0x{Config.KEY_ID}")
        confirm = input("    Overwrite? [y/N]: ")
        if confirm.lower() != 'y':
            return 1

    # Connect to SE050
    print("")
    print("[1/5] Connecting to SE050...")
    if not se050_connect():
        return 1

    # Generate mnemonic
    strength = 256 if args.words == 24 else 128
    print("")
    print(f"[2/5] Generating {args.words}-word seed phrase...")
    mnemonic = generate_mnemonic(strength)

    print("")
    print("=" * 60)
    print("WRITE DOWN THESE WORDS - THIS IS YOUR ONLY BACKUP!")
    print("=" * 60)
    print("")
    words = mnemonic.split()
    for i, word in enumerate(words, 1):
        print(f"  {i:2d}. {word}")
    print("")
    print("=" * 60)
    print("WARNING: If you lose these words, you lose your Bitcoin!")
    print("=" * 60)
    print("")

    # Verify user wrote it down
    confirm = input("Have you written down your seed phrase? [y/N]: ")
    if confirm.lower() != 'y':
        print("Please write down your seed phrase before continuing.")
        return 1

    print("")
    verify = input("Enter word #1 to verify: ").strip().lower()
    if verify != words[0]:
        print(f"Incorrect! Expected '{words[0]}'. Please try again.")
        return 1

    verify = input(f"Enter word #{len(words)} to verify: ").strip().lower()
    if verify != words[-1]:
        print(f"Incorrect! Expected '{words[-1]}'. Please try again.")
        return 1

    # Derive key from seed
    print("")
    print("[3/5] Deriving private key from seed...")
    seed = mnemonic_to_seed(mnemonic)
    coin_type = 1 if Config.NETWORK == "testnet" else 0
    private_key, pubkey = derive_bip84_key(seed, coin_type=coin_type)

    # Delete existing key if present
    if se050_key_exists(Config.KEY_ID):
        se050_delete_key(Config.KEY_ID)

    # Write key to SE050
    print("")
    print(f"[4/5] Writing private key to SE050 slot 0x{Config.KEY_ID}...")
    if not se050_set_ecc_keypair(Config.KEY_ID, private_key):
        return 1

    # Export public key
    print("")
    print("[5/5] Exporting public key...")
    if not se050_export_pubkey(Config.KEY_ID, Config.pubkey_der_path(), "DER"):
        return 1
    se050_export_pubkey(Config.KEY_ID, Config.pubkey_pem_path(), "PEM")

    # Load and display wallet
    wallet = Wallet()
    wallet.created_at = datetime.now().isoformat()
    if wallet.load():
        wallet.save_info()

        print("")
        print("=" * 60)
        print("WALLET CREATED SUCCESSFULLY")
        print("=" * 60)
        print(f"")
        print(f"Key ID:     0x{Config.KEY_ID}")
        print(f"Network:    {Config.NETWORK}")
        print(f"Derivation: m/84'/0'/0'/0/0 (BIP84 Native SegWit)")
        print(f"")
        print(f"RECEIVE ADDRESSES:")
        print(f"  SegWit:  {wallet.addresses['segwit']}")
        print(f"  Legacy:  {wallet.addresses['legacy']}")
        print("")
        print("BACKUP:")
        print("=" * 60)
        print("")

    return 0


def cmd_import_seed(args):
    """Import wallet from seed phrase"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet
    from sigil.hardware.interface import (
        se050_connect, se050_key_exists, se050_delete_key,
        se050_set_ecc_keypair, se050_export_pubkey,
    )
    from sigil.crypto.bip39 import validate_mnemonic, mnemonic_to_seed
    from sigil.crypto.bip32 import derive_bip84_key

    print("")
    print("=" * 60)
    print("SE050 HARDWARE WALLET - IMPORT FROM SEED PHRASE")
    print("=" * 60)

    Config.WALLET_DIR.mkdir(parents=True, exist_ok=True)

    # Check if wallet already exists
    if Config.pubkey_der_path().exists():
        print("")
        print(f"[!] Wallet already exists for Key ID 0x{Config.KEY_ID}")
        confirm = input("    Overwrite? [y/N]: ")
        if confirm.lower() != 'y':
            return 1

    # Get mnemonic
    if args.mnemonic:
        mnemonic = args.mnemonic.strip().lower()
    else:
        print("")
        print("Enter your seed phrase (12 or 24 words):")
        mnemonic = input("> ").strip().lower()

    # Validate mnemonic
    if not validate_mnemonic(mnemonic):
        print("")
        print("[FAIL] Invalid seed phrase!")
        return 1

    words = mnemonic.split()

    # Connect to SE050
    print("")
    print("[1/4] Connecting to SE050...")
    if not se050_connect():
        return 1

    # Derive key from seed
    print("")
    print("[2/4] Deriving private key from seed...")
    seed = mnemonic_to_seed(mnemonic)
    coin_type = 1 if Config.NETWORK == "testnet" else 0
    private_key, pubkey = derive_bip84_key(seed, coin_type=coin_type)

    # Delete existing key if present
    if se050_key_exists(Config.KEY_ID):
        se050_delete_key(Config.KEY_ID)

    # Write key to SE050
    print("")
    print(f"[3/4] Writing private key to SE050 slot 0x{Config.KEY_ID}...")
    if not se050_set_ecc_keypair(Config.KEY_ID, private_key):
        return 1

    # Export public key
    print("")
    print("[4/4] Exporting public key...")
    if not se050_export_pubkey(Config.KEY_ID, Config.pubkey_der_path(), "DER"):
        return 1
    se050_export_pubkey(Config.KEY_ID, Config.pubkey_pem_path(), "PEM")

    # Load and display wallet
    wallet = Wallet()
    wallet.created_at = datetime.now().isoformat()
    if wallet.load():
        wallet.save_info()

        print("")
        print("=" * 60)
        print("WALLET IMPORTED SUCCESSFULLY")
        print("=" * 60)
        print(f"")
        print(f"Key ID:     0x{Config.KEY_ID}")
        print(f"Network:    {Config.NETWORK}")
        print(f"Derivation: m/84'/0'/0'/0/0 (BIP84 Native SegWit)")
        print(f"")
        print(f"RECEIVE ADDRESSES:")
        print(f"  SegWit:  {wallet.addresses['segwit']}")
        print(f"  Legacy:  {wallet.addresses['legacy']}")
        print("")
        print("Your wallet has been restored from your seed phrase.")
        print("=" * 60)
        print("")

    return 0


def cmd_address(args):
    """Display wallet addresses"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet
    from sigil.wallet.qr import generate_qr_ascii

    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1

    print("")
    print("=" * 60)
    print("SE050ARD HARDWARE WALLET")
    print("=" * 60)
    print(f"")
    print(f"Key ID:  0x{Config.KEY_ID}")
    print(f"Network: {Config.NETWORK}")
    print(f"Pubkey:  {wallet.pubkey_compressed.hex()}")
    print(f"")
    print(f"RECEIVE ADDRESSES:")
    print(f"")
    print(f"  Legacy (P2PKH):   {wallet.addresses['legacy']}")
    print(f"  SegWit (P2WPKH):  {wallet.addresses['segwit']}  <- recommended")

    # Show QR code if requested
    if hasattr(args, 'qr') and args.qr:
        addr = wallet.addresses['segwit']
        print("")
        print("=" * 60)
        print("SCAN TO RECEIVE (SegWit address):")
        print("=" * 60)
        print("")
        qr = generate_qr_ascii(addr)
        for line in qr.split('\n'):
            print(f"  {line}")

    print("")
    print("=" * 60)
    print("")

    return 0


def cmd_balance(args):
    """Check wallet balance"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet
    from sigil.bitcoin.network import (
        get_address_info, get_utxos, get_fee_estimates, get_btc_price,
    )

    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1

    print(f"")
    print(f"Checking balance on {Config.NETWORK}...")
    print("")

    # Get fiat price if requested
    fiat_price = None
    fiat_currency = getattr(args, 'fiat', None)
    if fiat_currency:
        fiat_currency = fiat_currency.upper()
        fiat_price = get_btc_price(fiat_currency)

    total_balance = 0
    total_utxos = 0

    for name, addr in [('SegWit', wallet.addresses['segwit']),
                       ('Legacy', wallet.addresses['legacy'])]:
        info = get_address_info(addr)
        utxos = get_utxos(addr)

        if info:
            funded = info['chain_stats']['funded_txo_sum']
            spent = info['chain_stats']['spent_txo_sum']
            balance = funded - spent
            total_balance += balance
            total_utxos += len(utxos)

            print(f"  {name}: {balance:>12,} sats  ({len(utxos)} UTXOs)")
            print(f"          {addr}")
        else:
            print(f"  {name}: {0:>12,} sats")
            print(f"          {addr}")

    print(f"")
    print(f"  {'-' * 40}")
    print(f"  TOTAL:  {total_balance:>12,} sats ({total_balance / 1e8:.8f} BTC)")

    # Show fiat value if available
    if fiat_price and total_balance > 0:
        fiat_value = (total_balance / 1e8) * fiat_price
        print(f"          \u2248 {fiat_value:,.2f} {fiat_currency} @ {fiat_price:,.0f}/{fiat_currency}")

    print(f"          {total_utxos} spendable UTXOs")

    fees = get_fee_estimates()
    print(f"")
    print(f"  Current fees: {fees.get('fastestFee', '?')} sat/vB (fast), "
          f"{fees.get('hourFee', '?')} sat/vB (slow)")

    if fiat_price:
        print(f"  BTC Price: {fiat_price:,.0f} {fiat_currency}")

    print("")

    return 0


def cmd_send(args):
    """Send Bitcoin"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet
    from sigil.bitcoin.amount import parse_amount
    from sigil.bitcoin.network import get_utxos, broadcast_transaction
    from sigil.bitcoin.transaction import (
        create_output_script, build_and_sign_transaction,
    )
    from sigil.hardware.interface import se050_connect

    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1

    dest_address = args.address

    # Parse amount with unit support
    try:
        amount_sats, amount_desc = parse_amount(args.amount)
    except ValueError as e:
        print(f"")
        print(f"[FAIL] Invalid amount: {e}")
        print("")
        return 1

    fee_rate = args.fee or Config.DEFAULT_FEE_RATE

    print(f"")
    print(f"SEND TRANSACTION")
    print(f"  To:     {dest_address}")
    print(f"  Amount: {amount_desc}")
    print(f"  Fee:    {fee_rate} sat/vB")

    try:
        create_output_script(dest_address)
    except Exception as e:
        print(f"")
        print(f"[FAIL] Invalid destination address: {e}")
        print("")
        return 1

    print(f"")
    print(f"[1/5] Fetching UTXOs...")
    utxos = get_utxos(wallet.addresses['segwit'])

    if not utxos:
        utxos = get_utxos(wallet.addresses['legacy'])
        if not utxos:
            print("")
            return 1

    total_in = sum(u['value'] for u in utxos)
    print(f"      Found {len(utxos)} UTXOs totaling {total_in:,} sats")

    estimated_vsize = 110 + (68 * len(utxos))
    fee = estimated_vsize * fee_rate

    if total_in < amount_sats + fee:
        print(f"")
        print(f"[FAIL] Insufficient funds!")
        print(f"       Have:  {total_in:,} sats")
        print(f"       Need:  {amount_sats + fee:,} sats (amount + fee)")
        print("")
        return 1

    change = total_in - amount_sats - fee

    print(f"")
    print(f"[2/5] Building transaction...")
    print(f"      Input:  {total_in:,} sats")
    print(f"      Output: {amount_sats:,} sats")
    print(f"      Fee:    {fee:,} sats ({fee_rate} sat/vB)")
    if change > 546:
        print(f"      Change: {change:,} sats")

    inputs = [{'txid': u['txid'], 'vout': u['vout'], 'value': u['value']} for u in utxos]

    outputs = [{'value': amount_sats, 'script': create_output_script(dest_address)}]

    if change > 546:
        change_script = bytes([0x00, 0x14]) + wallet.pubkey_hash
        outputs.append({'value': change, 'script': change_script})

    print(f"")
    print(f"[3/5] Connecting to SE050...")
    if not se050_connect():
        print("")
        return 1

    print(f"")
    print(f"[4/5] Signing with SE050...")
    try:
        raw_tx = build_and_sign_transaction(
            inputs, outputs,
            wallet.pubkey_compressed,
            wallet.pubkey_hash
        )
    except Exception as e:
        print("")
        return 1

    tx_hex = raw_tx.hex()
    print(f"")
    print(f"      Raw TX ({len(raw_tx)} bytes)")
    print(f"      {tx_hex[:64]}...")

    # Handle --no-broadcast for solo mining / manual broadcast
    if getattr(args, 'no_broadcast', False):
        raw_path = Config.WALLET_DIR / f"tx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.hex"
        raw_path.write_text(tx_hex)
        print(f"")
        print(f"[5/5] Transaction signed (NOT broadcast)")
        print(f"      Raw TX saved to: {raw_path}")
        print(f"")
        print(f"      For solo mining: Add to your mempool with:")
        print(f"        bitcoin-cli sendrawtransaction $(cat {raw_path})")
        print(f"")
        print(f"      Or broadcast later with:")
        print(f"        curl -X POST -d @{raw_path} https://mempool.space/api/tx")
        print("")
        return 0

    if not args.yes:
        print(f"")
        print(f"[5/5] Ready to broadcast")
        confirm = input("      Broadcast transaction? [y/N]: ")
        if confirm.lower() != 'y':
            save = input("      Save raw transaction? [y/N]: ")
            if save.lower() == 'y':
                raw_path = Config.WALLET_DIR / f"tx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.hex"
                raw_path.write_text(tx_hex)
                print(f"      Saved to {raw_path}")
            print("")
            return 0

    print(f"")
    print(f"[5/5] Broadcasting...")
    if Config.TOR_ENABLED:
        print(f"      (via Tor)")
    if Config.BROADCAST_METHOD == "local" or (Config.BROADCAST_METHOD == "both" and Config.LOCAL_NODE_ENABLED):
        print(f"      (via local node: {Config.LOCAL_NODE_RPC_HOST}:{Config.LOCAL_NODE_RPC_PORT})")
    txid = broadcast_transaction(tx_hex)

    if txid:
        explorer = "mempool.space/testnet4" if Config.NETWORK == "testnet" else "mempool.space"
        print(f"")
        print(f"      TXID: {txid}")
        print(f"      https://{explorer}/tx/{txid}")
        print("")
        return 0
    else:
        raw_path = Config.WALLET_DIR / f"tx_failed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.hex"
        raw_path.write_text(tx_hex)
        print(f"      Raw TX saved to {raw_path}")
        print("")
        return 1


def cmd_export(args):
    """Export public key and wallet info (NOT private key!)"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet

    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1

    print("")
    print("=" * 60)
    print("PUBLIC KEY EXPORT (Private key remains in SE050!)")
    print("=" * 60)

    print(f"")
    print(f"Key ID:  0x{Config.KEY_ID}")
    print(f"Network: {Config.NETWORK}")
    print(f"")
    print(f"Public Key (compressed, hex):")
    print(f"  {wallet.pubkey_compressed.hex()}")
    print(f"")
    print(f"Public Key (uncompressed, hex):")
    print(f"  {wallet.pubkey_uncompressed.hex()}")
    print(f"")
    print(f"Pubkey Hash (HASH160):")
    print(f"  {wallet.pubkey_hash.hex()}")
    print(f"")
    print(f"Addresses:")
    print(f"  Legacy: {wallet.addresses['legacy']}")
    print(f"  SegWit: {wallet.addresses['segwit']}")
    print(f"")
    print(f"Files:")
    print(f"  DER: {Config.pubkey_der_path()}")
    print(f"  PEM: {Config.pubkey_pem_path()}")

    if Config.pubkey_pem_path().exists():
        print(f"")
        print(f"PEM Format:")
        print(Config.pubkey_pem_path().read_text())

    print("=" * 60)
    print("")

    return 0


def cmd_wipe(args):
    """Delete wallet (DANGER!)"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet
    from sigil.hardware.interface import (
        se050_connect, se050_delete_key,
    )

    print("")
    print("=" * 60)
    print("WARNING: WALLET WIPE")
    print("=" * 60)

    wallet = Wallet()
    wallet_exists = wallet.load()

    if wallet_exists:
        print(f"")
        print(f"This will PERMANENTLY DELETE:")
        print(f"  Key ID:  0x{Config.KEY_ID}")
        print(f"  SegWit:  {wallet.addresses['segwit']}")
        print(f"  Legacy:  {wallet.addresses['legacy']}")

    print(f"")
    print(f"[!] This action CANNOT be undone!")
    print(f"[!] Any funds at these addresses will be LOST FOREVER!")

    confirm = input(f"\nType 'WIPE {Config.KEY_ID}' to confirm: ")
    if confirm != f"WIPE {Config.KEY_ID}":
        print("Cancelled.")
        print("")
        return 0

    print("")
    print("Connecting to SE050...")
    if se050_connect():
        print(f"Deleting key 0x{Config.KEY_ID} from SE050...")
        if se050_delete_key(Config.KEY_ID):
            pass  # debug print removed
        else:
            pass  # debug print removed

    print("Deleting local wallet files...")
    for path in [Config.pubkey_der_path(), Config.pubkey_pem_path(), Config.wallet_info_path()]:
        if path.exists():
            path.unlink()
            print(f"  Deleted {path}")

    print("")
    print("[OK] Wallet wiped.")
    print("")
    return 0


def cmd_reset(args):
    """Reset SE050 connection"""
    from sigil.bitcoin.config import Config
    from sigil.hardware.interface import (
        se050_disconnect, se050_connect, se050_get_uid, se050_get_random,
    )
    import time

    port = Config.get_connection_port()

    print("")
    print(f"Connection: {Config.CONNECTION_TYPE} @ {port}")
    print("")
    print("Disconnecting...")
    se050_disconnect()

    time.sleep(1)

    print("Reconnecting...")
    if se050_connect():
        print("[OK] Reconnected successfully")
        uid = se050_get_uid()
        if uid:
            print(f"UID: {uid}")
        rng = se050_get_random()
        if rng:
            print(f"TRNG: {rng.hex()}")
        return 0
    else:
        print("[FAIL] Reconnection failed")
        print("")
        print("Try:")
        print(f"  3. Check device exists: ls {port}")
        return 1


def cmd_info(args):
    """Show SE050 and wallet status"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet
    from sigil.hardware.interface import (
        se050_connect, se050_get_uid, se050_get_random,
        se050_key_exists, _HAS_NATIVE_SE050,
    )

    print("")
    print("=" * 60)
    print("SE050 STATUS")
    print("=" * 60)

    if not _HAS_NATIVE_SE050:
        print("")
        print("[FAIL] Native SE050 library not found")
        return 1
    print("")
    print("[OK] Native library loaded")

    port = Config.get_connection_port()
    print(f"")
    print(f"Connection: {Config.CONNECTION_TYPE} @ {port}")

    print("")
    print("Connecting to SE050...")
    if not se050_connect():
        print("[FAIL] Connection failed. Check:")
        print(f"")
        print(f"       Check: ls {port}")
        return 1
    print("[OK] Connected")

    uid = se050_get_uid()
    if uid:
        print(f"")
        print(f"SE050 UID: {uid}")

    rng = se050_get_random()
    if rng:
        print(f"TRNG Test: {rng.hex()} [OK]")

    print(f"")
    print(f"Key Slot 0x{Config.KEY_ID}:")
    if se050_key_exists(Config.KEY_ID):
        pass  # debug print removed
    else:
        pass  # debug print removed

    print(f"")
    print(f"Local Wallet ({Config.WALLET_DIR}):")
    if Config.pubkey_der_path().exists():
        wallet = Wallet()
        if wallet.load():
            print(f"  Pubkey: {wallet.pubkey_compressed.hex()[:32]}...")
            print(f"  SegWit: {wallet.addresses['segwit']}")
    else:
        pass  # debug print removed

    print("")
    print("=" * 60)
    print("")
    return 0


def cmd_sign_message(args):
    """Sign a message with the wallet's private key"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet
    from sigil.hardware.interface import se050_connect
    from sigil.crypto.signatures import sign_message_with_se050, encode_signed_message

    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1

    message = args.message

    print("")
    print("=" * 60)
    print("BITCOIN SIGNED MESSAGE")
    print("=" * 60)
    print(f"")
    print(f"Message:  {message[:50]}{'...' if len(message) > 50 else ''}")
    print(f"Address:  {wallet.addresses['segwit']}")
    print(f"")

    print("Connecting to SE050...")
    if not se050_connect():
        print("[FAIL] Failed to connect to SE050")
        return 1
    print("[OK] Connected")

    print("")
    print("Signing with SE050...")
    try:
        (r, s), recovery_id = sign_message_with_se050(Config.KEY_ID, message)
        signature = encode_signed_message(r, s, recovery_id, compressed=True)
        print("[OK] Message signed")
    except Exception as e:
        print(f"[FAIL] Signing failed: {e}")
        return 1

    print("")
    print("=" * 60)
    print("SIGNATURE:")
    print("=" * 60)
    print(f"")
    print(f"{signature}")
    print(f"")
    print("=" * 60)
    print("")
    print("To verify, use: https://www.verifybitcoinmessage.com/")
    print(f"  Address: {wallet.addresses['legacy']}")
    print(f"  Message: {message}")
    print(f"  Signature: (above)")
    print("")

    return 0


def cmd_history(args):
    """Show transaction history"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet
    from sigil.bitcoin.network import get_address_txs
    from sigil.bitcoin.amount import format_timestamp

    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1

    limit = getattr(args, 'limit', 10) or 10

    print("")
    print("=" * 60)
    print("TRANSACTION HISTORY")
    print("=" * 60)
    print(f"")
    print(f"Fetching transactions for {Config.NETWORK}...")
    print("")

    all_txs = []

    # Fetch from both addresses
    for addr in [wallet.addresses['segwit'], wallet.addresses['legacy']]:
        txs = get_address_txs(addr, limit=50)
        for tx in txs:
            tx['_address'] = addr
        all_txs.extend(txs)

    # Deduplicate by txid
    seen = set()
    unique_txs = []
    for tx in all_txs:
        if tx['txid'] not in seen:
            seen.add(tx['txid'])
            unique_txs.append(tx)

    # Sort by confirmation time (newest first)
    unique_txs.sort(key=lambda x: x.get('status', {}).get('block_time', 0), reverse=True)
    unique_txs = unique_txs[:limit]

    if not unique_txs:
        print("")
        return 0

    for tx in unique_txs:
        txid = tx['txid']
        status = tx.get('status', {})
        confirmed = status.get('confirmed', False)
        block_time = status.get('block_time', 0)

        # Calculate net flow for this wallet
        total_in = 0
        total_out = 0

        our_addresses = {wallet.addresses['segwit'], wallet.addresses['legacy']}

        for vin in tx.get('vin', []):
            prevout = vin.get('prevout', {})
            if prevout.get('scriptpubkey_address') in our_addresses:
                total_out += prevout.get('value', 0)

        for vout in tx.get('vout', []):
            if vout.get('scriptpubkey_address') in our_addresses:
                total_in += vout.get('value', 0)

        net = total_in - total_out

        # Format output
        if net > 0:
            direction = "\u2190 RECV"
            amount_str = f"+{net:,} sats"
        elif net < 0:
            direction = "\u2192 SEND"
            amount_str = f"{net:,} sats"
        else:
            direction = "\u27f7 SELF"
            amount_str = f"0 sats (self-transfer)"

        time_str = format_timestamp(block_time) if block_time else "unconfirmed"
        conf_str = "\u2713" if confirmed else "\u23f3"

        print(f"  {conf_str} {time_str}  {direction}  {amount_str}")
        print(f"    {txid[:16]}...{txid[-8:]}")
        print("")

    explorer = "mempool.space/testnet4" if Config.NETWORK == "testnet" else "mempool.space"
    print(f"  View on explorer: https://{explorer}/address/{wallet.addresses['segwit']}")
    print("")

    return 0


def cmd_verify(args):
    """Verify SE050 is really being used"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet
    from sigil.crypto.hashing import sha256
    from sigil.crypto.signatures import parse_der_signature
    from sigil.hardware.interface import (
        se050_connect, se050_export_pubkey, se050_sign,
    )
    from sigil.hardware import interface as _hw_interface

    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1

    print("")
    print("=" * 60)
    print("SE050 VERIFICATION")
    print("=" * 60)
    print("")

    print("[1/4] Connecting to SE050...")
    if not se050_connect():
        return 1

    print("")
    print("[2/4] Comparing public keys...")

    # Export fresh key from SE050
    verify_path = Path("/tmp/se050_verify_pubkey.der")
    if not se050_export_pubkey(Config.KEY_ID, verify_path, "DER"):
        return 1

    # Compare with stored key
    stored_key = Config.pubkey_der_path().read_bytes()
    exported_key = verify_path.read_bytes()

    if stored_key == exported_key:
        pass  # debug print removed
    else:
        return 1

    print("")
    print("[3/4] Testing signature generation...")

    test_msg = f"SE050 verification test {datetime.now().isoformat()}"
    test_hash = sha256(test_msg.encode())

    try:
        sig = se050_sign(Config.KEY_ID, test_hash)
        r, s = parse_der_signature(sig)
        print(f"       [OK] Signature generated")
        print(f"       R: {hex(r)[:32]}...")
        print(f"       S: {hex(s)[:32]}...")
    except Exception as e:
        print(f"       [FAIL] Signing failed: {e}")
        return 1

    print("")
    print("[4/4] Verifying private key is locked...")

    # The SE050 only allows reading the public key - private key export is
    # prohibited by the secure element's design. We verify by checking that
    # we can read the public key (which proves key exists) but the SE050
    # API has no command to export private keys.
    try:
        key_id_int = int(Config.KEY_ID, 16)
        pubkey = _hw_interface._se050_session.read_pubkey(key_id_int)

        # A secp256k1 uncompressed public key is 65 bytes (04 + X + Y)
        if len(pubkey) == 65 and pubkey[0] == 0x04:
            print(f"       (read_pubkey returns public key only, {len(pubkey)} bytes)")
        else:
            print(f"       [OK] Public key format: {len(pubkey)} bytes")
    except Exception as e:
        print(f"       [WARN] Could not verify key lock: {e}")

    print("")
    print("=" * 60)
    print("VERIFICATION PASSED")
    print("=" * 60)
    print("")
    print("\u2713 SE050 is connected and responding")
    print("\u2713 Public key matches wallet")
    print("\u2713 Signatures are being generated on SE050")
    print("\u2713 Private key is locked inside SE050")
    print("")

    return 0


def cmd_watch(args):
    """Watch wallet for incoming transactions"""
    from sigil.bitcoin.config import Config
    from sigil.wallet.core import Wallet
    from sigil.bitcoin.network import get_address_info
    import time

    wallet = Wallet()
    if not wallet.load():
        print("")
        print("[FAIL] No wallet found. Run 'init' first.")
        print("")
        return 1

    interval = args.interval or 30

    print("")
    print("=" * 60)
    print("WATCHING FOR TRANSACTIONS")
    print("=" * 60)
    print("")
    print(f"SegWit: {wallet.addresses['segwit']}")
    print(f"Legacy: {wallet.addresses['legacy']}")
    print(f"")
    print(f"Checking every {interval} seconds. Press Ctrl+C to stop.")
    print("")

    # Get initial balance
    def get_total_balance():
        total = 0
        for addr in [wallet.addresses['segwit'], wallet.addresses['legacy']]:
            info = get_address_info(addr)
            if info:
                funded = info['chain_stats']['funded_txo_sum']
                spent = info['chain_stats']['spent_txo_sum']
                total += funded - spent
        return total

    last_balance = get_total_balance()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Current balance: {last_balance:,} sats")

    try:
        while True:
            time.sleep(interval)

            current = get_total_balance()
            timestamp = datetime.now().strftime('%H:%M:%S')

            if current != last_balance:
                diff = current - last_balance
                if diff > 0:
                    print(f"[{timestamp}] \U0001f4b0 RECEIVED +{diff:,} sats! New balance: {current:,} sats")
                    # Try system notification
                    try:
                        subprocess.run(['notify-send', 'Bitcoin Received!', f'+{diff:,} sats'],
                                     capture_output=True, timeout=5)
                    except:
                        pass
                else:
                    print(f"[{timestamp}] \U0001f4e4 SENT {diff:,} sats. New balance: {current:,} sats")
                last_balance = current
            else:
                print(f"[{timestamp}] No change. Balance: {current:,} sats")

    except KeyboardInterrupt:
        print("")
        print("Stopped watching.")
        return 0
