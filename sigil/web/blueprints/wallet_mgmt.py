"""
SIGIL Web - Wallet Management Blueprint

Routes: /create, /import, /verify, /key-slot, /generate-key, /check-slot,
        /export-pubkey, /wipe
"""

import json
from datetime import datetime
from pathlib import Path

from flask import (
    Blueprint, request, redirect, url_for, flash, session, render_template
)

from sigil.bitcoin.config import Config
from sigil.wallet.core import Wallet
from sigil.wallet.slots import load_locked_slots, scan_all_slots, scan_all_slots_offline
from sigil.hardware.interface import (
    se050_key_exists, se050_get_uid, se050_get_random,
    se050_export_pubkey, se050_delete_key,
    se050_generate_keypair, se050_set_ecc_keypair
)
from sigil.bitcoin.addresses import compress_pubkey, parse_der_pubkey, derive_addresses
from sigil.crypto.bip39 import generate_mnemonic, validate_mnemonic, mnemonic_to_seed
from sigil.crypto.bip32 import derive_bip84_key
from sigil.web.helpers import (
    SIGIL_VERSION, SIGIL_DIR, get_connection_status,
    login_required, signing_pin_enabled, check_signing_pin
)
from sigil.web.security import csrf_required, _validate_key_slot
from sigil.web.session_mgmt import se050_session

wallet_mgmt_bp = Blueprint('wallet_mgmt_bp', __name__)


@wallet_mgmt_bp.route('/create', methods=['GET', 'POST'])
@login_required
@csrf_required
def create_wallet():
    import random

    step = 1
    mnemonic = None
    verify_word = random.randint(1, 24)

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'generate':
            # Check signing PIN if enabled
            signing_pin = request.form.get('signing_pin', '')
            if signing_pin_enabled() and not check_signing_pin(signing_pin):
                flash('Invalid signing PIN', 'error')
                return redirect(url_for('wallet_mgmt_bp.create_wallet'))
            # Generate new mnemonic
            try:
                mnemonic = generate_mnemonic(strength=256)  # 24 words
                step = 2
                verify_word = random.randint(1, 24)
            except Exception as e:
                flash(f'Error generating seed: {str(e)}', 'error')

        elif action == 'confirm':
            mnemonic = request.form.get('mnemonic', '')
            verify_input = request.form.get('verify', '').strip().lower()
            verify_word = int(request.form.get('verify_word', 1))
            verify_idx = verify_word - 1

            words = mnemonic.split()
            if verify_idx < len(words) and verify_input == words[verify_idx].lower():
                # Verification passed - create wallet
                try:
                    seed = mnemonic_to_seed(mnemonic)
                    privkey, chaincode = derive_bip84_key(seed)

                    pubkey_path = Config.pubkey_der_path()
                    pubkey_path.parent.mkdir(parents=True, exist_ok=True)

                    with se050_session():
                        set_ok = se050_set_ecc_keypair(Config.KEY_ID, privkey)
                        if not set_ok:
                            flash('Failed to write key to SE050', 'error')
                            step = 2
                        else:
                            export_ok = se050_export_pubkey(Config.KEY_ID, pubkey_path, "DER")
                            if export_ok:
                                # Save wallet info
                                info = {'created_at': datetime.now().isoformat(), 'network': Config.NETWORK}
                                Config.wallet_info_path().write_text(json.dumps(info))
                                step = 3
                                flash('Wallet created successfully!', 'success')
                            else:
                                # Check if file was created anyway
                                if pubkey_path.exists():
                                    info = {'created_at': datetime.now().isoformat(), 'network': Config.NETWORK}
                                    Config.wallet_info_path().write_text(json.dumps(info))
                                    step = 3
                                    flash('Wallet created (pubkey saved)', 'success')
                                else:
                                    flash(f'Failed to export pubkey to {pubkey_path}', 'error')
                                    step = 2
                except Exception as e:
                    import traceback
                    flash(f'Error: {str(e)} - {traceback.format_exc()[:200]}', 'error')
                    step = 2
            else:
                flash('Incorrect word. Please try again.', 'error')
                step = 2

    return render_template(
        'create_wallet.html',
        title='Create Wallet', connection_status=get_connection_status(), slot_num=int(Config.KEY_ID, 16) & 0xFF, key_slot=Config.KEY_ID, active='', version=SIGIL_VERSION,
        step=step, mnemonic=mnemonic, verify_word=verify_word,
        pin_required=signing_pin_enabled(), session=session
    )


@wallet_mgmt_bp.route('/import', methods=['GET', 'POST'])
@login_required
@csrf_required
def import_wallet():
    error = None

    if request.method == 'POST':
        mnemonic = request.form.get('mnemonic', '').strip().lower()

        # Check signing PIN if enabled
        signing_pin = request.form.get('signing_pin', '')
        if signing_pin_enabled() and not check_signing_pin(signing_pin):
            error = 'Invalid signing PIN'
        elif not validate_mnemonic(mnemonic):
            error = 'Invalid seed phrase. Check spelling and word order.'
        else:
            try:
                seed = mnemonic_to_seed(mnemonic)
                privkey, chaincode = derive_bip84_key(seed)

                pubkey_path = Config.pubkey_der_path()
                pubkey_path.parent.mkdir(parents=True, exist_ok=True)

                with se050_session():
                    se050_set_ecc_keypair(Config.KEY_ID, privkey)
                    export_ok = se050_export_pubkey(Config.KEY_ID, pubkey_path, "DER")

                if export_ok:
                    # Save wallet info
                    info = {'created_at': datetime.now().isoformat(), 'network': Config.NETWORK}
                    Config.wallet_info_path().write_text(json.dumps(info))
                    flash('Wallet imported successfully!', 'success')
                    return redirect(url_for('dashboard_bp.dashboard'))
                else:
                    error = 'Failed to export public key from SE050'
            except Exception as e:
                error = f'Error importing wallet: {str(e)}'

    return render_template(
        'import_wallet.html',
        title='Import Wallet', connection_status=get_connection_status(), active='', version=SIGIL_VERSION,
        error=error, pin_required=signing_pin_enabled(), session=session
    )


@wallet_mgmt_bp.route('/verify')
@login_required
def verify_se050():
    connected = False
    uid = ""
    key_exists = False
    random_bytes = ""
    pubkey = ""
    slots = []

    try:
        with se050_session():
            uid = se050_get_uid()
            if uid:
                connected = True

            key_exists = se050_key_exists(Config.KEY_ID)

            rand = se050_get_random(16)
            if rand:
                random_bytes = rand.hex()

            # Scan slots while SE050 is connected
            slots = scan_all_slots()
    except Exception:
        pass

    # If SE050 failed, still show slots (without key status)
    if not slots:
        slots = scan_all_slots_offline()

    try:
        if key_exists:
            # Read from saved pubkey file
            pubkey_path = Config.pubkey_der_path()
            if pubkey_path.exists():
                pubkey = pubkey_path.read_bytes().hex()
    except Exception:
        pass

    try:
        current_slot_num = int(Config.KEY_ID, 16) & 0xFF
    except:
        current_slot_num = 0

    return render_template(
        'verify.html',
        title='Slots', active='verify', connection_status=get_connection_status(), slots=slots, current_slot_num=current_slot_num, version=SIGIL_VERSION,
        connected=connected, uid=uid, key_slot=Config.KEY_ID,
        key_exists=key_exists, random_bytes=random_bytes, pubkey=pubkey,
        session=session
    )


@wallet_mgmt_bp.route('/key-slot', methods=['GET', 'POST'])
@login_required
@csrf_required
def change_key_slot():
    if request.method == "GET":
        return redirect(url_for("wallet_mgmt_bp.verify_se050"))
    new_slot = request.form.get('key_slot', '').strip().upper()
    if new_slot:
        if not _validate_key_slot(new_slot):
            flash('Invalid key slot (must be 0x20000000-0x7FFFFFFF)', 'error')
            return redirect(url_for('wallet_mgmt_bp.verify_se050'))
        try:
            Config.KEY_ID = new_slot
            # Save to config file
            keyslot_file = SIGIL_DIR / 'keyslot.conf'
            keyslot_file.write_text(new_slot)
            # Cache pubkey if key exists in this slot
            try:
                with se050_session():
                    if se050_key_exists(new_slot):
                        pubkey_path = Config.pubkey_der_path()
                        pubkey_path.parent.mkdir(parents=True, exist_ok=True)
                        se050_export_pubkey(new_slot, pubkey_path, "DER")
            except:
                pass
            flash(f'Switched to key slot 0x{new_slot}', 'success')
        except ValueError:
            flash('Invalid key slot (must be hex)', 'error')
    return redirect(url_for('wallet_mgmt_bp.verify_se050'))


@wallet_mgmt_bp.route('/generate-key', methods=['GET', 'POST'])
@login_required
@csrf_required
def generate_key():
    if request.method == "GET":
        return redirect(url_for("wallet_mgmt_bp.verify_se050"))
    # Check signing PIN if enabled
    signing_pin = request.form.get('signing_pin', '')
    if signing_pin_enabled() and not check_signing_pin(signing_pin):
        flash('Invalid signing PIN', 'error')
        return redirect(url_for('wallet_mgmt_bp.verify_se050'))
    try:
        pubkey_path = Config.pubkey_der_path()
        pubkey_path.parent.mkdir(parents=True, exist_ok=True)

        with se050_session():
            se050_generate_keypair(Config.KEY_ID)
            export_ok = se050_export_pubkey(Config.KEY_ID, pubkey_path, "DER")

        flash(f'Key generated in slot 0x{Config.KEY_ID}', 'success')
        if export_ok:
            flash('Public key exported', 'success')
        else:
            flash('Warning: Failed to export public key', 'warning')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    return redirect(url_for('wallet_mgmt_bp.verify_se050'))


@wallet_mgmt_bp.route('/check-slot', methods=['GET', 'POST'])
@login_required
@csrf_required
def check_slot():
    if request.method == "GET":
        return redirect(url_for("wallet_mgmt_bp.verify_se050"))
    try:
        with se050_session():
            exists = se050_key_exists(Config.KEY_ID)
        if exists:
            flash(f'Key EXISTS in slot 0x{Config.KEY_ID}', 'success')
        else:
            flash(f'No key in slot 0x{Config.KEY_ID}', 'warning')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    return redirect(url_for('wallet_mgmt_bp.verify_se050'))


@wallet_mgmt_bp.route('/export-pubkey')
@login_required
def export_pubkey():
    wallet = Wallet()
    wallet.load()

    pubkey_hex = ""
    pubkey_der = ""
    addresses = {}

    if wallet.pubkey_compressed:
        pubkey_hex = wallet.pubkey_compressed.hex()
    if wallet.pubkey_uncompressed:
        pubkey_der = wallet.pubkey_uncompressed.hex()
    if wallet.addresses:
        addresses = wallet.addresses

    return render_template(
        'export_pubkey.html',
        title='Export Public Key', active='', version=SIGIL_VERSION,
        pubkey_hex=pubkey_hex, addresses=addresses, session=session
    )


@wallet_mgmt_bp.route('/wipe', methods=['GET', 'POST'])
@login_required
@csrf_required
def wipe_key():
    if request.method == 'POST':
        confirm = request.form.get('confirm', '').strip().upper()
        signing_pin = request.form.get('signing_pin', '')
        # Check signing PIN if enabled
        if signing_pin_enabled() and not check_signing_pin(signing_pin):
            flash('Invalid signing PIN', 'error')
            return redirect(url_for('wallet_mgmt_bp.wipe_key'))
        if confirm == 'WIPE':
            try:
                with se050_session():
                    se050_delete_key(Config.KEY_ID)

                # Delete local files
                for path in [Config.pubkey_der_path(), Config.pubkey_pem_path(), Config.wallet_info_path()]:
                    if path.exists():
                        path.unlink()

                flash('Key wiped from SE050 and local files deleted', 'warning')
                return redirect(url_for('dashboard_bp.dashboard'))
            except Exception as e:
                flash(f'Error: {str(e)}', 'error')
        else:
            flash('Confirmation failed. Type WIPE to confirm.', 'error')

    # Show confirmation page
    return render_template(
        'wipe.html',
        title='Wipe Wallet', connection_status=get_connection_status(), active='', version=SIGIL_VERSION,
        key_slot=Config.KEY_ID, pin_required=signing_pin_enabled(), session=session
    )
