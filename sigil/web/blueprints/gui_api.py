"""
SIGIL Web - Desktop GUI JSON API Blueprint

All /api/gui/* endpoints for the desktop GUI client.

Routes: /api/gui/status, /api/gui/history, /api/gui/logs/<log_type>,
        /api/gui/sign, /api/gui/tumbler, /api/gui/tumbler/start,
        /api/gui/tumbler/cancel, /api/gui/tumbler/cleanup,
        /api/gui/send/prepare, /api/gui/send/broadcast,
        /api/gui/fees, /api/gui/balance
"""

from datetime import datetime
from pathlib import Path

from flask import Blueprint, request, jsonify

from sigil.bitcoin.config import Config
from sigil.wallet.core import Wallet
from sigil.wallet.slots import load_locked_slots
from sigil.bitcoin.network import (
    get_utxos, get_address_txs, get_fee_estimates, get_btc_price,
    broadcast_transaction
)
from sigil.bitcoin.transaction import build_and_sign_transaction, create_output_script
from sigil.bitcoin.addresses import compress_pubkey, parse_der_pubkey, derive_addresses
from sigil.crypto.hashing import hash160
from sigil.crypto.signatures import sign_message_with_se050, encode_signed_message
from sigil.hardware.interface import se050_export_pubkey
from sigil.hardware.session import SE050Session
from sigil.hardware.constants import SE050_CURVE_SECP256K1
from sigil.privacy.tumbler import (
    TumbleState, DELAY_PRESETS, find_available_slots,
    generate_job_id, start_tumbler_monitor
)
from sigil.web.helpers import (
    login_required, signing_pin_enabled, check_signing_pin
)
from sigil.web.security import (
    _validate_bitcoin_address, _validate_fee_rate, HONEYPOT_LOG
)
from sigil.web.session_mgmt import se050_session

gui_api_bp = Blueprint('gui_api_bp', __name__)


@gui_api_bp.route('/api/gui/status')
@login_required
def api_gui_status():
    """GUI status endpoint - returns JSON"""
    try:
        wallet = Wallet()
        wallet.load()

        balance_sats = 0
        address = wallet.addresses.get('segwit', '') if wallet.addresses else ''

        if address:
            utxos = get_utxos(address)
            if utxos:
                for utxo in utxos:
                    balance_sats += utxo.get('value', 0)

        balance_btc = balance_sats / 100_000_000
        price = get_btc_price() or 0
        usd_value = balance_btc * price if price else 0

        return jsonify({
            'balance_sats': balance_sats,
            'balance_btc': f'{balance_btc:.8f}',
            'usd_value': f'{usd_value:.2f}',
            'address': address,
            'price': price
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@gui_api_bp.route('/api/gui/history')
@login_required
def api_gui_history():
    """GUI history endpoint - returns JSON"""
    try:
        wallet = Wallet()
        wallet.load()
        address = wallet.addresses.get('segwit', '') if wallet.addresses else ''

        if not address:
            return jsonify({'txs': []})

        txs = get_address_txs(address) or []
        result = []
        for tx in txs[:50]:
            result.append({
                'txid': tx.get('txid', ''),
                'confirmed': tx.get('status', {}).get('confirmed', False),
                'block_height': tx.get('status', {}).get('block_height'),
                'value': sum(v.get('value', 0) for v in tx.get('vout', []) if v.get('scriptpubkey_address') == address)
            })
        return jsonify({'txs': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@gui_api_bp.route('/api/gui/logs/<log_type>')
@login_required
def api_gui_logs(log_type='honeypot'):
    """GUI logs endpoint - returns JSON"""
    if log_type == 'access':
        log_path = '/var/log/sigil/access.log'
    elif log_type == 'error':
        log_path = '/var/log/sigil/error.log'
    elif log_type == 'honeypot':
        log_path = str(HONEYPOT_LOG)
    else:
        return jsonify({'lines': [], 'error': 'Invalid log type'})

    lines = []
    try:
        if Path(log_path).exists():
            with open(log_path, 'r') as f:
                all_lines = f.readlines()
                lines = [l.rstrip() for l in all_lines[-200:]]
                lines.reverse()
    except Exception as e:
        return jsonify({'lines': [], 'error': str(e)})

    return jsonify({'lines': lines, 'log_type': log_type})


@gui_api_bp.route('/api/gui/sign', methods=['POST'])
@login_required
def api_gui_sign():
    """GUI sign message endpoint - returns JSON"""
    message = request.form.get('message', '')
    if not message:
        return jsonify({'error': 'No message'}), 400

    try:
        with se050_session():
            (r, s), recovery_id = sign_message_with_se050(Config.KEY_ID, message)
            signature = encode_signed_message(r, s, recovery_id, compressed=True)
        return jsonify({'signature': signature, 'message': message})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@gui_api_bp.route('/api/gui/tumbler')
@login_required
def api_gui_tumbler():
    """GUI tumbler status - returns JSON"""
    try:
        state = TumbleState()
        state.load()
        return jsonify({
            'status': state.status,
            'job_id': state.job_id,
            'deposit_address': state.deposit_address,
            'current_hop': state.current_hop,
            'total_hops': len(state.hop_slots) if state.hop_slots else 0,
            'amount_sats': state.amount_sats,
            'txids': state.txids,
            'delay_preset': getattr(state, 'delay_preset', 'normal'),
            'next_hop_time': getattr(state, 'next_hop_time', None),
            'error': getattr(state, 'error', None)
        })
    except Exception as e:
        return jsonify({'status': 'idle', 'error': str(e)})


@gui_api_bp.route('/api/gui/tumbler/start', methods=['POST'])
@login_required
def api_gui_tumbler_start():
    """Start tumble - returns JSON"""
    state = TumbleState.load()
    if state.status != 'idle':
        return jsonify({'error': 'Tumble already in progress'}), 400

    delay_preset = request.form.get('delay_preset', 'normal')
    if delay_preset not in DELAY_PRESETS:
        delay_preset = 'normal'

    locked = load_locked_slots()
    locked.add(Config.KEY_ID.lstrip('0x').lstrip('0'))
    locked.add(Config.KEY_ID)

    available = find_available_slots(4, locked)
    if len(available) < 4:
        return jsonify({'error': f'Not enough slots. Need 4, found {len(available)}'}), 400

    deposit_slot = available[0]
    hop_slots = available[1:4]

    try:
        with se050_session():
            for slot in [deposit_slot] + hop_slots:
                slot_int = int(slot, 16)
                se = SE050Session()
                se.connect()
                se.generate_keypair(slot_int, SE050_CURVE_SECP256K1)
                se.close()

        addresses = []
        for slot in [deposit_slot] + hop_slots:
            from tempfile import NamedTemporaryFile
            with NamedTemporaryFile(suffix='.der', delete=False) as tmp:
                tmp_path = Path(tmp.name)

            with se050_session():
                se050_export_pubkey(slot, tmp_path, 'DER')

            der_data = tmp_path.read_bytes()
            pubkey = compress_pubkey(parse_der_pubkey(der_data))
            tmp_path.unlink()

            addrs = derive_addresses(pubkey)
            addresses.append(addrs['segwit'])

        wallet = Wallet()
        wallet.load()
        main_address = wallet.addresses.get('segwit', '')

        if not main_address:
            return jsonify({'error': 'Main wallet not initialized'}), 400

        state = TumbleState()
        state.job_id = generate_job_id()
        state.status = 'waiting_deposit'
        state.deposit_slot = deposit_slot
        state.deposit_address = addresses[0]
        state.hop_slots = hop_slots
        state.hop_addresses = addresses[1:4]
        state.main_address = main_address
        state.delay_preset = delay_preset
        state.created_at = datetime.now().isoformat()
        state.save()

        start_tumbler_monitor()

        return jsonify({'success': True, 'deposit_address': state.deposit_address, 'job_id': state.job_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@gui_api_bp.route('/api/gui/tumbler/cancel', methods=['POST'])
@login_required
def api_gui_tumbler_cancel():
    """Cancel tumble - returns JSON"""
    try:
        state = TumbleState.load()
        if state.status == 'idle':
            return jsonify({'error': 'No active tumble'}), 400

        # Delete temporary keys
        slots_to_delete = []
        if state.deposit_slot:
            slots_to_delete.append(state.deposit_slot)
        if state.hop_slots:
            slots_to_delete.extend(state.hop_slots)

        with se050_session():
            for slot in slots_to_delete:
                try:
                    se = SE050Session()
                    se.connect()
                    se.delete_object(int(slot, 16))
                    se.close()
                except:
                    pass

        state.reset()
        state.save()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@gui_api_bp.route('/api/gui/tumbler/cleanup', methods=['POST'])
@login_required
def api_gui_tumbler_cleanup():
    """Cleanup after complete - returns JSON"""
    return api_gui_tumbler_cancel()


@gui_api_bp.route('/api/gui/send/prepare', methods=['POST'])
@login_required
def api_gui_send_prepare():
    """Prepare transaction - returns tx_hex for confirmation"""
    try:
        to_address = request.form.get('address', '').strip()
        amount = int(request.form.get('amount', 0))
        fee_rate = int(request.form.get('fee_rate', 5))
        send_max = request.form.get('send_max', '0') == '1'
        signing_pin = request.form.get('signing_pin', '')

        # Validation
        if not _validate_bitcoin_address(to_address):
            return jsonify({'error': 'Invalid Bitcoin address'}), 400
        if not send_max and (amount < 546):
            return jsonify({'error': 'Amount too small (dust)'}), 400
        if not _validate_fee_rate(fee_rate):
            return jsonify({'error': 'Fee rate must be 1-2000 sat/vB'}), 400

        # Check signing PIN if enabled
        if signing_pin_enabled() and not check_signing_pin(signing_pin):
            return jsonify({'error': 'Invalid signing PIN'}), 403

        # Load wallet
        wallet = Wallet()
        wallet.load()

        if not wallet.addresses or not wallet.pubkey_compressed:
            return jsonify({'error': 'Wallet not initialized'}), 400

        # Get UTXOs
        utxos = []
        for addr in wallet.addresses.values():
            if addr:
                addr_utxos = get_utxos(addr)
                if addr_utxos:
                    for utxo in addr_utxos:
                        utxo['address'] = addr
                        utxos.append(utxo)

        if not utxos:
            return jsonify({'error': 'No UTXOs available'}), 400

        total_in = sum(u['value'] for u in utxos)
        pubkey_hash = hash160(wallet.pubkey_compressed)

        # Build inputs
        inputs = [{'txid': u['txid'], 'vout': u['vout'], 'value': u['value']} for u in utxos]
        n_inputs = len(utxos)

        outputs = None
        fee = 0

        if send_max:
            est_vsize = 10 + (68 * n_inputs) + 31
            fee = est_vsize * fee_rate
            amount = total_in - fee

            if amount < 546:
                return jsonify({'error': f'Balance too low. Have {total_in}, fee {fee}'}), 400

            outputs = [{'value': amount, 'script': create_output_script(to_address)}]
        else:
            est_vsize = 10 + (68 * n_inputs) + 62
            fee = est_vsize * fee_rate

            if total_in < amount + fee:
                return jsonify({'error': f'Insufficient funds. Have {total_in}, need {amount + fee}'}), 400

            change = total_in - amount - fee
            outputs = [{'value': amount, 'script': create_output_script(to_address)}]

            if change > 546:
                change_script = bytes([0x00, 0x14]) + pubkey_hash
                outputs.append({'value': change, 'script': change_script})
            elif change > 0:
                fee += change

        # Sign with SE050
        with se050_session():
            raw_tx = build_and_sign_transaction(inputs, outputs, wallet.pubkey_compressed, pubkey_hash)

        tx_hex = raw_tx.hex()

        return jsonify({
            'success': True,
            'tx_hex': tx_hex,
            'to_address': to_address,
            'amount': amount,
            'fee': fee,
            'fee_rate': fee_rate,
            'total': amount + fee
        })

    except ValueError as e:
        return jsonify({'error': f'Invalid input: {e}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@gui_api_bp.route('/api/gui/send/broadcast', methods=['POST'])
@login_required
def api_gui_send_broadcast():
    """Broadcast signed transaction"""
    tx_hex = request.form.get('tx_hex', '')

    if not tx_hex:
        return jsonify({'error': 'No transaction provided'}), 400

    try:
        txid = broadcast_transaction(tx_hex)
        if txid:
            return jsonify({'success': True, 'txid': txid})
        else:
            return jsonify({'error': 'Broadcast failed'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@gui_api_bp.route('/api/gui/fees')
@login_required
def api_gui_fees():
    """Get current fee estimates"""
    try:
        fees = get_fee_estimates() or {}
        return jsonify(fees)
    except:
        return jsonify({'fastestFee': 20, 'halfHourFee': 10, 'hourFee': 5})


@gui_api_bp.route('/api/gui/balance')
@login_required
def api_gui_balance():
    """Get balance and UTXO count"""
    try:
        wallet = Wallet()
        wallet.load()

        balance = 0
        utxo_count = 0

        if wallet.addresses:
            for addr in wallet.addresses.values():
                if addr:
                    utxos = get_utxos(addr)
                    if utxos:
                        for utxo in utxos:
                            balance += utxo.get('value', 0)
                            utxo_count += 1

        return jsonify({'balance': balance, 'utxo_count': utxo_count})
    except Exception as e:
        return jsonify({'balance': 0, 'utxo_count': 0, 'error': str(e)})
