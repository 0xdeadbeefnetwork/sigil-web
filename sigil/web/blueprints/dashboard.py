"""
SIGIL Web - Dashboard Blueprint

Routes: / (dashboard), /receive, /send, /send/broadcast, /history
"""

from datetime import datetime

from flask import (
    Blueprint, request, redirect, url_for, flash, session, render_template
)

from sigil.bitcoin.config import Config
from sigil.wallet.core import Wallet
from sigil.bitcoin.network import (
    get_utxos, get_address_txs, get_fee_estimates, get_btc_price,
    broadcast_transaction
)
from sigil.bitcoin.transaction import build_and_sign_transaction, create_output_script
from sigil.crypto.hashing import hash160
from sigil.hardware.interface import se050_get_uid
from sigil.web.helpers import (
    SIGIL_VERSION, get_connection_status, get_mempool_base,
    login_required, signing_pin_enabled, check_signing_pin
)
from sigil.web.security import (
    csrf_required, _validate_bitcoin_address, _validate_amount, _validate_fee_rate
)
from sigil.web.session_mgmt import se050_session

dashboard_bp = Blueprint('dashboard_bp', __name__)


@dashboard_bp.route('/')
@login_required
def dashboard():
    wallet = Wallet()
    wallet.load()

    # Get balance
    balance_sats = 0
    utxo_count = 0
    recent_txs = []
    address = ""

    if wallet.addresses:
        # Use native segwit (bech32) as primary address
        address = wallet.addresses.get('segwit', wallet.addresses.get('segwit', ''))

        # Check all address types for UTXOs
        all_addrs = [a for a in wallet.addresses.values() if a]
        try:
            for addr in all_addrs:
                utxos = get_utxos(addr)
                if utxos:
                    for utxo in utxos:
                        balance_sats += utxo.get('value', 0)
                        utxo_count += 1
        except Exception:
            pass  # API error, continue with zero balance

        # Get recent transactions
        try:
            if address:
                txs = get_address_txs(address)
                for tx in (txs or [])[:5]:
                    recent_txs.append({
                        'txid': tx.get('txid', ''),
                        'received': sum(v.get('value', 0) for v in tx.get('vout', [])
                                       if v.get('scriptpubkey_address') in all_addrs),
                        'sent': 0,
                        'net': 0,
                        'confirmed': tx.get('status', {}).get('confirmed', False),
                        'time': datetime.fromtimestamp(tx.get('status', {}).get('block_time', 0)).strftime('%Y-%m-%d %H:%M') if tx.get('status', {}).get('block_time') else 'Pending'
                    })
                    recent_txs[-1]['net'] = recent_txs[-1]['received'] - recent_txs[-1]['sent']
        except Exception:
            pass  # API error, continue without transactions

    try:
        btc_price = get_btc_price()
    except Exception:
        btc_price = 0

    uid = ""
    try:
        with se050_session():
            uid = se050_get_uid() or ""
    except Exception:
        pass  # SE050 unavailable, show dashboard anyway

    return render_template(
        'dashboard.html',
        title='Dashboard', connection_status=get_connection_status(), active='dashboard', version=SIGIL_VERSION,
        balance_sats=balance_sats, balance_btc=balance_sats/100_000_000,
        btc_price=btc_price, uid=uid, key_slot=Config.KEY_ID,
        network=Config.NETWORK, utxo_count=utxo_count, address=address,
        recent_txs=recent_txs, session=session
    )


@dashboard_bp.route('/receive')
@login_required
def receive():
    wallet = Wallet()
    wallet.load()

    address = ""
    path = "m/84'/0'/0'/0/0"  # BIP84 native segwit path
    if wallet.addresses:
        address = wallet.addresses.get('segwit', '')

    return render_template(
        'receive.html',
        title='Receive', connection_status=get_connection_status(), active='receive', version=SIGIL_VERSION,
        address=address, path=path, index=0,
        session=session
    )


@dashboard_bp.route('/send', methods=['GET', 'POST'])
@login_required
@csrf_required
def send():
    wallet = Wallet()
    wallet.load()

    # Get balance
    balance_sats = 0
    utxos = []

    if wallet.addresses:
        try:
            for addr in wallet.addresses.values():
                if addr:
                    addr_utxos = get_utxos(addr)
                    if addr_utxos:
                        for utxo in addr_utxos:
                            utxo['address'] = addr
                            balance_sats += utxo.get('value', 0)
                            utxos.append(utxo)
        except Exception:
            pass

    try:
        fees = get_fee_estimates() or {}
    except Exception:
        fees = {}

    if request.method == 'POST':
        to_address = request.form.get('address', '').strip()
        try:
            amount = int(request.form.get('amount', 0))
        except (ValueError, TypeError):
            amount = 0
        try:
            fee_rate = int(request.form.get('fee_rate', 5))
        except (ValueError, TypeError):
            fee_rate = 5
        send_max = request.form.get('send_max', '0') == '1'
        signing_pin = request.form.get('signing_pin', '')

        # Input validation
        if not _validate_bitcoin_address(to_address):
            flash('Invalid Bitcoin address format', 'error')
            return redirect(url_for('dashboard_bp.send'))
        if not send_max and not _validate_amount(amount):
            flash('Invalid amount', 'error')
            return redirect(url_for('dashboard_bp.send'))
        if not _validate_fee_rate(fee_rate):
            flash('Fee rate must be between 1-2000 sat/vB', 'error')
            return redirect(url_for('dashboard_bp.send'))

        # Signing PIN verification (if enabled)
        if signing_pin_enabled() and not check_signing_pin(signing_pin):
            flash('Invalid signing PIN', 'error')
            return redirect(url_for('dashboard_bp.send'))

        try:
            if not utxos:
                flash('No UTXOs available', 'error')
            elif not wallet.pubkey_compressed:
                flash('Wallet not loaded', 'error')
            else:
                total_in = sum(u['value'] for u in utxos)
                pubkey_hash = hash160(wallet.pubkey_compressed)

                # Build inputs
                inputs = [{'txid': u['txid'], 'vout': u['vout'], 'value': u['value']} for u in utxos]

                # Calculate vsize: 10 (overhead) + 68 per input + 31 per output
                # Sweep (1 output): 10 + 68*n + 31
                # With change (2 outputs): 10 + 68*n + 62
                n_inputs = len(utxos)

                outputs = None
                fee = 0

                if send_max:
                    # Sweep - send everything minus fee, no change output
                    est_vsize = 10 + (68 * n_inputs) + 31
                    fee = est_vsize * fee_rate
                    amount = total_in - fee

                    if amount < 546:
                        flash(f'Balance too low after fees. Have {total_in} sats, fee {fee} sats', 'error')
                    else:
                        outputs = [{'value': amount, 'script': create_output_script(to_address)}]
                else:
                    # Regular send with potential change
                    est_vsize = 10 + (68 * n_inputs) + 62  # 2 outputs
                    fee = est_vsize * fee_rate

                    if total_in < amount + fee:
                        flash(f'Insufficient funds. Have {total_in} sats, need {amount + fee} sats', 'error')
                    else:
                        change = total_in - amount - fee
                        outputs = [{'value': amount, 'script': create_output_script(to_address)}]

                        if change > 546:  # Dust threshold
                            change_script = bytes([0x00, 0x14]) + pubkey_hash
                            outputs.append({'value': change, 'script': change_script})
                        elif change > 0:
                            # Change is dust, add to fee instead
                            fee += change

                if outputs:
                    # Sign with SE050 (connect per-request for device sharing)
                    with se050_session():
                        raw_tx = build_and_sign_transaction(inputs, outputs, wallet.pubkey_compressed, pubkey_hash)

                    tx_hex = raw_tx.hex()
                    return render_template(
                        'send_confirm.html',
                        title='Confirm', active='send', version=SIGIL_VERSION,
                        to_address=to_address, amount=amount, fee=fee,
                        fee_rate=fee_rate, tx_hex=tx_hex, session=session
                    )
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')

    return render_template(
        'send.html',
        title='Send', connection_status=get_connection_status(), active='send', version=SIGIL_VERSION,
        balance_sats=balance_sats, balance_btc=balance_sats/100_000_000,
        utxos=utxos, fees=fees, pin_required=signing_pin_enabled(), session=session
    )


@dashboard_bp.route('/send/broadcast', methods=['POST'])
@login_required
@csrf_required
def send_broadcast():
    tx_hex = request.form.get('tx_hex', '')

    if tx_hex:
        txid = broadcast_transaction(tx_hex)
        if txid:
            flash(f'Transaction broadcast! TXID: {txid}', 'success')
        else:
            flash('Broadcast failed', 'error')

    return redirect(url_for('dashboard_bp.dashboard'))


@dashboard_bp.route('/history')
@login_required
def history():
    wallet = Wallet()
    wallet.load()

    transactions = []

    if wallet.addresses:
        addr_set = set(wallet.addresses.values())

        try:
            for addr in wallet.addresses.values():
                if addr:
                    txs = get_address_txs(addr)
                    if txs:
                        for tx in txs:
                            received = sum(v.get('value', 0) for v in tx.get('vout', [])
                                          if v.get('scriptpubkey_address') in addr_set)
                            sent = sum(v.get('value', 0) for v in tx.get('vin', [])
                                      if v.get('prevout', {}).get('scriptpubkey_address') in addr_set)

                            transactions.append({
                                'txid': tx.get('txid', ''),
                                'received': received,
                                'sent': sent,
                                'net': received - sent,
                                'fee': tx.get('fee', 0),
                                'confirmed': tx.get('status', {}).get('confirmed', False),
                                'confirmations': tx.get('status', {}).get('block_height', 0),
                                'time': datetime.fromtimestamp(tx.get('status', {}).get('block_time', 0)).strftime('%Y-%m-%d %H:%M') if tx.get('status', {}).get('block_time') else 'Pending'
                            })
        except Exception:
            pass

    # Deduplicate by txid
    seen = set()
    unique_txs = []
    for tx in transactions:
        if tx['txid'] not in seen:
            seen.add(tx['txid'])
            unique_txs.append(tx)

    return render_template(
        'history.html',
        title='History', connection_status=get_connection_status(), active='history', version=SIGIL_VERSION,
        transactions=unique_txs, session=session, mempool_base=get_mempool_base()
    )
