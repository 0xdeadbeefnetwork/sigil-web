"""
SIGIL Web - Tumbler Blueprint

Self-tumbler for breaking the transaction graph.

Routes: /tumbler, /tumbler/start, /tumbler/qr, /tumbler/cancel, /tumbler/cleanup
"""

from datetime import datetime
from pathlib import Path

from flask import (
    Blueprint, request, redirect, url_for, flash, session, render_template
)

from sigil.bitcoin.config import Config
from sigil.wallet.core import Wallet
from sigil.wallet.slots import load_locked_slots
from sigil.hardware.interface import se050_export_pubkey, se050_generate_keypair
from sigil.bitcoin.addresses import compress_pubkey, parse_der_pubkey, derive_addresses
from sigil.privacy.tumbler import (
    TumbleState, DELAY_PRESETS, find_available_slots,
    generate_job_id, start_tumbler_monitor, stop_tumbler_monitor,
    cleanup_tumble_slots
)
from sigil.web.helpers import SIGIL_VERSION, login_required, get_mempool_base
from sigil.web.security import csrf_required
from sigil.web.session_mgmt import se050_session

tumbler_bp = Blueprint('tumbler_bp', __name__)


@tumbler_bp.route('/tumbler')
@login_required
def tumbler():
    state = TumbleState.load()
    return render_template(
        'tumbler.html',
        title='Tumbler', active='tumbler', version=SIGIL_VERSION,
        state=state, session=session, mempool_base=get_mempool_base()
    )


@tumbler_bp.route('/tumbler/start', methods=['POST'])
@login_required
@csrf_required
def tumbler_start():
    # Check if tumble already in progress
    state = TumbleState.load()
    if state.status != 'idle':
        flash('Tumble already in progress', 'error')
        return redirect(url_for('tumbler_bp.tumbler'))

    delay_preset = request.form.get('delay_preset', 'normal')
    if delay_preset not in DELAY_PRESETS:
        delay_preset = 'normal'

    # Find 4 available slots (1 deposit + 3 hops)
    locked = load_locked_slots()
    # Also exclude main wallet slot
    locked.add(Config.KEY_ID.lstrip('0x').lstrip('0'))
    locked.add(Config.KEY_ID)

    available = find_available_slots(4, locked)
    if len(available) < 4:
        flash(f'Not enough available slots. Need 4, found {len(available)}', 'error')
        return redirect(url_for('tumbler_bp.tumbler'))

    deposit_slot = available[0]
    hop_slots = available[1:4]

    try:
        # Generate keypairs in all slots using the high-level interface
        with se050_session():
            for slot in [deposit_slot] + hop_slots:
                if not se050_generate_keypair(slot):
                    raise Exception(f"Failed to generate keypair in slot {slot}")

        # Export pubkeys and derive addresses
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

        # Get main wallet address
        wallet = Wallet()
        wallet.load()
        main_address = wallet.addresses.get('segwit', '')

        if not main_address:
            flash('Main wallet not initialized', 'error')
            return redirect(url_for('tumbler_bp.tumbler'))

        # Create tumble state
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

        # Start background monitor
        start_tumbler_monitor()

        flash('Tumble address generated. Send coins to begin tumbling.', 'success')

    except Exception as e:
        flash(f'Failed to create tumble job: {e}', 'error')

    return redirect(url_for('tumbler_bp.tumbler'))


@tumbler_bp.route('/tumbler/qr')
@login_required
def tumbler_qr():
    state = TumbleState.load()
    if not state.deposit_address:
        return '', 404

    import qrcode
    from io import BytesIO

    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(f'bitcoin:{state.deposit_address}')
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')

    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)

    return buf.getvalue(), 200, {'Content-Type': 'image/png'}


@tumbler_bp.route('/tumbler/cancel', methods=['POST'])
@login_required
@csrf_required
def tumbler_cancel():
    state = TumbleState.load()

    if state.status == 'idle':
        flash('No tumble job to cancel', 'info')
        return redirect(url_for('tumbler_bp.tumbler'))

    # Stop monitor
    stop_tumbler_monitor()

    # Cleanup slots
    try:
        deleted = cleanup_tumble_slots(state)
        flash(f'Tumble cancelled. Deleted {len(deleted)} temporary slots.', 'warning')
    except Exception as e:
        flash(f'Cleanup error: {e}', 'error')

    # Reset state
    state.reset()

    return redirect(url_for('tumbler_bp.tumbler'))


@tumbler_bp.route('/tumbler/cleanup', methods=['POST'])
@login_required
@csrf_required
def tumbler_cleanup():
    state = TumbleState.load()

    # Cleanup slots
    try:
        deleted = cleanup_tumble_slots(state)
        flash(f'Cleaned up {len(deleted)} temporary slots. Ready for new tumble.', 'success')
    except Exception as e:
        flash(f'Cleanup error: {e}', 'error')

    # Reset state
    state.reset()

    return redirect(url_for('tumbler_bp.tumbler'))


def _init_tumbler():
    """Start tumbler monitor on app startup (if job in progress)"""
    state = TumbleState.load()
    if state.status in ('waiting_deposit', 'tumbling'):
        start_tumbler_monitor()
