"""
SIGIL Web - Settings Blueprint

Routes: /settings, /settings/password, /settings/signing-pin, /settings/network,
        /settings/rotate-keys
"""

import os
import json

from flask import (
    Blueprint, request, redirect, url_for, flash, session, render_template
)

from sigil.bitcoin.config import Config
from sigil.wallet.slots import load_locked_slots
from sigil.hardware.interface import se050_get_uid, se050_key_exists
from sigil.hardware.constants import SE050E_KEY_VERSION
from sigil.hardware.scp03 import (
    _load_scp03_keys, _load_scp03_dek, is_using_factory_keys, save_scp03_keys
)
from sigil.web.helpers import (
    SIGIL_VERSION, SIGIL_DIR, get_exit_ip,
    login_required, signing_pin_enabled,
    check_password, set_password,
    check_signing_pin, set_signing_pin, clear_signing_pin
)
from sigil.web.security import csrf_required
from sigil.web.session_mgmt import se050_session
from sigil.network.electrum import get_pinned_servers, clear_pin, clear_all_pins

settings_bp = Blueprint('settings_bp', __name__)


@settings_bp.route('/settings')
@login_required
def settings():
    uid = ""
    key_exists = False
    slots_with_keys = set()
    try:
        with se050_session():
            uid = se050_get_uid() or ""
            key_exists = se050_key_exists(Config.KEY_ID)
            # Check which slots have keys
            for i in range(1, 17):
                slot_hex = f"{0x20000000 + i:08X}"
                try:
                    if se050_key_exists(slot_hex):
                        slots_with_keys.add(slot_hex)
                except:
                    pass
    except Exception:
        pass

    # Load locked slots
    locked_slots = load_locked_slots()

    # Load saved settings
    rpc_url = ""
    use_tor = False
    settings_file = SIGIL_DIR / "network_settings.json"
    if settings_file.exists():
        try:
            saved = json.loads(settings_file.read_text())
            rpc_url = saved.get('rpc_url', '')
            use_tor = saved.get('use_tor', False)
        except Exception:
            pass

    # Get exit IP
    exit_ip = None
    is_tor = False
    try:
        exit_ip, is_tor = get_exit_ip()
    except:
        pass

    # Check SCP03 key status
    factory_keys = True
    try:
        factory_keys = is_using_factory_keys()
    except Exception:
        pass

    # Load Electrum certificate pins
    electrum_pins = get_pinned_servers()

    return render_template(
        'settings.html',
        title='Settings', active='settings', version=SIGIL_VERSION,
        uid=uid, key_slot=Config.KEY_ID, key_exists=key_exists,
        locked_slots=locked_slots, slots_with_keys=slots_with_keys,
        network=Config.NETWORK, rpc_url=rpc_url, use_tor=use_tor, api_backend=getattr(Config, 'API_BACKEND', 'electrum'),
        exit_ip=exit_ip, is_tor=is_tor, tor_enabled=use_tor,
        signing_pin_active=signing_pin_enabled(), factory_keys=factory_keys,
        electrum_pins=electrum_pins,
        session=session
    )


@settings_bp.route('/settings/password', methods=['GET', 'POST'])
@login_required
@csrf_required
def change_password():
    if request.method == "GET":
        return redirect(url_for("settings_bp.settings"))
    current = request.form.get('current', '')
    new_password = request.form.get('new_password', '')
    confirm = request.form.get('confirm', '')

    if not check_password(current):
        flash('Current password incorrect', 'error')
    elif new_password != confirm:
        flash('Passwords do not match', 'error')
    elif len(new_password) < 8:
        flash('Password must be at least 8 characters', 'error')
    else:
        set_password(new_password)
        flash('Password updated successfully', 'success')

    return redirect(url_for('settings_bp.settings'))


@settings_bp.route('/settings/signing-pin', methods=['GET', 'POST'])
@login_required
@csrf_required
def set_signing_pin_route():
    if request.method == "GET":
        return redirect(url_for("settings_bp.settings"))
    current_pin = request.form.get('current_pin', '')
    new_pin = request.form.get('new_pin', '')
    confirm_pin = request.form.get('confirm_pin', '')

    # If PIN is currently set, verify current PIN
    if signing_pin_enabled():
        if not check_signing_pin(current_pin):
            flash('Current signing PIN incorrect', 'error')
            return redirect(url_for('settings_bp.settings'))

    # If new_pin is empty, disable signing PIN
    if not new_pin:
        clear_signing_pin()
        flash('Signing PIN disabled', 'success')
        return redirect(url_for('settings_bp.settings'))

    # Validate new PIN
    if new_pin != confirm_pin:
        flash('PINs do not match', 'error')
    elif len(new_pin) < 4:
        flash('PIN must be at least 4 characters', 'error')
    else:
        set_signing_pin(new_pin)
        flash('Signing PIN updated successfully', 'success')

    return redirect(url_for('settings_bp.settings'))


@settings_bp.route('/settings/network', methods=['GET', 'POST'])
@login_required
@csrf_required
def save_network_settings():
    if request.method == "GET":
        return redirect(url_for("settings_bp.settings"))

    network = request.form.get('network', 'mainnet')
    rpc_url = request.form.get('rpc_url', '').strip()
    use_tor = request.form.get('use_tor') == 'on'

    # Update Config
    if network in ('mainnet', 'testnet'):
        Config.NETWORK = network
    Config.TOR_ENABLED = use_tor  # Sync Tor setting with wallet API

    # Get api_backend
    api_backend = request.form.get('api_backend', 'electrum')
    if api_backend in ('mempool', 'electrum'):
        Config.API_BACKEND = api_backend

    # Save to file
    settings_file = SIGIL_DIR / "network_settings.json"
    SIGIL_DIR.mkdir(parents=True, exist_ok=True)
    settings_file.write_text(json.dumps({
        'network': network,
        'rpc_url': rpc_url,
        'use_tor': use_tor,
        'api_backend': api_backend
    }))

    flash('Network settings saved', 'success')
    return redirect(url_for('settings_bp.settings'))


@settings_bp.route('/settings/rotate-keys', methods=['GET', 'POST'])
@login_required
def rotate_keys():
    """SCP03 key rotation page"""
    from sigil.hardware.session import SE050Session

    # Determine current key status
    factory_keys = True
    current_kcv = {'enc': '???', 'mac': '???'}
    try:
        factory_keys = is_using_factory_keys()
        enc, mac = _load_scp03_keys()
        current_kcv = {
            'enc': SE050Session.compute_kcv(enc).hex().upper(),
            'mac': SE050Session.compute_kcv(mac).hex().upper()
        }
    except Exception:
        pass

    if request.method == 'GET':
        return render_template(
            'rotate_keys.html',
            title='Rotate SCP03 Keys', active='settings', version=SIGIL_VERSION,
            factory_keys=factory_keys, current_kcv=current_kcv,
            pin_required=signing_pin_enabled(), session=session,
            new_keys=None
        )

    # POST — perform rotation
    # CSRF check
    from sigil.web.security import _validate_csrf
    if not _validate_csrf():
        flash('Invalid CSRF token', 'error')
        return redirect(url_for('settings_bp.rotate_keys'))

    # Verify confirmation text
    confirm = request.form.get('confirm', '')
    if confirm != 'ROTATE':
        flash('Type ROTATE to confirm', 'error')
        return redirect(url_for('settings_bp.rotate_keys'))

    # Verify signing PIN if enabled
    if signing_pin_enabled():
        pin = request.form.get('signing_pin', '')
        if not check_signing_pin(pin):
            flash('Invalid signing PIN', 'error')
            return redirect(url_for('settings_bp.rotate_keys'))

    # Load current keys
    try:
        cur_enc, cur_mac = _load_scp03_keys()
    except RuntimeError:
        # No keys configured — assume factory defaults for first rotation
        from sigil.hardware.constants import FACTORY_ENC, FACTORY_MAC
        cur_enc, cur_mac = FACTORY_ENC, FACTORY_MAC

    cur_dek = _load_scp03_dek()
    if cur_dek is None:
        flash('Cannot load current DEK key. Needed for rotation.', 'error')
        return redirect(url_for('settings_bp.rotate_keys'))

    # Generate new keys (CSPRNG)
    new_enc = os.urandom(16)
    new_mac = os.urandom(16)
    new_dek = os.urandom(16)

    # CRITICAL SAFETY: Save new keys to disk BEFORE rotating on the chip.
    # If rotation succeeds but file write fails after, the device is bricked.
    # By writing first: worst case is stale file (chip still has old keys = safe).
    from sigil.bitcoin.config import Config
    backup_file = Config.WALLET_DIR / 'scp03_pending.json'
    try:
        Config.WALLET_DIR.mkdir(parents=True, exist_ok=True)
        import json as _json
        backup_file.write_text(_json.dumps({
            'enc': new_enc.hex().upper(),
            'mac': new_mac.hex().upper(),
            'dek': new_dek.hex().upper(),
            'key_version': 11,
            'status': 'pending_rotation'
        }, indent=2))
        try:
            backup_file.chmod(0o600)
        except OSError:
            pass
    except Exception as e:
        flash(f'Cannot write key backup file before rotation: {e}', 'error')
        return redirect(url_for('settings_bp.rotate_keys'))

    # Perform rotation via ISD-mode session
    try:
        se = SE050Session(
            enc_key=cur_enc, mac_key=cur_mac,
            dek_key=cur_dek, key_version=SE050E_KEY_VERSION,
            isd_mode=True
        )
        se.connect()
        try:
            se.rotate_platform_keys(new_enc, new_mac, new_dek, SE050E_KEY_VERSION)
        finally:
            try:
                se.disconnect()
            except:
                pass

        # Rotation succeeded — now save as the active keys
        save_scp03_keys(new_enc, new_mac, new_dek)

        # Clean up pending file
        try:
            backup_file.unlink()
        except:
            pass

        flash('SCP03 keys rotated successfully! Back up your new keys below.', 'success')

        # Render page with new keys shown ONE TIME
        new_kcv = {
            'enc': SE050Session.compute_kcv(new_enc).hex().upper(),
            'mac': SE050Session.compute_kcv(new_mac).hex().upper(),
            'dek': SE050Session.compute_kcv(new_dek).hex().upper()
        }

        return render_template(
            'rotate_keys.html',
            title='Keys Rotated', active='settings', version=SIGIL_VERSION,
            factory_keys=False, current_kcv=new_kcv,
            pin_required=signing_pin_enabled(), session=session,
            new_keys={
                'enc': new_enc.hex().upper(),
                'mac': new_mac.hex().upper(),
                'dek': new_dek.hex().upper(),
                'kcv': new_kcv
            }
        )

    except Exception as e:
        flash(f'Key rotation failed: {e}', 'error')
        flash(
            'If rotation partially completed, new keys were pre-saved to '
            '~/.se050-wallet/scp03_pending.json — try connecting with both old and new keys.',
            'warning'
        )
        return redirect(url_for('settings_bp.rotate_keys'))


@settings_bp.route('/settings/clear-electrum-pin', methods=['POST'])
@login_required
@csrf_required
def clear_electrum_pin():
    """Clear a single Electrum server certificate pin"""
    server_key = request.form.get('server_key', '').strip()
    if not server_key:
        flash('No server specified', 'error')
    elif clear_pin(server_key):
        flash(f'Certificate pin cleared for {server_key}', 'success')
    else:
        flash(f'No pin found for {server_key}', 'error')
    return redirect(url_for('settings_bp.settings'))


@settings_bp.route('/settings/clear-all-electrum-pins', methods=['POST'])
@login_required
@csrf_required
def clear_all_electrum_pins():
    """Clear all Electrum server certificate pins"""
    clear_all_pins()
    flash('All Electrum certificate pins cleared. Certs will be re-pinned on next connection.', 'success')
    return redirect(url_for('settings_bp.settings'))
