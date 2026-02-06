"""
SIGIL Web - Privacy Tools Blueprint

Warrant canary and transaction privacy analyzer.

Routes: /canary, /canary/create, /canary/verify, /privacy
"""

import base64
import hashlib

from flask import (
    Blueprint, request, redirect, url_for, flash, session, render_template
)

from sigil.bitcoin.addresses import compress_pubkey, derive_addresses
from sigil.privacy.canary import Canary, create_canary, export_canary_text
from sigil.privacy.analyzer import (
    PrivacyScore, analyze_transaction, get_privacy_recommendations
)
from sigil.web.helpers import (
    SIGIL_VERSION, login_required, signing_pin_enabled, check_signing_pin
)
from sigil.web.security import csrf_required

privacy_bp = Blueprint('privacy_bp', __name__)


@privacy_bp.route('/canary')
@login_required
def canary():
    canary_obj = Canary.load()
    canary_text = export_canary_text(canary_obj) if canary_obj else ""

    return render_template(
        'canary.html',
        title='Canary', active='canary', version=SIGIL_VERSION,
        canary=canary_obj, canary_text=canary_text,
        pin_required=signing_pin_enabled(), session=session
    )


@privacy_bp.route('/canary/create', methods=['POST'])
@login_required
@csrf_required
def canary_create():
    validity_days = int(request.form.get('validity_days', 30))
    custom_text = request.form.get('custom_text', '').strip()
    signing_pin = request.form.get('signing_pin', '')

    # Verify signing PIN if enabled
    if signing_pin_enabled() and not check_signing_pin(signing_pin):
        flash('Invalid signing PIN', 'error')
        return redirect(url_for('privacy_bp.canary'))

    try:
        canary_obj = create_canary(validity_days, custom_text)
        flash(f'Canary signed! Sequence #{canary_obj.sequence}. Valid for {validity_days} days.', 'success')
    except Exception as e:
        flash(f'Failed to create canary: {e}', 'error')

    return redirect(url_for('privacy_bp.canary'))


@privacy_bp.route('/privacy', methods=['GET', 'POST'])
@login_required
def privacy_analyzer():
    score = None
    recommendations = []
    txid = None

    if request.method == 'POST':
        txid = request.form.get('txid', '').strip()
        if txid and len(txid) == 64:
            try:
                score = analyze_transaction(txid)
                recommendations = get_privacy_recommendations(score)
            except Exception as e:
                flash(f'Analysis failed: {e}', 'error')
        else:
            flash('Invalid transaction ID (must be 64 hex characters)', 'error')

    return render_template(
        'privacy_analyzer.html',
        title='Privacy Analyzer', active='privacy', version=SIGIL_VERSION,
        score=score, recommendations=recommendations, txid=txid, session=session
    )


@privacy_bp.route('/canary/verify', methods=['GET', 'POST'])
@login_required
def canary_verify():
    result = None
    address = ''
    signature = ''
    message = ''

    if request.method == 'POST':
        address = request.form.get('address', '').strip()
        signature = request.form.get('signature', '').strip()
        message = request.form.get('message', '')  # Don't strip - whitespace matters

        if address and signature and message:
            result = _verify_bitcoin_message(address, signature, message)

    return render_template(
        'canary_verify.html',
        title='Verify', active='canary', version=SIGIL_VERSION,
        result=result, address=address, signature=signature, message=message,
        session=session
    )


def _verify_bitcoin_message(address: str, signature: str, message: str) -> bool:
    """Verify a Bitcoin signed message"""
    try:
        sig_bytes = base64.b64decode(signature)
        if len(sig_bytes) != 65:
            return False

        header = sig_bytes[0]
        r = int.from_bytes(sig_bytes[1:33], 'big')
        s = int.from_bytes(sig_bytes[33:65], 'big')

        if header < 27 or header > 34:
            return False
        recovery_id = (header - 27) & 3
        compressed = (header - 27) >= 4

        # Hash the message
        prefix = b'\x18Bitcoin Signed Message:\n'
        msg_bytes = message.encode('utf-8')
        msg_len = len(msg_bytes)
        if msg_len < 0xfd:
            len_bytes = bytes([msg_len])
        elif msg_len <= 0xffff:
            len_bytes = b'\xfd' + msg_len.to_bytes(2, 'little')
        else:
            len_bytes = b'\xfe' + msg_len.to_bytes(4, 'little')
        full_msg = prefix + len_bytes + msg_bytes
        msg_hash = hashlib.sha256(hashlib.sha256(full_msg).digest()).digest()

        # Recover pubkey
        recovered = _recover_pubkey(msg_hash, r, s, recovery_id)
        if not recovered:
            return False

        # Compress if needed
        if compressed:
            Q_x = int.from_bytes(recovered[1:33], 'big')
            Q_y = int.from_bytes(recovered[33:65], 'big')
            prefix_byte = b'\x02' if Q_y % 2 == 0 else b'\x03'
            pubkey = prefix_byte + Q_x.to_bytes(32, 'big')
        else:
            pubkey = recovered

        # Derive address
        addr = derive_addresses(pubkey if len(pubkey) == 33 else compress_pubkey(pubkey))

        return address in addr.values()
    except Exception as e:
        print(f'Verify error: {e}')
        return False


def _recover_pubkey(msg_hash: bytes, r: int, s: int, recovery_id: int):
    """Recover public key from ECDSA signature (secp256k1)"""
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    def modinv(a, m):
        def egcd(a, b):
            if a == 0: return b, 0, 1
            g, y, x = egcd(b % a, a)
            return g, x - (b // a) * y, y
        g, x, _ = egcd(a % m, m)
        return x % m

    def point_add(p1, p2):
        if p1 is None: return p2
        if p2 is None: return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2 and y1 != y2: return None
        if x1 == x2:
            lam = (3 * x1 * x1) * modinv(2 * y1, P) % P
        else:
            lam = (y2 - y1) * modinv(x2 - x1, P) % P
        x3 = (lam * lam - x1 - x2) % P
        y3 = (lam * (x1 - x3) - y1) % P
        return x3, y3

    def point_mul(k, point):
        result = None
        addend = point
        while k:
            if k & 1: result = point_add(result, addend)
            addend = point_add(addend, addend)
            k >>= 1
        return result

    x = r + (recovery_id >> 1) * N
    if x >= P: return None

    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if (y % 2) != (recovery_id & 1): y = P - y

    R = (x, y)
    e = int.from_bytes(msg_hash, 'big')
    r_inv = modinv(r, N)
    sR = point_mul(s, R)
    eG = point_mul(e, (Gx, Gy))
    neg_eG = (eG[0], P - eG[1]) if eG else None
    diff = point_add(sR, neg_eG)
    Q = point_mul(r_inv, diff)

    if Q is None: return None
    return b'\x04' + Q[0].to_bytes(32, 'big') + Q[1].to_bytes(32, 'big')
