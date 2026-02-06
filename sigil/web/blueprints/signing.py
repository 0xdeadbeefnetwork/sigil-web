"""
SIGIL Web - Message Signing Blueprint

Routes: /sign-message
"""

from flask import (
    Blueprint, request, flash, session, render_template
)

from sigil.bitcoin.config import Config
from sigil.wallet.core import Wallet
from sigil.crypto.signatures import sign_message_with_se050, encode_signed_message
from sigil.web.helpers import (
    SIGIL_VERSION, get_connection_status,
    login_required, signing_pin_enabled, check_signing_pin
)
from sigil.web.security import csrf_required
from sigil.web.session_mgmt import se050_session

signing_bp = Blueprint('signing_bp', __name__)


@signing_bp.route('/sign-message', methods=['GET', 'POST'])
@login_required
@csrf_required
def sign_message():
    signature = None
    address = None
    message = None

    if request.method == 'POST':
        message = request.form.get('message', '')
        signing_pin = request.form.get('signing_pin', '')

        # Signing PIN verification (if enabled)
        if signing_pin_enabled() and not check_signing_pin(signing_pin):
            flash('Invalid signing PIN', 'error')
        else:
            wallet = Wallet()
            wallet.load()

            if wallet.addresses:
                address = wallet.addresses.get('segwit', '')

                try:
                    with se050_session():
                        (r, s), recovery_id = sign_message_with_se050(Config.KEY_ID, message)
                        signature = encode_signed_message(r, s, recovery_id, compressed=True)
                except Exception as e:
                    flash(f'Signing error: {str(e)}', 'error')

    return render_template(
        'sign_message.html',
        title='Sign Message', connection_status=get_connection_status(), active='', version=SIGIL_VERSION,
        signature=signature, address=address, message=message,
        pin_required=signing_pin_enabled(), session=session
    )
