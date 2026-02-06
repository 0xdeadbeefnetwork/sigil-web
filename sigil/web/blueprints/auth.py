"""
SIGIL Web - Authentication Blueprint

Routes: /login, /logout
"""

import time
import secrets

from flask import Blueprint, request, redirect, url_for, flash, session, render_template

from sigil.web.helpers import (
    SIGIL_VERSION, check_password, login_required
)
from sigil.web.security import (
    _check_rate_limit, _record_login_attempt, _login_attempts
)

auth_bp = Blueprint('auth_bp', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        client_ip = request.remote_addr or 'unknown'
        # Check rate limit
        if not _check_rate_limit(client_ip):
            flash('Too many login attempts. Try again in 5 minutes.', 'error')
            return render_template(
                'login.html',
                title='Login', active='', version=SIGIL_VERSION, session=session
            )
        password = request.form.get('password', '')
        if check_password(password):
            # Clear rate limit on successful login
            _login_attempts[client_ip] = []
            # Regenerate session to prevent fixation
            session.clear()
            session['authenticated'] = True
            session['last_active'] = time.time()
            session['_csrf_token'] = secrets.token_hex(32)
            return redirect(url_for('dashboard_bp.dashboard'))

        _record_login_attempt(client_ip)
        flash('Invalid password', 'error')

    return render_template(
        'login.html',
        title='Login', active='', version=SIGIL_VERSION, session=session
    )


@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('auth_bp.login'))
