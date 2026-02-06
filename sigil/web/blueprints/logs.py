"""
SIGIL Web - Logs Blueprint

Routes: /logs, /logs/<log_type>, /logs/<log_type>/clear
"""

from pathlib import Path

from flask import (
    Blueprint, request, redirect, url_for, flash, session, render_template
)

from sigil.web.helpers import (
    SIGIL_VERSION, get_connection_status, login_required
)
from sigil.web.security import csrf_required, HONEYPOT_LOG

logs_bp = Blueprint('logs_bp', __name__)


@logs_bp.route('/logs')
@logs_bp.route('/logs/<log_type>')
@login_required
def logs(log_type='access'):
    lines = []

    if log_type == 'access':
        log_path = '/var/log/sigil/access.log'
    elif log_type == 'error':
        log_path = '/var/log/sigil/error.log'
    elif log_type == 'honeypot':
        log_path = str(HONEYPOT_LOG)
    else:
        log_path = '/var/log/sigil/access.log'
        log_type = 'access'

    try:
        if Path(log_path).exists():
            with open(log_path, 'r') as f:
                all_lines = f.readlines()
                lines = [l.rstrip() for l in all_lines[-200:]]
                lines.reverse()
    except Exception as e:
        lines = [f'Error reading log: {str(e)}']

    return render_template(
        'logs.html',
        title='Logs', active='logs', version=SIGIL_VERSION, connection_status=get_connection_status(),
        log_type=log_type, lines=lines, session=session
    )


@logs_bp.route('/logs/<log_type>/clear', methods=['POST'])
@login_required
@csrf_required
def clear_logs(log_type='access'):
    if log_type == 'access':
        log_path = '/var/log/sigil/access.log'
    elif log_type == 'error':
        log_path = '/var/log/sigil/error.log'
    elif log_type == 'honeypot':
        log_path = str(HONEYPOT_LOG)
    else:
        flash('Invalid log type', 'error')
        return redirect(url_for('logs_bp.logs'))

    try:
        if Path(log_path).exists():
            with open(log_path, 'w') as f:
                f.write('')
            flash(f'{log_type.title()} log cleared', 'success')
    except Exception as e:
        flash(f'Error clearing log: {str(e)}', 'error')

    return redirect(url_for('logs_bp.logs', log_type=log_type))
