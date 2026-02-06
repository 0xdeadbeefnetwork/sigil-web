"""
SIGIL Web - Application Factory

Creates and configures the Flask application with all blueprints,
security headers, and CSRF token injection.
"""

import os
from flask import Flask

from sigil.web.security import add_security_headers, inject_csrf
from sigil.web.blueprints.auth import auth_bp
from sigil.web.blueprints.dashboard import dashboard_bp
from sigil.web.blueprints.wallet_mgmt import wallet_mgmt_bp
from sigil.web.blueprints.settings import settings_bp
from sigil.web.blueprints.signing import signing_bp
from sigil.web.blueprints.logs import logs_bp
from sigil.web.blueprints.honeypot import honeypot_bp
from sigil.web.blueprints.tumbler_bp import tumbler_bp, _init_tumbler
from sigil.web.blueprints.privacy_bp import privacy_bp
from sigil.web.blueprints.pubkeys import pubkeys_bp
from sigil.web.blueprints.gui_api import gui_api_bp
from sigil.web.blueprints.qr import qr_bp


def create_app():
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
        static_folder=os.path.join(os.path.dirname(__file__), 'static'),
    )

    # ---- Register blueprints ----
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(wallet_mgmt_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(signing_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(honeypot_bp)
    app.register_blueprint(tumbler_bp)
    app.register_blueprint(privacy_bp)
    app.register_blueprint(pubkeys_bp)
    app.register_blueprint(gui_api_bp)
    app.register_blueprint(qr_bp)

    # ---- Security headers on every response ----
    app.after_request(add_security_headers)

    # ---- CSRF token + connection status in every template ----
    app.context_processor(inject_csrf)

    # ---- Resume tumbler if a job was in progress ----
    with app.app_context():
        _init_tumbler()

    return app
