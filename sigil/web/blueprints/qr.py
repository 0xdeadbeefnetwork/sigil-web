"""
SIGIL Web - QR Code Blueprint

Routes: /qr
"""

from flask import Blueprint, request

from sigil.web.helpers import login_required

qr_bp = Blueprint('qr_bp', __name__)


@qr_bp.route('/qr')
@login_required
def qr_code():
    """Generate QR code image"""
    import io
    try:
        import qrcode
    except ImportError:
        # Return a placeholder if qrcode not installed
        return "QR library not installed", 500

    data = request.args.get('data', '')
    if not data:
        return "No data", 400

    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)

    from flask import send_file
    return send_file(buf, mimetype='image/png')
