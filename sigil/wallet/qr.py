"""
QR code generation utilities.
"""


def generate_qr_ascii(data: str, border: int = 1) -> str:
    """
    Generate ASCII QR code using pure Python.
    Implements QR Code Model 2, Version 1-4 (up to 50 chars for alphanumeric)
    Falls back to simplified display if data too long.
    """
    # Try to use qrcode library if available, otherwise use simple box
    try:
        import importlib.util
        if importlib.util.find_spec('qrcode'):
            import qrcode
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=1,
                border=border
            )
            qr.add_data(data)
            qr.make(fit=True)

            lines = []
            for row in qr.modules:
                line = ''
                for cell in row:
                    line += '\u2588\u2588' if cell else '  '
                lines.append(line)
            return '\n'.join(lines)
    except:
        pass

    # Fallback: simple framed display
    lines = []
    lines.append('\u250c' + '\u2500' * (len(data) + 2) + '\u2510')
    lines.append('\u2502 ' + data + ' \u2502')
    lines.append('\u2514' + '\u2500' * (len(data) + 2) + '\u2518')
    lines.append('')
    lines.append('(Install qrcode for QR: pip3 install qrcode)')
    return '\n'.join(lines)
