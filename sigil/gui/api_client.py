#!/usr/bin/env python3
"""
SIGIL Desktop v3 - API Client
==============================

HTTP client that talks to sigil_web backend.
No SE050 lock conflicts.
"""

import requests
from typing import Optional, Dict, List

# QR Code support
try:
    import qrcode
    from PIL import Image, ImageTk
    HAS_QR = True
except ImportError:
    HAS_QR = False


# ============================================================================
#                              API CLIENT
# ============================================================================

class SigilAPI:
    def __init__(self, base_url: str = "http://127.0.0.1:5000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'SIGIL-Desktop/3.0'

    def _url(self, endpoint: str) -> str:
        return f"{self.base_url}{endpoint}"

    def _get(self, endpoint: str):
        try:
            return self.session.get(self._url(endpoint), timeout=30)
        except Exception as e:
            print(f"[API] GET {endpoint}: {e}")
            return None

    def _post(self, endpoint: str, data: dict = None):
        try:
            return self.session.post(self._url(endpoint), data=data or {}, timeout=30)
        except Exception as e:
            print(f"[API] POST {endpoint}: {e}")
            return None

    def _get_json(self, endpoint: str) -> Optional[Dict]:
        resp = self._get(endpoint)
        if resp and resp.status_code == 200:
            try:
                return resp.json()
            except:
                pass
        return None

    def _post_json(self, endpoint: str, data: dict = None) -> Optional[Dict]:
        resp = self._post(endpoint, data)
        if resp and resp.status_code == 200:
            try:
                return resp.json()
            except:
                pass
        return None

    def check_connection(self) -> bool:
        try:
            resp = self.session.get(self._url('/login'), timeout=5)
            return resp.status_code == 200
        except:
            return False

    def login(self, password: str) -> bool:
        # Get login page for any CSRF
        self._get('/login')
        resp = self._post('/login', {'password': password})
        if resp and resp.status_code == 200:
            return '/login' not in resp.url and 'dashboard' in resp.url.lower() or '/login' not in resp.text[:500].lower()
        return False

    def logout(self):
        self._post('/logout')

    # JSON API endpoints
    def get_status(self) -> Dict:
        return self._get_json('/api/gui/status') or {}

    def get_history(self) -> List[Dict]:
        data = self._get_json('/api/gui/history')
        return data.get('txs', []) if data else []

    def get_logs(self, log_type: str) -> List[str]:
        data = self._get_json(f'/api/gui/logs/{log_type}')
        return data.get('lines', []) if data else []

    def sign_message(self, message: str) -> Optional[str]:
        data = self._post_json('/api/gui/sign', {'message': message})
        return data.get('signature') if data else None

    def get_tumbler(self) -> Dict:
        return self._get_json('/api/gui/tumbler') or {'status': 'unknown'}


    def start_tumble(self, delay_preset: str = 'normal') -> Dict:
        return self._post_json('/api/gui/tumbler/start', {'delay_preset': delay_preset}) or {'error': 'Request failed'}

    def cancel_tumble(self) -> Dict:
        return self._post_json('/api/gui/tumbler/cancel') or {'error': 'Request failed'}


    def get_fees(self) -> Dict:
        return self._get_json('/api/gui/fees') or {'fastestFee': 20, 'halfHourFee': 10, 'hourFee': 5}

    def get_balance(self) -> Dict:
        return self._get_json('/api/gui/balance') or {'balance': 0, 'utxo_count': 0}

    def prepare_send(self, address: str, amount: int, fee_rate: int, signing_pin: str = '', send_max: bool = False) -> Dict:
        data = {
            'address': address,
            'amount': str(amount),
            'fee_rate': str(fee_rate),
            'signing_pin': signing_pin,
            'send_max': '1' if send_max else '0'
        }
        return self._post_json('/api/gui/send/prepare', data) or {'error': 'Request failed'}

    def broadcast_tx(self, tx_hex: str) -> Dict:
        return self._post_json('/api/gui/send/broadcast', {'tx_hex': tx_hex}) or {'error': 'Request failed'}

    def cleanup_tumble(self) -> Dict:
        return self._post_json('/api/gui/tumbler/cleanup') or {'error': 'Request failed'}

    def get_pubkeys(self) -> List[Dict]:
        data = self._get_json('/pubkeys/stream')
        return data.get('pubkeys', []) if data else []

    def start_tumbler(self, amount: int, hops: int, delay: str) -> bool:
        self._get('/tumbler')
        resp = self._post('/tumbler/start', {
            'amount': str(amount),
            'hops': str(hops),
            'delay_preset': delay
        })
        return resp is not None and resp.status_code == 200

    def cancel_tumbler(self) -> bool:
        resp = self._post('/tumbler/cancel')
        return resp is not None


# ============================================================================
#                              QR HELPER
# ============================================================================

def make_qr(data: str, size: int = 200):
    if not HAS_QR or not data:
        return None
    try:
        qr = qrcode.QRCode(version=1, box_size=8, border=2)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img = img.resize((size, size), Image.Resampling.LANCZOS)
        return ImageTk.PhotoImage(img)
    except:
        return None
