"""
SIGIL Web - Pubkeys Blueprint

Live exposed public keys visualization from the mempool.

Routes: /pubkeys, /pubkeys/stream
"""

import json
import threading
import re as _re

from flask import Blueprint, session, render_template

from sigil.web.helpers import SIGIL_VERSION, login_required

pubkeys_bp = Blueprint('pubkeys_bp', __name__)

# =========================================================================
#                         PUBKEYS TRACKING STATE
# =========================================================================

pubkeys_queue = []
pubkeys_stats = {'connected': False}
pubkeys_worker_started = False


def pubkeys_worker():
    """Fetch recent txs and extract exposed pubkeys from mempool."""
    import requests
    import time as _time
    while True:
        try:
            r = requests.get('https://mempool.space/api/mempool/recent', timeout=10)
            recent = r.json()
            for tx_summary in recent[:5]:
                txid = tx_summary.get('txid')
                if not txid:
                    continue
                tx_r = requests.get(f'https://mempool.space/api/tx/{txid}', timeout=10)
                tx = tx_r.json()
                for vin in tx.get('vin', []):
                    witness = vin.get('witness', [])
                    if len(witness) >= 2:
                        pubkey = witness[-1]
                        if len(pubkey) in [66, 130]:
                            if len(pubkeys_queue) >= 100:
                                pubkeys_queue.pop(0)
                            pubkeys_queue.append({'pubkey': pubkey, 'type': 'witness', 'txid': txid})
                    scriptsig = vin.get('scriptsig', '')
                    if scriptsig and len(scriptsig) > 66:
                        matches = _re.findall(r'(0[23][0-9a-f]{64})', scriptsig.lower())
                        for m in matches:
                            if len(pubkeys_queue) >= 100:
                                pubkeys_queue.pop(0)
                            pubkeys_queue.append({'pubkey': m, 'type': 'legacy', 'txid': txid})
            pubkeys_stats['connected'] = True
            _time.sleep(3)
        except Exception:
            pubkeys_stats['connected'] = False
            _time.sleep(5)


# =========================================================================
#                         ROUTES
# =========================================================================

@pubkeys_bp.route('/pubkeys')
@login_required
def pubkeys_page():
    """Live exposed pubkeys visualization."""
    global pubkeys_worker_started
    if not pubkeys_worker_started:
        pubkeys_worker_started = True
        t = threading.Thread(target=pubkeys_worker, daemon=True)
        t.start()
    return render_template(
        'pubkeys.html',
        title='Exposed Pubkeys', active='pubkeys')


@pubkeys_bp.route('/pubkeys/stream')
@login_required
def pubkeys_stream():
    """JSON endpoint for pubkeys data."""
    global pubkeys_worker_started
    if not pubkeys_worker_started:
        pubkeys_worker_started = True
        t = threading.Thread(target=pubkeys_worker, daemon=True)
        t.start()
    return json.dumps({'connected': pubkeys_stats.get('connected', False), 'pubkeys': list(pubkeys_queue)}), 200, {'Content-Type': 'application/json'}
