"""
SE050 key slot management.
Extracted from sigil_web.py.
"""

import json
from pathlib import Path

from sigil.bitcoin.config import Config


SIGIL_DIR = Path.home() / ".sigil"
LOCKED_SLOTS_FILE = SIGIL_DIR / "locked_slots.json"
DEFAULT_LOCKED_SLOTS = {"20000001", "20000002", "20000003", "20000005"}  # Slots 1,2,3,5 bricked - no ALLOW_DELETE


def load_locked_slots():
    locked = set(DEFAULT_LOCKED_SLOTS)
    try:
        if LOCKED_SLOTS_FILE.exists():
            data = json.loads(LOCKED_SLOTS_FILE.read_text())
            locked.update(str(s).upper() for s in data)
    except:
        pass
    return locked


def scan_all_slots():
    """Scan all slots - must be called within se050_session()"""
    from sigil.hardware.interface import se050_key_exists

    slots = []
    locked_slots = load_locked_slots()
    for slot_num in range(1, 17):
        slot_id = 0x20000000 + slot_num
        hex_id = f"{slot_id:08X}"
        slot_info = {
            'id': slot_id, 'hex_id': hex_id, 'num': slot_num,
            'status': 'empty', 'status_label': 'Empty',
            'status_class': 'slot-empty', 'can_select': True
        }
        if hex_id in locked_slots:
            slot_info.update({'status': 'locked', 'status_label': 'Locked',
                            'status_class': 'slot-locked', 'can_select': False})
        else:
            try:
                if se050_key_exists(hex_id):
                    slot_info.update({'status': 'active', 'status_label': 'Key',
                                    'status_class': 'slot-active'})
            except:
                pass
        slots.append(slot_info)
    return slots


def scan_all_slots_offline():
    """Scan slots without SE050 connection - shows locked status only"""
    slots = []
    locked_slots = load_locked_slots()
    for slot_num in range(1, 17):
        slot_id = 0x20000000 + slot_num
        hex_id = f"{slot_id:08X}"
        slot_info = {
            'id': slot_id, 'hex_id': hex_id, 'num': slot_num,
            'status': 'unknown', 'status_label': '?',
            'status_class': 'slot-empty', 'can_select': True
        }
        if hex_id in locked_slots:
            slot_info.update({'status': 'locked', 'status_label': 'Locked',
                            'status_class': 'slot-locked', 'can_select': False})
        slots.append(slot_info)
    return slots
