"""
sigil.wallet - Wallet state and slot management.

Re-exports the public API from submodules.
"""

from sigil.wallet.core import Wallet
from sigil.wallet.slots import load_locked_slots, scan_all_slots, scan_all_slots_offline
from sigil.wallet.qr import generate_qr_ascii

__all__ = [
    "Wallet",
    "load_locked_slots",
    "scan_all_slots",
    "scan_all_slots_offline",
    "generate_qr_ascii",
]
