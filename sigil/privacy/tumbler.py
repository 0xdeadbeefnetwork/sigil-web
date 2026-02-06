#!/usr/bin/env python3
"""
SIGIL Self-Tumbler
==================
Break the transaction graph with automated coin tumbling.
Deposit -> Hop1 -> Hop2 -> Hop3 -> Main Wallet
"""

import json
import time
import secrets
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple

from sigil.hardware.session import SE050Session
from sigil.bitcoin.config import Config
from sigil.bitcoin.network import get_utxos, broadcast_transaction
from sigil.bitcoin.transaction import build_and_sign_transaction
from sigil.bitcoin.addresses import derive_addresses, compress_pubkey
from sigil.crypto.hashing import hash160

SIGIL_DIR = Path.home() / ".sigil"
TUMBLE_STATE_FILE = SIGIL_DIR / "tumble_state.json"

# Delay presets (min_seconds, max_seconds)
DELAY_PRESETS = {
    "fast": (60, 300),           # 1-5 minutes
    "normal": (600, 1800),       # 10-30 minutes
    "stealth": (3600, 21600),    # 1-6 hours
    "paranoid": (21600, 86400),  # 6-24 hours
}


class TumbleState:
    """Persistent tumble job state"""

    def __init__(self):
        self.job_id: Optional[str] = None
        self.status: str = "idle"  # idle, waiting_deposit, tumbling, complete, failed
        self.deposit_slot: Optional[str] = None
        self.deposit_address: Optional[str] = None
        self.hop_slots: List[str] = []
        self.hop_addresses: List[str] = []
        self.main_address: Optional[str] = None
        self.amount_sats: int = 0
        self.delay_preset: str = "normal"
        self.current_hop: int = 0
        self.next_hop_time: Optional[str] = None
        self.txids: List[str] = []
        self.created_at: Optional[str] = None
        self.error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "deposit_slot": self.deposit_slot,
            "deposit_address": self.deposit_address,
            "hop_slots": self.hop_slots,
            "hop_addresses": self.hop_addresses,
            "main_address": self.main_address,
            "amount_sats": self.amount_sats,
            "delay_preset": self.delay_preset,
            "current_hop": self.current_hop,
            "next_hop_time": self.next_hop_time,
            "txids": self.txids,
            "created_at": self.created_at,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TumbleState":
        state = cls()
        for key, value in data.items():
            if hasattr(state, key):
                setattr(state, key, value)
        return state

    def save(self):
        SIGIL_DIR.mkdir(parents=True, exist_ok=True)
        TUMBLE_STATE_FILE.write_text(json.dumps(self.to_dict(), indent=2))
        try:
            TUMBLE_STATE_FILE.chmod(0o600)
        except OSError:
            pass

    @classmethod
    def load(cls) -> "TumbleState":
        if TUMBLE_STATE_FILE.exists():
            try:
                data = json.loads(TUMBLE_STATE_FILE.read_text())
                return cls.from_dict(data)
            except:
                pass
        return cls()

    def reset(self):
        """Reset to idle state"""
        self.__init__()
        self.save()


def find_available_slots(n: int, locked_slots: set) -> List[str]:
    """Find n available SE050 slots that aren't locked/bricked"""
    available = []
    # Check slots 4, 6-16+ (skip 1,2,3,5 which are commonly bricked)
    candidates = [4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]

    for slot_num in candidates:
        slot_hex = f"{0x20000000 + slot_num:08x}"
        # Check if slot is locked
        if slot_hex.lstrip('0') not in locked_slots and slot_hex not in locked_slots:
            # Check the short form too
            short_hex = hex(0x20000000 + slot_num)[2:]
            if short_hex not in locked_slots:
                available.append(slot_hex)
        if len(available) >= n:
            break

    return available[:n]


def get_random_delay(preset: str) -> int:
    """Get random delay in seconds based on preset"""
    min_delay, max_delay = DELAY_PRESETS.get(preset, DELAY_PRESETS["normal"])
    return secrets.randbelow(max_delay - min_delay + 1) + min_delay


def generate_job_id() -> str:
    """Generate unique job ID"""
    return f"tumble_{int(time.time())}_{secrets.randbelow(9000) + 1000}"


# Background tumbler thread
_tumbler_thread: Optional[threading.Thread] = None
_tumbler_stop_event = threading.Event()


def start_tumbler_monitor():
    """Start background thread to monitor tumble jobs"""
    global _tumbler_thread

    if _tumbler_thread and _tumbler_thread.is_alive():
        return  # Already running

    _tumbler_stop_event.clear()
    _tumbler_thread = threading.Thread(target=_tumbler_loop, daemon=True)
    _tumbler_thread.start()


def stop_tumbler_monitor():
    """Stop background tumbler thread"""
    _tumbler_stop_event.set()
    if _tumbler_thread:
        _tumbler_thread.join(timeout=5)


def _tumbler_loop():
    """Background loop to process tumble jobs"""
    while not _tumbler_stop_event.is_set():
        try:
            state = TumbleState.load()

            if state.status == "waiting_deposit":
                _check_deposit(state)
            elif state.status == "tumbling":
                _process_hop(state)

        except Exception as e:
            print(f"[TUMBLER] Error: {e}")

        # Check every 30 seconds
        _tumbler_stop_event.wait(30)


def _check_deposit(state: TumbleState):
    """Check if deposit has been received"""
    if not state.deposit_address:
        return

    try:
        utxos = get_utxos(state.deposit_address)
        if utxos:
            # Deposit received!
            total = sum(u.get("value", 0) for u in utxos)
            if total > 0:
                state.amount_sats = total
                state.status = "tumbling"
                state.current_hop = 0
                # Set first hop time
                delay = get_random_delay(state.delay_preset)
                next_time = datetime.now() + timedelta(seconds=delay)
                state.next_hop_time = next_time.isoformat()
                state.save()
                print(f"[TUMBLER] Deposit received: {total} sats. First hop in {delay}s")
    except Exception as e:
        print(f"[TUMBLER] Error checking deposit: {e}")


def _process_hop(state: TumbleState):
    """Process next hop if it's time"""
    if not state.next_hop_time:
        return

    next_time = datetime.fromisoformat(state.next_hop_time)
    if datetime.now() < next_time:
        return  # Not time yet

    try:
        _execute_hop(state)
    except Exception as e:
        state.error = str(e)
        state.status = "failed"
        state.save()
        print(f"[TUMBLER] Hop failed: {e}")


def _execute_hop(state: TumbleState):
    """Execute a single hop transaction"""
    from sigil.bitcoin.transaction import create_output_script
    from sigil.hardware.interface import se050_export_pubkey
    from sigil.web.session_mgmt import se050_session
    from sigil.bitcoin.addresses import parse_der_pubkey
    from tempfile import NamedTemporaryFile

    hop_num = state.current_hop
    total_hops = len(state.hop_slots) + 1  # +1 for final hop to main

    print(f"[TUMBLER] Executing hop {hop_num + 1}/{total_hops}")

    # Determine source and destination
    if hop_num == 0:
        # First hop: deposit -> hop1
        source_slot = state.deposit_slot
        dest_address = state.hop_addresses[0]
    elif hop_num <= len(state.hop_slots) - 1:
        # Middle hops: hopN -> hopN+1
        source_slot = state.hop_slots[hop_num - 1]
        dest_address = state.hop_addresses[hop_num]
    else:
        # Final hop: last hop -> main wallet
        source_slot = state.hop_slots[-1]
        dest_address = state.main_address

    # Get source wallet info
    source_slot_int = int(source_slot, 16)

    # Temporarily switch to source slot to sign
    original_key_id = Config.KEY_ID
    Config.KEY_ID = source_slot

    try:
        # Export pubkey and get address for source
        with NamedTemporaryFile(suffix=".der", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        with se050_session():
            se050_export_pubkey(source_slot, tmp_path, "DER")

        der_data = tmp_path.read_bytes()
        pubkey_uncompressed = parse_der_pubkey(der_data)
        pubkey_compressed = compress_pubkey(pubkey_uncompressed)
        tmp_path.unlink()

        addresses = derive_addresses(pubkey_compressed)
        source_address = addresses["segwit"]
        pubkey_hash = hash160(pubkey_compressed)

        # Get UTXOs
        utxos = get_utxos(source_address)
        if not utxos:
            raise Exception(f"No UTXOs at {source_address}")

        total_in = sum(u["value"] for u in utxos)

        # Build transaction (sweep all to destination)
        inputs = [{"txid": u["txid"], "vout": u["vout"], "value": u["value"]} for u in utxos]

        # Estimate fee (sweep tx: ~110 vbytes)
        fee_rate = 5  # Conservative fee
        est_vsize = 10 + (68 * len(inputs)) + 31
        fee = est_vsize * fee_rate

        send_amount = total_in - fee
        if send_amount < 546:
            raise Exception(f"Amount too small after fees: {send_amount} sats")

        outputs = [{"value": send_amount, "script": create_output_script(dest_address)}]

        # Sign and broadcast
        with se050_session():
            raw_tx = build_and_sign_transaction(inputs, outputs, pubkey_compressed, pubkey_hash)

        txid = broadcast_transaction(raw_tx.hex())
        if not txid:
            raise Exception("Broadcast failed")

        state.txids.append(txid)
        state.amount_sats = send_amount
        print(f"[TUMBLER] Hop {hop_num + 1} complete: {txid}")

        # Schedule next hop or complete
        state.current_hop += 1

        if state.current_hop > len(state.hop_slots):
            # All hops complete
            state.status = "complete"
            state.next_hop_time = None
            print(f"[TUMBLER] Tumble complete! {state.amount_sats} sats delivered to main wallet")
            # Cleanup will happen separately
        else:
            # Schedule next hop
            delay = get_random_delay(state.delay_preset)
            next_time = datetime.now() + timedelta(seconds=delay)
            state.next_hop_time = next_time.isoformat()
            print(f"[TUMBLER] Next hop in {delay} seconds")

        state.save()

    finally:
        Config.KEY_ID = original_key_id


def cleanup_tumble_slots(state: TumbleState) -> List[str]:
    """Delete all temporary tumble slots"""
    from sigil.hardware.interface import se050_delete_key
    from sigil.web.session_mgmt import se050_session

    deleted = []
    all_slots = [state.deposit_slot] + state.hop_slots

    with se050_session():
        for slot in all_slots:
            if slot:
                try:
                    se050_delete_key(slot)
                    deleted.append(slot)
                    print(f"[TUMBLER] Deleted slot {slot}")
                except Exception as e:
                    print(f"[TUMBLER] Failed to delete {slot}: {e}")

    return deleted


# Export main functions
__all__ = [
    "TumbleState", "DELAY_PRESETS", "find_available_slots",
    "get_random_delay", "generate_job_id", "start_tumbler_monitor",
    "stop_tumbler_monitor", "cleanup_tumble_slots",
]
