#!/usr/bin/env python3
"""
SIGIL Privacy - Transaction Analyzer
======================================
Analyze transactions for privacy leaks and fingerprinting risks.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any

from sigil.bitcoin.config import Config
from sigil.bitcoin.network import api_get


class PrivacyScore:
    """Transaction privacy analysis results"""

    def __init__(self):
        self.score: int = 100  # Start at 100, deduct for issues
        self.issues: List[Dict[str, Any]] = []
        self.warnings: List[Dict[str, Any]] = []
        self.good: List[Dict[str, Any]] = []
        self.tx_data: Optional[Dict] = None

    def deduct(self, points: int, category: str, description: str, severity: str = "warning"):
        self.score = max(0, self.score - points)
        issue = {"category": category, "description": description, "points": points}
        if severity == "critical":
            self.issues.append(issue)
        else:
            self.warnings.append(issue)

    def add_good(self, category: str, description: str):
        self.good.append({"category": category, "description": description})

    def grade(self) -> str:
        if self.score >= 90:
            return "A"
        elif self.score >= 80:
            return "B"
        elif self.score >= 70:
            return "C"
        elif self.score >= 60:
            return "D"
        else:
            return "F"


def analyze_transaction(txid: str) -> PrivacyScore:
    """Analyze a transaction for privacy leaks"""
    score = PrivacyScore()

    # Fetch transaction data
    try:
        tx = api_get(f"/tx/{txid}")
        if not tx:
            raise Exception("Transaction not found")
        score.tx_data = tx
    except Exception as e:
        score.deduct(100, "fetch", f"Could not fetch transaction: {e}", "critical")
        return score

    inputs = tx.get("vin", [])
    outputs = tx.get("vout", [])

    # === INPUT ANALYSIS ===

    # 1. Single input (no ambiguity about ownership)
    if len(inputs) == 1:
        score.deduct(5, "inputs", "Single input - no ambiguity about source")
    elif len(inputs) > 5:
        score.deduct(10, "inputs", f"Many inputs ({len(inputs)}) - likely consolidation, links addresses", "critical")
    else:
        score.add_good("inputs", f"Multiple inputs ({len(inputs)}) - some ambiguity")

    # 2. Check for address reuse in inputs
    input_addresses = []
    input_types = set()
    for inp in inputs:
        prevout = inp.get("prevout", {})
        addr = prevout.get("scriptpubkey_address", "")
        script_type = prevout.get("scriptpubkey_type", "")
        if addr:
            input_addresses.append(addr)
        if script_type:
            input_types.add(script_type)

    if len(input_addresses) != len(set(input_addresses)):
        score.deduct(15, "address_reuse", "Address reuse detected in inputs", "critical")

    # 3. Mixed script types in inputs (fingerprinting)
    if len(input_types) > 1:
        score.deduct(10, "script_types", f"Mixed input types: {', '.join(input_types)} - wallet fingerprinting risk")

    # === OUTPUT ANALYSIS ===

    # 4. Round amounts (psychological fingerprint)
    output_values = [out.get("value", 0) for out in outputs]
    for i, val in enumerate(output_values):
        btc = val / 100_000_000
        # Check for round BTC amounts
        if btc > 0 and (btc * 1000) % 1 == 0:  # Round to 0.001 BTC
            score.deduct(8, "round_amount", f"Output {i}: {btc} BTC - round amount reveals intent")

    # 5. Change detection heuristics
    if len(outputs) == 2:
        val0, val1 = output_values
        out0_type = outputs[0].get("scriptpubkey_type", "")
        out1_type = outputs[1].get("scriptpubkey_type", "")

        # Same script type as input = likely change
        if input_types and out0_type in input_types and out1_type not in input_types:
            score.deduct(10, "change_detection", "Output 0 likely change (same script type as input)")
        elif input_types and out1_type in input_types and out0_type not in input_types:
            score.deduct(10, "change_detection", "Output 1 likely change (same script type as input)")

        # Smaller output often change
        if val0 < val1 * 0.1:
            score.deduct(5, "change_detection", "Output 0 much smaller - likely change")
        elif val1 < val0 * 0.1:
            score.deduct(5, "change_detection", "Output 1 much smaller - likely change")

    # 6. Output count analysis
    if len(outputs) == 1:
        score.add_good("outputs", "Single output - sweep transaction, no change analysis possible")
    elif len(outputs) == 2:
        score.deduct(5, "outputs", "Two outputs - standard send with change, analyzable")
    elif len(outputs) > 5:
        score.deduct(5, "outputs", f"Many outputs ({len(outputs)}) - batch send or mixing")

    # 7. Dust outputs (toxic change)
    for i, val in enumerate(output_values):
        if 0 < val < 546:
            score.deduct(15, "dust", f"Output {i}: {val} sats - dust output, toxic change", "critical")
        elif 546 <= val < 1000:
            score.deduct(5, "dust", f"Output {i}: {val} sats - very small output")

    # 8. Output script types
    output_types = set(out.get("scriptpubkey_type", "") for out in outputs)
    if len(output_types) > 1:
        score.deduct(5, "script_types", f"Mixed output types: {', '.join(output_types)}")

    # === TIMING ANALYSIS ===

    # 9. Check confirmation time (if available)
    status = tx.get("status", {})
    if status.get("confirmed"):
        block_time = status.get("block_time", 0)
        if block_time:
            tx_time = datetime.fromtimestamp(block_time)
            # Weekend transactions slightly more private (less volume)
            if tx_time.weekday() >= 5:
                score.add_good("timing", "Weekend transaction - lower volume period")

    # === FEE ANALYSIS ===

    # 10. Unusual fee rate
    fee = tx.get("fee", 0)
    weight = tx.get("weight", 1)
    vsize = (weight + 3) // 4
    fee_rate = fee / vsize if vsize else 0

    if fee_rate > 100:
        score.deduct(5, "fee", f"High fee rate ({fee_rate:.1f} sat/vB) - urgency reveals information")
    elif fee_rate < 1:
        score.deduct(3, "fee", f"Very low fee rate ({fee_rate:.1f} sat/vB) - might stand out")

    # === GOOD PRACTICES ===

    # Native SegWit only
    if input_types == {"v0_p2wpkh"} and output_types <= {"v0_p2wpkh", "v1_p2tr"}:
        score.add_good("modern", "Uses native SegWit - modern, efficient, common")

    # Taproot
    if "v1_p2tr" in input_types or "v1_p2tr" in output_types:
        score.add_good("taproot", "Uses Taproot - enhanced privacy features")

    return score


def get_privacy_recommendations(score: PrivacyScore) -> List[str]:
    """Generate recommendations based on analysis"""
    recs = []

    categories = set(i["category"] for i in score.issues + score.warnings)

    if "address_reuse" in categories:
        recs.append("Never reuse addresses. Generate a new address for each receive.")

    if "round_amount" in categories:
        recs.append("Avoid round amounts. Send 0.00847291 BTC instead of 0.01 BTC.")

    if "change_detection" in categories:
        recs.append("Use the tumbler to break change linkage.")

    if "inputs" in categories and any("consolidation" in i["description"] for i in score.issues + score.warnings):
        recs.append("Avoid consolidating many UTXOs. Each input links addresses together.")

    if "script_types" in categories:
        recs.append("Use consistent address types. Mixing P2PKH/P2WPKH reveals wallet.")

    if "dust" in categories:
        recs.append("Avoid creating dust outputs. They're expensive to spend and toxic.")

    if not recs:
        recs.append("Transaction looks good! Consider using the tumbler for extra privacy.")

    return recs


__all__ = [
    "PrivacyScore", "analyze_transaction", "get_privacy_recommendations",
]
