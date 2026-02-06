#!/usr/bin/env python3
"""
SIGIL Privacy Module
=====================
Canary system, transaction privacy analysis, message verification, and tumbler.
"""

from sigil.privacy.canary import (
    Canary,
    generate_canary_message,
    create_canary,
    export_canary_text,
)

from sigil.privacy.analyzer import (
    PrivacyScore,
    analyze_transaction,
    get_privacy_recommendations,
)

from sigil.privacy.verify import (
    verify_signed_message,
)

from sigil.privacy.tumbler import (
    TumbleState,
    DELAY_PRESETS,
    find_available_slots,
    get_random_delay,
    generate_job_id,
    start_tumbler_monitor,
    stop_tumbler_monitor,
    cleanup_tumble_slots,
)

__all__ = [
    # Canary
    "Canary",
    "generate_canary_message",
    "create_canary",
    "export_canary_text",
    # Analyzer
    "PrivacyScore",
    "analyze_transaction",
    "get_privacy_recommendations",
    # Verify
    "verify_signed_message",
    # Tumbler
    "TumbleState",
    "DELAY_PRESETS",
    "find_available_slots",
    "get_random_delay",
    "generate_job_id",
    "start_tumbler_monitor",
    "stop_tumbler_monitor",
    "cleanup_tumble_slots",
]
