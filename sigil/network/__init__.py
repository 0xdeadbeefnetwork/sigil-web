"""
sigil.network - Network communication for SIGIL.

Re-exports the public API from submodules.
"""

from sigil.network.electrum import (
    MAINNET_SEEDS,
    TESTNET_SEEDS,
    ElectrumClient,
    get_client,
    electrum_get_utxos,
    electrum_get_balance,
    electrum_get_history,
    electrum_broadcast,
    electrum_get_fee,
    get_pinned_servers,
    clear_pin,
    clear_all_pins,
    get_cached_peer_count,
)

__all__ = [
    "MAINNET_SEEDS",
    "TESTNET_SEEDS",
    "ElectrumClient",
    "get_client",
    "electrum_get_utxos",
    "electrum_get_balance",
    "electrum_get_history",
    "electrum_broadcast",
    "electrum_get_fee",
    "get_pinned_servers",
    "clear_pin",
    "clear_all_pins",
    "get_cached_peer_count",
]
