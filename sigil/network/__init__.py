"""
sigil.network - Network communication for SIGIL.

Re-exports the public API from submodules.
"""

from sigil.network.electrum import (
    MAINNET_SERVERS,
    TESTNET_SERVERS,
    ElectrumClient,
    get_client,
    electrum_get_utxos,
    electrum_get_balance,
    electrum_get_history,
    electrum_broadcast,
    electrum_get_fee,
)

__all__ = [
    "MAINNET_SERVERS",
    "TESTNET_SERVERS",
    "ElectrumClient",
    "get_client",
    "electrum_get_utxos",
    "electrum_get_balance",
    "electrum_get_history",
    "electrum_broadcast",
    "electrum_get_fee",
]
