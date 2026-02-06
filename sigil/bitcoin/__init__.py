"""
sigil.bitcoin - Bitcoin protocol utilities.

Re-exports the public API from submodules.
"""

from sigil.bitcoin.config import Config
from sigil.bitcoin.addresses import compress_pubkey, parse_der_pubkey, derive_addresses
from sigil.bitcoin.transaction import (
    varint,
    build_p2wpkh_sighash_preimage,
    create_output_script,
    build_and_sign_transaction,
)
from sigil.bitcoin.local_node import (
    local_node_rpc,
    broadcast_via_local_node,
)
from sigil.bitcoin.network import (
    api_get,
    api_post,
    broadcast_transaction,
    get_utxos,
    get_utxos_local,
    get_address_info,
    get_address_txs,
    get_fee_estimates,
    get_btc_price,
)
from sigil.bitcoin.amount import parse_amount, format_timestamp

__all__ = [
    # config
    "Config",
    # addresses
    "compress_pubkey",
    "parse_der_pubkey",
    "derive_addresses",
    # transaction
    "varint",
    "build_p2wpkh_sighash_preimage",
    "create_output_script",
    "build_and_sign_transaction",
    # local_node
    "local_node_rpc",
    "broadcast_via_local_node",
    # network
    "api_get",
    "api_post",
    "broadcast_transaction",
    "get_utxos",
    "get_utxos_local",
    "get_address_info",
    "get_address_txs",
    "get_fee_estimates",
    "get_btc_price",
    # amount
    "parse_amount",
    "format_timestamp",
]
