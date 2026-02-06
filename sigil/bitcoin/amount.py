"""
Amount parsing and formatting utilities for Bitcoin.
"""

from typing import Tuple
from datetime import datetime


def parse_amount(amount_str: str) -> Tuple[int, str]:
    """
    Parse amount string with optional unit suffix.

    Supports:
        10000       -> 10000 sats
        10000sat    -> 10000 sats
        10000sats   -> 10000 sats
        0.0001btc   -> sats equivalent
        0.0001BTC   -> sats equivalent
        50usd       -> sats equivalent (fetches price)
        50USD       -> sats equivalent
        $50         -> sats equivalent

    Returns: (satoshis, description)
    """
    amount_str = amount_str.strip()

    # Handle $50 format
    if amount_str.startswith('$'):
        amount_str = amount_str[1:] + 'usd'

    # Lowercase for matching
    lower = amount_str.lower()

    # Satoshis (default)
    if lower.endswith('sat') or lower.endswith('sats'):
        num = lower.replace('sats', '').replace('sat', '').strip()
        sats = int(float(num))
        return sats, f"{sats:,} sats"

    # BTC
    if lower.endswith('btc'):
        num = lower.replace('btc', '').strip()
        btc = float(num)
        sats = int(btc * 100_000_000)
        return sats, f"{btc} BTC ({sats:,} sats)"

    # USD
    if lower.endswith('usd'):
        from sigil.bitcoin.network import get_btc_price
        num = lower.replace('usd', '').strip()
        usd = float(num)
        price = get_btc_price('USD')
        if not price:
            raise ValueError("Could not fetch BTC price for USD conversion")
        btc = usd / price
        sats = int(btc * 100_000_000)
        return sats, f"${usd:.2f} USD ({sats:,} sats @ ${price:,.0f})"

    # EUR
    if lower.endswith('eur'):
        from sigil.bitcoin.network import get_btc_price
        num = lower.replace('eur', '').strip()
        eur = float(num)
        price = get_btc_price('EUR')
        if not price:
            raise ValueError("Could not fetch BTC price for EUR conversion")
        btc = eur / price
        sats = int(btc * 100_000_000)
        return sats, f"\u20ac{eur:.2f} EUR ({sats:,} sats @ \u20ac{price:,.0f})"

    # GBP
    if lower.endswith('gbp'):
        from sigil.bitcoin.network import get_btc_price
        num = lower.replace('gbp', '').strip()
        gbp = float(num)
        price = get_btc_price('GBP')
        if not price:
            raise ValueError("Could not fetch BTC price for GBP conversion")
        btc = gbp / price
        sats = int(btc * 100_000_000)
        return sats, f"\u00a3{gbp:.2f} GBP ({sats:,} sats @ \u00a3{price:,.0f})"

    # Default: plain number = sats
    sats = int(float(amount_str))
    return sats, f"{sats:,} sats"


def format_timestamp(unix_ts: int) -> str:
    """Format unix timestamp to readable date"""
    return datetime.fromtimestamp(unix_ts).strftime('%Y-%m-%d %H:%M')
