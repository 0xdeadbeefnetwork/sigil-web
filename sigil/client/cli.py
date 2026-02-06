#!/usr/bin/env python3
"""
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557\u2588\u2588\u2557
\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2551\u2588\u2588\u2551
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551
\u255a\u2550\u2550\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551\u2588\u2588\u2551
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d

SIGIL Client - Remote Wallet Access
=====================================

Connect to your SIGIL server (SE050 signing oracle) from anywhere.
Supports clearnet and Tor .onion addresses.

"We are defending our privacy with cryptography."
                                        - Eric Hughes

Usage:
    ./sigil_client.py --server http://localhost:5000 --key YOUR_API_KEY status
    ./sigil_client.py --server http://xyz.onion --key YOUR_API_KEY --tor balance
    ./sigil_client.py --config ~/.sigil/client.json balance

Commands:
    status          Show SE050 connection status
    balance         Get wallet balance
    address [N]     Get receive address (optional: index N)
    utxos           List all UTXOs
    sign HASH       Sign a 32-byte hash (hex)
    sign-message MSG Sign a message
    fees            Get fee estimates

License: Cypherpunk Open Hardware License
"""

import sys
import json
import argparse
from pathlib import Path

from sigil.client.client import SigilClient, load_config, save_config, CLIENT_CONFIG

# =============================================================================
#                                CLI
# =============================================================================

def print_banner():
    """Print banner"""
    print("""
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557\u2588\u2588\u2557      \u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557     \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2557   \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557
\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d \u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2551     \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551\u255a\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255d
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2551     \u2588\u2588\u2551     \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2554\u2588\u2588\u2557 \u2588\u2588\u2551   \u2588\u2588\u2551
\u255a\u2550\u2550\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2551\u2588\u2588\u2551     \u2588\u2588\u2551     \u2588\u2588\u2551     \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u255d  \u2588\u2588\u2551\u255a\u2588\u2588\u2557\u2588\u2588\u2551   \u2588\u2588\u2551
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2551   \u2588\u2588\u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u255d   \u255a\u2550\u255d
""")

def format_output(data: dict):
    """Pretty print output"""
    if 'error' in data:
        print(f"\n[ERROR] {data['error']}")
        return False

    print(json.dumps(data, indent=2))
    return True

def main():
    parser = argparse.ArgumentParser(
        description='SIGIL Client - Remote Wallet Access',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  status              Show SE050 connection status
  balance             Get wallet balance
  address [INDEX]     Get receive address
  utxos               List all UTXOs
  sign HASH           Sign a 32-byte hash (hex)
  sign-message MSG    Sign a message
  broadcast TX_HEX    Broadcast a raw transaction
  fees                Get fee estimates
  health              Health check (no auth)
  configure           Interactive configuration

Examples:
  %(prog)s --server http://abc.onion --key KEY123 --tor balance
  %(prog)s status
  %(prog)s sign 0123456789abcdef...
""")

    parser.add_argument('--server', '-s', help='SIGIL server URL')
    parser.add_argument('--key', '-k', help='API key')
    parser.add_argument('--tor', '-t', action='store_true', help='Use Tor')
    parser.add_argument('--tor-proxy', default='socks5h://127.0.0.1:9050',
                        help='Tor SOCKS proxy')
    parser.add_argument('--config', '-c', help='Config file path')
    parser.add_argument('command', nargs='?', help='Command to run')
    parser.add_argument('args', nargs='*', help='Command arguments')

    args = parser.parse_args()

    # Load config
    if args.config:
        config = json.loads(Path(args.config).read_text())
    else:
        config = load_config()

    # Override with CLI args
    server = args.server or config.get('server')
    api_key = args.key or config.get('api_key')
    use_tor = args.tor or config.get('use_tor', False)
    tor_proxy = args.tor_proxy or config.get('tor_proxy', 'socks5h://127.0.0.1:9050')

    # Configure command
    if args.command == 'configure':
        print_banner()
        print("SIGIL Client Configuration")
        print("=" * 40)

        server = input(f"Server URL [{config.get('server', '')}]: ").strip()
        if not server:
            server = config.get('server', '')

        api_key = input(f"API Key [{config.get('api_key', '')[:8]}...]: ").strip()
        if not api_key:
            api_key = config.get('api_key', '')

        use_tor = input("Use Tor? (y/N): ").strip().lower() == 'y'

        new_config = {
            'server': server,
            'api_key': api_key,
            'use_tor': use_tor,
            'tor_proxy': tor_proxy
        }

        save_config(new_config)
        print(f"\nConfiguration saved to {CLIENT_CONFIG}")
        return

    # Validate
    if not args.command:
        parser.print_help()
        return

    if not server:
        print("[!] No server specified. Use --server or run 'configure'")
        sys.exit(1)

    if args.command != 'health' and not api_key:
        print("[!] No API key specified. Use --key or run 'configure'")
        sys.exit(1)

    # Create client
    client = SigilClient(server, api_key, use_tor, tor_proxy)

    # Show connection info
    print(f"[*] Server: {server}")
    if use_tor or '.onion' in server:
        print(f"[*] Using Tor proxy: {tor_proxy}")
    print()

    # Execute command
    cmd = args.command.lower()

    if cmd == 'status':
        result = client.status()
        if 'error' not in result:
            print("SE050 Status")
            print("=" * 40)
            print(f"  Connected:    {result.get('connected')}")
            print(f"  Network:      {result.get('network')}")
            print(f"  Key Slot:     {result.get('key_slot')}")
            print(f"  Key Present:  {result.get('key_present')}")
            print(f"  UID:          {result.get('uid')}")
        else:
            format_output(result)

    elif cmd == 'balance':
        result = client.balance()
        if 'error' not in result:
            print("Wallet Balance")
            print("=" * 40)
            print(f"  Balance:  {result.get('balance_sats'):,} sats")
            print(f"            {result.get('balance_btc'):.8f} BTC")
            print(f"  UTXOs:    {result.get('utxo_count')}")
            print(f"  Address:  {result.get('address')}")
        else:
            format_output(result)

    elif cmd == 'address':
        index = int(args.args[0]) if args.args else 0
        result = client.address(index)
        if 'error' not in result:
            print("Receive Address")
            print("=" * 40)
            print(f"  Index:   {result.get('index')}")
            print(f"  Path:    {result.get('path')}")
            print(f"  Address: {result.get('address')}")
        else:
            format_output(result)

    elif cmd == 'utxos':
        result = client.utxos()
        if 'error' not in result:
            print(f"UTXOs ({result.get('count')})")
            print("=" * 60)
            for utxo in result.get('utxos', []):
                confirmed = "confirmed" if utxo.get('status', {}).get('confirmed') else "pending"
                print(f"  {utxo.get('txid')[:16]}... : {utxo.get('vout')} = {utxo.get('value'):,} sats [{confirmed}]")
        else:
            format_output(result)

    elif cmd == 'sign':
        if not args.args:
            print("[!] Usage: sign HASH")
            sys.exit(1)
        hash_hex = args.args[0]
        result = client.sign(hash_hex)
        if 'error' not in result:
            print("Signature")
            print("=" * 60)
            print(f"  Hash:      {result.get('hash')}")
            print(f"  Key:       {result.get('key_id')}")
            print(f"  Signature: {result.get('signature')}")
        else:
            format_output(result)

    elif cmd == 'sign-message':
        if not args.args:
            print("[!] Usage: sign-message MESSAGE")
            sys.exit(1)
        message = ' '.join(args.args)
        result = client.sign_message(message)
        if 'error' not in result:
            print("Message Signature")
            print("=" * 60)
            print(f"  Address:   {result.get('address')}")
            print(f"  Message:   {result.get('message')}")
            print(f"  Signature: {result.get('signature')}")
        else:
            format_output(result)

    elif cmd == 'broadcast':
        if not args.args:
            print("[!] Usage: broadcast TX_HEX")
            sys.exit(1)
        tx_hex = args.args[0]
        result = client.broadcast(tx_hex)
        if 'error' not in result:
            print("Broadcast Result")
            print("=" * 60)
            print(f"  Success: {result.get('success')}")
            print(f"  TXID:    {result.get('txid')}")
        else:
            format_output(result)

    elif cmd == 'fees':
        result = client.fees()
        if 'error' not in result:
            print("Fee Estimates (sat/vB)")
            print("=" * 40)
            for key, value in result.items():
                print(f"  {key}: {value}")
        else:
            format_output(result)

    elif cmd == 'health':
        result = client.health()
        format_output(result)

    else:
        print(f"[!] Unknown command: {cmd}")
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()
