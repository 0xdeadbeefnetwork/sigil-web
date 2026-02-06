"""
CLI entry point for the SIGIL Bitcoin wallet.

Parses command-line arguments and dispatches to the appropriate command handler.
"""

import sys
import argparse

from sigil.bitcoin.config import Config
from sigil.cli.commands import (
    cmd_init,
    cmd_create,
    cmd_import_seed,
    cmd_address,
    cmd_balance,
    cmd_send,
    cmd_export,
    cmd_wipe,
    cmd_reset,
    cmd_info,
    cmd_sign_message,
    cmd_history,
    cmd_verify,
    cmd_watch,
)


def main():
    parser = argparse.ArgumentParser(
        description="SE050ARD Hardware Bitcoin Wallet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s create                      Create wallet with seed phrase backup
  %(prog)s create --words 24           Create wallet with 24-word seed
  %(prog)s import-seed                 Import wallet from existing seed
  %(prog)s init                        Create wallet (NO seed backup - legacy)
  %(prog)s address                     Show receive addresses
  %(prog)s address --qr                Show address with QR code
  %(prog)s balance                     Check balance
  %(prog)s balance --fiat usd          Check balance with USD value
  %(prog)s send bc1q... 10000          Send 10,000 sats
  %(prog)s send bc1q... 0.001btc       Send 0.001 BTC
  %(prog)s send bc1q... $50            Send $50 USD worth
  %(prog)s sign-message "Hello"        Sign a message
  %(prog)s history                     Show transaction history
  %(prog)s verify                      Verify SE050 is working
  %(prog)s export                      Export public key info
  %(prog)s wipe                        Delete wallet (DANGER!)
  %(prog)s info                        Show SE050 status
        """
    )

    parser.add_argument('--testnet', action='store_true', help='Use testnet')
    parser.add_argument('--keyid', type=str, help='SE050 key slot (hex, default: 20000001)')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # init (legacy - generates key on SE050, no backup)
    subparsers.add_parser('init', help='Initialize wallet (generates key on SE050, NO BACKUP)')

    # create (new - generates seed phrase for backup)
    create_parser = subparsers.add_parser('create', help='Create new wallet with seed phrase backup')
    create_parser.add_argument('--words', type=int, choices=[12, 24], default=12,
                               help='Number of seed words (default: 12)')

    # import-seed (restore from seed phrase)
    import_parser = subparsers.add_parser('import-seed', help='Import wallet from seed phrase')
    import_parser.add_argument('mnemonic', nargs='?', help='Seed phrase (or enter interactively)')

    # address
    addr_parser = subparsers.add_parser('address', help='Show receive addresses')
    addr_parser.add_argument('--qr', action='store_true', help='Show QR code')

    # balance
    bal_parser = subparsers.add_parser('balance', help='Check balance')
    bal_parser.add_argument('--fiat', type=str, help='Show value in fiat currency (usd, eur, gbp, etc.)')

    # send
    send_parser = subparsers.add_parser('send', help='Send Bitcoin')
    send_parser.add_argument('address', help='Destination address')
    send_parser.add_argument('amount', type=str, help='Amount: 10000, 0.0001btc, $50, 50usd')
    send_parser.add_argument('-f', '--fee', type=int, help='Fee rate (sat/vB)')
    send_parser.add_argument('-y', '--yes', action='store_true', help='Skip confirmation')
    send_parser.add_argument('--no-broadcast', action='store_true',
                            help='Sign but do not broadcast (for solo mining or manual broadcast)')

    # sign-message
    sign_parser = subparsers.add_parser('sign-message', help='Sign a message')
    sign_parser.add_argument('message', help='Message to sign')

    # history
    hist_parser = subparsers.add_parser('history', help='Show transaction history')
    hist_parser.add_argument('-n', '--limit', type=int, default=10, help='Number of transactions (default: 10)')

    # verify
    subparsers.add_parser('verify', help='Verify SE050 is working correctly')

    # watch
    watch_parser = subparsers.add_parser('watch', help='Watch for incoming transactions')
    watch_parser.add_argument('-i', '--interval', type=int, default=30, help='Check interval in seconds (default: 30)')

    # export
    subparsers.add_parser('export', help='Export public key info')

    # wipe
    subparsers.add_parser('wipe', help='Delete wallet (DANGER!)')

    # info
    subparsers.add_parser('info', help='Show SE050 status')
    subparsers.add_parser('reset', help='Reset SE050 connection')

    args = parser.parse_args()

    if args.testnet:
        Config.NETWORK = "testnet"
    if args.keyid:
        Config.KEY_ID = args.keyid

    commands = {
        'init': cmd_init,
        'create': cmd_create,
        'import-seed': cmd_import_seed,
        'address': cmd_address,
        'balance': cmd_balance,
        'send': cmd_send,
        'sign-message': cmd_sign_message,
        'history': cmd_history,
        'verify': cmd_verify,
        'watch': cmd_watch,
        'export': cmd_export,
        'wipe': cmd_wipe,
        'info': cmd_info,
        'reset': cmd_reset,
    }

    if args.command in commands:
        sys.exit(commands[args.command](args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
