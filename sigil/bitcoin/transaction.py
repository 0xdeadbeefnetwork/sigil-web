"""
Bitcoin transaction building and signing.
"""

from typing import List, Dict

from sigil.crypto.hashing import sha256d, hash160
from sigil.crypto.encoding import bech32_decode, convertbits, b58check_decode
from sigil.crypto.signatures import parse_der_signature, normalize_signature
from sigil.bitcoin.config import Config


def varint(n: int) -> bytes:
    """Encode integer as Bitcoin varint"""
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    else:
        return b'\xff' + n.to_bytes(8, 'little')


def build_p2wpkh_sighash_preimage(
    inputs: List[Dict],
    outputs: List[Dict],
    input_index: int,
    pubkey_hash: bytes,
    value: int
) -> bytes:
    """
    Build BIP-143 sighash preimage for P2WPKH input.

    Returns DOUBLE SHA256 of preimage (sighash). Pass this 32-byte hash
    directly to se050_sign() which signs the hash as-is.
    """

    prevouts = b''
    for inp in inputs:
        prevouts += bytes.fromhex(inp['txid'])[::-1]
        prevouts += inp['vout'].to_bytes(4, 'little')
    hash_prevouts = sha256d(prevouts)

    sequences = b''
    for inp in inputs:
        sequences += (0xfffffffd).to_bytes(4, 'little')
    hash_sequence = sha256d(sequences)

    outputs_ser = b''
    for out in outputs:
        outputs_ser += out['value'].to_bytes(8, 'little')
        outputs_ser += varint(len(out['script'])) + out['script']
    hash_outputs = sha256d(outputs_ser)

    script_code = bytes([0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac])

    inp = inputs[input_index]
    preimage = b''
    preimage += (2).to_bytes(4, 'little')
    preimage += hash_prevouts
    preimage += hash_sequence
    preimage += bytes.fromhex(inp['txid'])[::-1]
    preimage += inp['vout'].to_bytes(4, 'little')
    preimage += varint(len(script_code)) + script_code
    preimage += value.to_bytes(8, 'little')
    preimage += (0xfffffffd).to_bytes(4, 'little')
    preimage += hash_outputs
    preimage += (0).to_bytes(4, 'little')
    preimage += (1).to_bytes(4, 'little')

    # Return DOUBLE SHA256 - SE050 signs this hash directly
    return sha256d(preimage)


def create_output_script(address: str) -> bytes:
    """Create output script for address"""
    if address.startswith('bc1') or address.startswith('tb1'):
        _, wver, wprog = bech32_decode(address)
        return bytes([0x00, len(wprog)]) + wprog
    elif address.startswith('1') or address.startswith('m') or address.startswith('n'):
        _, pubkey_hash = b58check_decode(address)
        return bytes([0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac])
    elif address.startswith('3') or address.startswith('2'):
        _, script_hash = b58check_decode(address)
        return bytes([0xa9, 0x14]) + script_hash + bytes([0x87])
    else:
        raise ValueError(f"Unsupported address format: {address}")


def build_and_sign_transaction(
    inputs: List[Dict],
    outputs: List[Dict],
    pubkey_compressed: bytes,
    pubkey_hash: bytes
) -> bytes:
    """Build and sign complete transaction using SE050"""
    from sigil.hardware.interface import se050_sign

    witnesses = []

    for i, inp in enumerate(inputs):
        print(f"    Signing input {i + 1}/{len(inputs)}...")

        # Get single-SHA256 of preimage; SE050 will do second SHA256
        sighash_single = build_p2wpkh_sighash_preimage(
            inputs, outputs, i, pubkey_hash, inp['value']
        )

        sig_der = se050_sign(Config.KEY_ID, sighash_single)

        sig_with_hashtype = sig_der + b'\x01'
        witness = b'\x02'
        witness += varint(len(sig_with_hashtype)) + sig_with_hashtype
        witness += varint(len(pubkey_compressed)) + pubkey_compressed
        witnesses.append(witness)

    tx = b''
    tx += (2).to_bytes(4, 'little')
    tx += b'\x00\x01'

    tx += varint(len(inputs))
    for inp in inputs:
        tx += bytes.fromhex(inp['txid'])[::-1]
        tx += inp['vout'].to_bytes(4, 'little')
        tx += b'\x00'
        tx += (0xfffffffd).to_bytes(4, 'little')

    tx += varint(len(outputs))
    for out in outputs:
        tx += out['value'].to_bytes(8, 'little')
        tx += varint(len(out['script'])) + out['script']

    for wit in witnesses:
        tx += wit

    tx += (0).to_bytes(4, 'little')

    return tx
