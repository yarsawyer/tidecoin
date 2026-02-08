#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Encode and decode Bitcoin addresses.

- base58 P2PKH and P2SH addresses.
- bech32 segwit v0 P2WPKH and P2WSH addresses."""

import enum
import unittest

from .script import (
    CScript,
    OP_0,
    OP_TRUE,
    hash160,
    hash256,
    sha256,
)
from test_framework.script_util import (
    keyhash_to_p2pkh_script,
    program_to_witness_script,
    scripthash_to_p2sh_script,
)
from test_framework.segwit_addr import (
    decode_segwit_address,
    encode_segwit_address,
)


ADDRESS_BCRT1_UNSPENDABLE = 'rtbc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqmc23q4'
ADDRESS_BCRT1_UNSPENDABLE_DESCRIPTOR = 'addr(rtbc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqmc23q4)#gzgh7a0j'
# Coins sent to this address can be spent with a witness stack of just OP_TRUE
ADDRESS_BCRT1_P2WSH_OP_TRUE = 'rtbc1qft5p2uhsdcdc3l2ua4ap5qqfg4pjaqlp250x7us7a8qqhrxrxfsq68tsrn'


class AddressType(enum.Enum):
    bech32 = 'bech32'
    p2sh_segwit = 'p2sh-segwit'
    legacy = 'legacy'  # P2PKH


b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# PQ public keys are serialized with a 1-byte scheme prefix.
_PQ_SCHEME_PREFIXES = {
    0x07,  # Falcon-512
    0x08,  # Falcon-1024
    0x09,  # ML-DSA-44
    0x0A,  # ML-DSA-65
    0x0B,  # ML-DSA-87
}

# Tidecoin base58 prefixes from src/kernel/chainparams.cpp
_BASE58_PREFIXES = {
    "main": {"p2pkh": 33, "p2sh": 70, "p2sh2": 65},
    "test": {"p2pkh": 92, "p2sh": 132, "p2sh2": 127},
    "regtest": {"p2pkh": 117, "p2sh": 186, "p2sh2": 122},
}

_P2PKH_VERSIONS = {v["p2pkh"] for v in _BASE58_PREFIXES.values()}
_P2SH_VERSIONS = {v["p2sh"] for v in _BASE58_PREFIXES.values()} | {v["p2sh2"] for v in _BASE58_PREFIXES.values()}


def get_chain_bech32_hrp(chain):
    """Return the bech32 HRP for the given chain."""
    return {"main": "tbc", "test": "ttbc", "regtest": "rtbc"}.get(chain, "rtbc")

def create_deterministic_address_p2wsh_op_true(chain):
    """Generates a deterministic bech32 address (segwit v0 P2WSH) that
    can be spent with a witness stack of OP_TRUE.

    Returns a tuple with the generated address and the witness script.
    """
    witness_script = CScript([OP_TRUE])
    hrp = get_chain_bech32_hrp(chain)
    address = encode_segwit_address(hrp, 0, sha256(witness_script))
    return (address, witness_script)

def create_deterministic_address_bcrt1_p2wsh_op_true():
    """Backward-compatible helper for Bitcoin regtest addresses."""
    return (ADDRESS_BCRT1_P2WSH_OP_TRUE, CScript([OP_TRUE]))


def byte_to_base58(b, version):
    result = ''
    b = bytes([version]) + b  # prepend version
    b += hash256(b)[:4]       # append checksum
    value = int.from_bytes(b, 'big')
    while value > 0:
        result = b58chars[value % 58] + result
        value //= 58
    while b[0] == 0:
        result = b58chars[0] + result
        b = b[1:]
    return result


def base58_to_byte(s):
    """Converts a base58-encoded string to its data and version.

    Throws if the base58 checksum is invalid."""
    if not s:
        return b''
    n = 0
    for c in s:
        n *= 58
        assert c in b58chars
        digit = b58chars.index(c)
        n += digit
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    pad = 0
    for c in s:
        if c == b58chars[0]:
            pad += 1
        else:
            break
    res = b'\x00' * pad + res

    if hash256(res[:-4])[:4] != res[-4:]:
        raise ValueError('Invalid Base58Check checksum')

    return res[1:-4], int(res[0])


def _select_chain(chain, main):
    if chain is None:
        return "main" if main else "regtest"
    assert chain in _BASE58_PREFIXES
    return chain

def keyhash_to_p2pkh(hash, main=False, chain=None):
    assert len(hash) == 20
    chain = _select_chain(chain, main)
    version = _BASE58_PREFIXES[chain]["p2pkh"]
    return byte_to_base58(hash, version)

def scripthash_to_p2sh(hash, main=False, chain=None):
    assert len(hash) == 20
    chain = _select_chain(chain, main)
    # Use SCRIPT_ADDRESS2, which is the primary script prefix in Tidecoin.
    version = _BASE58_PREFIXES[chain]["p2sh2"]
    return byte_to_base58(hash, version)

def key_to_p2pkh(key, main=False, chain=None):
    key = check_key(key)
    return keyhash_to_p2pkh(hash160(key), main, chain)

def script_to_p2sh(script, main=False, chain=None):
    script = check_script(script)
    return scripthash_to_p2sh(hash160(script), main, chain)

def key_to_p2sh_p2wpkh(key, main=False, chain=None):
    key = check_key(key)
    p2shscript = CScript([OP_0, hash160(key)])
    return script_to_p2sh(p2shscript, main, chain)

def program_to_witness(version, program, main=False, chain=None):
    if (type(program) is str):
        program = bytes.fromhex(program)
    assert version == 0
    assert 2 <= len(program) <= 40
    assert version > 0 or len(program) in [20, 32]
    if chain is not None:
        hrp = get_chain_bech32_hrp(chain)
    else:
        hrp = "tbc" if main else "rtbc"
    return encode_segwit_address(hrp, version, program)

def script_to_p2wsh(script, main=False):
    script = check_script(script)
    return program_to_witness(0, sha256(script), main)

def key_to_p2wpkh(key, main=False, chain=None):
    key = check_key(key)
    return program_to_witness(0, hash160(key), main, chain)

def script_to_p2sh_p2wsh(script, main=False):
    script = check_script(script)
    p2shscript = CScript([OP_0, sha256(script)])
    return script_to_p2sh(p2shscript, main)

def check_key(key):
    if type(key) is str:
        key = bytes.fromhex(key)  # Assuming this is hex string
    if not isinstance(key, bytes):
        assert False
    if len(key) < 2:
        assert False
    # Tidecoin requires PQ keys with a valid scheme prefix.
    if key[0] not in _PQ_SCHEME_PREFIXES:
        assert False
    return key

def check_script(script):
    if (type(script) is str):
        script = bytes.fromhex(script)  # Assuming this is hex string
    if (type(script) is bytes or type(script) is CScript):
        return script
    assert False


def bech32_to_bytes(address):
    hrp = address.split('1')[0]
    if hrp not in ['bc', 'tb', 'bcrt', 'tbc', 'ttbc', 'rtbc', 'q', 'tq', 'rq']:
        return (None, None)
    version, payload = decode_segwit_address(hrp, address)
    if version is None:
        return (None, None)
    return version, bytearray(payload)


def address_to_scriptpubkey(address):
    """Converts a given address to the corresponding output script (scriptPubKey)."""
    version, payload = bech32_to_bytes(address)
    if version is not None:
        return program_to_witness_script(version, payload) # testnet segwit scriptpubkey
    payload, version = base58_to_byte(address)
    if version in _P2PKH_VERSIONS:
        return keyhash_to_p2pkh_script(payload)
    elif version in _P2SH_VERSIONS:
        return scripthash_to_p2sh_script(payload)
    # TODO: also support other address formats
    else:
        assert False


class TestFrameworkScript(unittest.TestCase):
    def test_base58encodedecode(self):
        def check_base58(data, version):
            self.assertEqual(base58_to_byte(byte_to_base58(data, version)), (data, version))

        check_base58(bytes.fromhex('1f8ea1702a7bd4941bca0941b852c4bbfedb2e05'), 111)
        check_base58(bytes.fromhex('3a0b05f4d7f66c3ba7009f453530296c845cc9cf'), 111)
        check_base58(bytes.fromhex('41c1eaf111802559bad61b60d62b1f897c63928a'), 111)
        check_base58(bytes.fromhex('0041c1eaf111802559bad61b60d62b1f897c63928a'), 111)
        check_base58(bytes.fromhex('000041c1eaf111802559bad61b60d62b1f897c63928a'), 111)
        check_base58(bytes.fromhex('00000041c1eaf111802559bad61b60d62b1f897c63928a'), 111)
        check_base58(bytes.fromhex('1f8ea1702a7bd4941bca0941b852c4bbfedb2e05'), 0)
        check_base58(bytes.fromhex('3a0b05f4d7f66c3ba7009f453530296c845cc9cf'), 0)
        check_base58(bytes.fromhex('41c1eaf111802559bad61b60d62b1f897c63928a'), 0)
        check_base58(bytes.fromhex('0041c1eaf111802559bad61b60d62b1f897c63928a'), 0)
        check_base58(bytes.fromhex('000041c1eaf111802559bad61b60d62b1f897c63928a'), 0)
        check_base58(bytes.fromhex('00000041c1eaf111802559bad61b60d62b1f897c63928a'), 0)


    def test_bech32_decode(self):
        def check_bech32_decode(payload, version):
            hrp = "tb"
            self.assertEqual(bech32_to_bytes(encode_segwit_address(hrp, version, payload)), (version, payload))

        check_bech32_decode(bytes.fromhex('36e3e2a33f328de12e4b43c515a75fba2632ecc3'), 0)
        check_bech32_decode(bytes.fromhex('823e9790fc1d1782321140d4f4aa61aabd5e045b'), 0)
        check_bech32_decode(bytes.fromhex('616211ab00dffe0adcb6ce258d6d3fd8cbd901e2'), 0)
        check_bech32_decode(bytes.fromhex('b6a7c98b482d7fb21c9fa8e65692a0890410ff22'), 0)
        check_bech32_decode(bytes.fromhex('f0c2109cb1008cfa7b5a09cc56f7267cd8e50929'), 0)
