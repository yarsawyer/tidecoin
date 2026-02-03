#!/usr/bin/env python3
# Copyright (c) 2014-2019 Daniel Kraft
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
AuxPoW helpers used by functional tests.

This module intentionally avoids external dependencies (like ltc_scrypt) and
uses hashlib.scrypt to compute the Litecoin-style scrypt_1024_1_1_256 hash:
  H = scrypt(password=header, salt=header, N=1024, r=1, p=1, dkLen=32)
"""

import binascii
import hashlib

from test_framework import auxpow


def _target_int(target):
    """Convert a 256-bit target represented as 64 hex chars (bytes/str) into an int."""
    if isinstance(target, (bytes, bytearray)):
        target = target.decode("ascii")
    return int(target, 16)


def _scrypt_pow_int(header_hex):
    """
    Return the scrypt_1024_1_1_256 PoW hash as an int.

    hashlib.scrypt matches Tidecoin's scrypt_1024_1_1_256 implementation. The PoW comparison in
    core interprets the resulting 32-byte digest as a uint256 (little-endian) when comparing
    against the compact target.
    """
    data = binascii.unhexlify(header_hex)
    digest = hashlib.scrypt(data, salt=data, n=1024, r=1, p=1, dklen=32)
    return int.from_bytes(digest, "little")


def computeAuxpow(block, target, ok):
    """
    Build an auxpow object (serialized as hex string) that solves (ok=True) or
    does not solve (ok=False) the block for the given target.
    """
    (tx, header) = auxpow.constructAuxpow(block)
    (header, _) = mineBlock2(header, target, ok)
    return auxpow.finishAuxpow(tx, header)


def mineAuxpowBlockWithMethods(create, submit):
    """
    Mine an auxpow block, using the given methods for creation and submission.
    """
    auxblock = create()
    target = auxpow.reverseHex(auxblock["_target"])
    apow = computeAuxpow(auxblock["hash"], target, True)
    res = submit(auxblock["hash"], apow)
    assert res
    return auxblock["hash"]


def getCoinbaseAddr(node, blockHash):
    """Extract the coinbase tx payout address for the given block."""
    blockData = node.getblock(blockHash)
    txn = blockData["tx"]
    assert len(txn) >= 1

    txData = node.getrawtransaction(txn[0], True, blockHash)
    assert len(txData["vout"]) >= 1 and len(txData["vin"]) == 1
    assert "coinbase" in txData["vin"][0]

    addr = txData["vout"][0]["scriptPubKey"]["address"]
    assert len(addr) > 0
    return addr


def mineBlock2(header, target, ok):
    """
    Given a parent block header (hex), update the nonce until its scrypt PoW is
    ok (or not ok) for the given target.
    """
    target_val = _target_int(target)
    data = bytearray(binascii.unhexlify(header))
    while True:
        nonce = int.from_bytes(data[76:80], "little")
        nonce = (nonce + 1) & 0xFFFFFFFF
        data[76:80] = nonce.to_bytes(4, "little")
        hexData = binascii.hexlify(data)

        pow_val = _scrypt_pow_int(hexData)
        if (ok and pow_val <= target_val) or ((not ok) and pow_val > target_val):
            break

    blockhash = auxpow.doubleHashHex(hexData)
    return (hexData, blockhash)
