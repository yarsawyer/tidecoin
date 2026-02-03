#!/usr/bin/env python3
# Copyright (c) 2014-2018 Daniel Kraft
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Basic helpers for constructing AuxPoW payloads.

This is adapted from Bellscoin/Namecoin-style functional tests and matches
Tidecoin's AuxPoW format (see src/auxpow.h).
"""

import binascii
import codecs
import hashlib


def constructAuxpow(block):
    """
    Start constructing a minimal auxpow, ready to be mined. Returns:
      - the fake coinbase tx (hex string)
      - the unmined parent block header (hex string)
    """

    block = codecs.encode(block, "ascii")

    # Merge-mining coinbase script: 0xfabe 'mm' + blockhash + merkle-size(1) + nonce(0).
    coinbase = b"fabe" + binascii.hexlify(b"m" * 2)
    coinbase += block
    coinbase += b"01000000" + (b"00" * 4)

    # Coinbase vin.
    vin = b"01"
    vin += (b"00" * 32) + (b"ff" * 4)
    vin += codecs.encode("%02x" % (len(coinbase) // 2), "ascii") + coinbase
    vin += (b"ff" * 4)

    # Coinbase tx (no outputs).
    tx = b"01000000" + vin + b"00" + (b"00" * 4)
    txHash = doubleHashHex(tx)

    # Parent block header (needs to be mined for scrypt PoW, doesn't need to be a valid block).
    header = b"01000000"
    header += b"00" * 32
    header += reverseHex(txHash)
    header += b"00" * 4
    header += b"00" * 4
    header += b"00" * 4

    return (tx.decode("ascii"), header.decode("ascii"))


def finishAuxpow(tx, header):
    """
    Construct the finished auxpow hex string based on the mined parent header.
    """

    # Mine helpers may return the header as either a str hex string or bytes.
    header_bytes = header if isinstance(header, (bytes, bytearray)) else codecs.encode(header, "ascii")
    blockhash = doubleHashHex(header)

    # MerkleTx: tx + hashBlock + vMerkleBranch(empty) + nIndex(0)
    auxpow = codecs.encode(tx, "ascii")
    auxpow += blockhash
    auxpow += b"00"
    auxpow += b"00" * 4

    # Chain merkle branch (empty), chain index (0), parent header.
    auxpow += b"00"
    auxpow += b"00" * 4
    auxpow += header_bytes

    return auxpow.decode("ascii")


def doubleHashHex(data):
    """Double-SHA256 hash of the given hex string, returning a hex string (little-endian)."""
    hasher = hashlib.sha256()
    hasher.update(binascii.unhexlify(data))
    data = hasher.digest()

    hasher = hashlib.sha256()
    hasher.update(data)

    return reverseHex(hasher.hexdigest())


def reverseHex(data):
    """Flip byte order in the given data (hex string). Returns bytes."""
    b = bytearray(binascii.unhexlify(data))
    b.reverse()
    return binascii.hexlify(b)


def getworkByteswap(data):
    """Byte-order swap step necessary for legacy getwork."""
    data = bytearray(data)
    assert len(data) % 4 == 0
    for i in range(0, len(data), 4):
        data[i], data[i + 3] = data[i + 3], data[i]
        data[i + 1], data[i + 2] = data[i + 2], data[i + 1]
    return data
