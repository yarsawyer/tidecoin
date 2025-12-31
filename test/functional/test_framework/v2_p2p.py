#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""V2 P2P transport helpers (functional test framework).

The upstream Bitcoin Core functional test framework implements v2 P2P transport
(BIP324) end-to-end. Tidecoin's v2 transport uses different cryptography, so the
upstream implementation is not applicable here.

This module is kept to satisfy imports from `test_framework.p2p`. Attempting to
use v2 transport in functional tests will raise `NotImplementedError`.
"""

SHORTID = {
    1: b"addr",
    2: b"block",
    3: b"blocktxn",
    4: b"cmpctblock",
    5: b"feefilter",
    6: b"filteradd",
    7: b"filterclear",
    8: b"filterload",
    9: b"getblocks",
    10: b"getblocktxn",
    11: b"getdata",
    12: b"getheaders",
    13: b"headers",
    14: b"inv",
    15: b"mempool",
    16: b"merkleblock",
    17: b"notfound",
    18: b"ping",
    19: b"pong",
    20: b"sendcmpct",
    21: b"tx",
    22: b"getcfilters",
    23: b"cfilter",
    24: b"getcfheaders",
    25: b"cfheaders",
    26: b"getcfcheckpt",
    27: b"cfcheckpt",
    28: b"addrv2",
}

# Dictionary which contains short message type ID for the P2P message
MSGTYPE_TO_SHORTID = {msgtype: shortid for shortid, msgtype in SHORTID.items()}


class EncryptedP2PState:
    """Placeholder for v2 transport state in functional tests."""

    def __init__(self, *, initiating, net):
        self.initiating = initiating
        self.net = net
        self.peer = None
        self.sent_garbage = b""
        self.tried_v2_handshake = False

    def _unsupported(self) -> None:
        raise NotImplementedError(
            "v2 transport is not implemented in Tidecoin's python functional test framework"
        )

    def initiate_v2_handshake(self):
        self._unsupported()

    def respond_v2_handshake(self, _response):
        self._unsupported()

    def complete_handshake(self, _response):
        self._unsupported()

    def authenticate_handshake(self, _response):
        self._unsupported()

    def v2_enc_packet(self, _contents, *, aad=b"", ignore=False):
        self._unsupported()

    def v2_receive_packet(self, _response, *, aad=b""):
        self._unsupported()

