#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test fastprune mode."""
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal
)
from test_framework.script import (
    CScript,
    OP_DROP,
)
from test_framework.wallet import MiniWallet, MiniWalletMode


class FeatureFastpruneTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-fastprune"]]

    def run_test(self):
        self.log.info("ensure that large blocks don't crash or freeze in -fastprune")
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_TRUE)
        # If no cached UTXOs exist for this script, mine enough to mature one.
        if not wallet.get_utxos(include_immature_coinbase=True, mark_as_spent=False):
            self.generatetodescriptor(self.nodes[0], COINBASE_MATURITY, wallet.get_descriptor())
            wallet.rescan_utxos()
        height_before = self.nodes[0].getblockcount()
        tx = wallet.create_self_transfer()['tx']
        # Build a large but valid legacy scriptSig (keep below MAX_SCRIPT_SIZE=65536
        # and MAX_SCRIPT_ELEMENT_SIZE=8192).
        padding = b"\xff" * 8192
        drops = []
        for _ in range(7):
            drops.extend([padding, OP_DROP])
        tx.vin[0].scriptSig = CScript(drops)
        self.generateblock(self.nodes[0], output="raw(55)", transactions=[tx.serialize().hex()])
        assert_equal(self.nodes[0].getblockcount(), height_before + 1)


if __name__ == '__main__':
    FeatureFastpruneTest(__file__).main()
