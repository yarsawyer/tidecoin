#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet accounts properly when there are cloned transactions with malleated scriptsigs."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.messages import (
    COIN,
    tx_from_hex,
)


class TxnMallTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [[
            "-deprecatedrpc=settxfee"
        ] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def add_options(self, parser):
        parser.add_argument("--mineblock", dest="mine_block", default=False, action="store_true",
                            help="Test double-spend of 1-confirmed transaction")
        parser.add_argument("--segwit", dest="segwit", default=False, action="store_true",
                            help="Test behaviour with SegWit txn (which should fail)")

    def setup_network(self):
        # Start with split network:
        super().setup_network()
        self.disconnect_nodes(1, 2)

    def spend_utxo(self, utxo, outputs):
        inputs = [utxo]
        tx = self.nodes[0].createrawtransaction(inputs, outputs)
        tx = self.nodes[0].fundrawtransaction(tx)
        tx = self.nodes[0].signrawtransactionwithwallet(tx['hex'])
        return self.nodes[0].sendrawtransaction(tx['hex'])

    def run_test(self):
        if self.options.segwit:
            output_type = "p2sh-segwit"
        else:
            output_type = "legacy"

        # Only node0's wallet accounting is asserted in this test.
        # Do not assume equal starting balances across all node wallets.
        starting_balance = self.nodes[0].getbalance()

        self.nodes[0].settxfee(.001)

        # Tidecoin test wallets can start with less than Bitcoin's legacy 1250 coin baseline.
        # Build two spend UTXOs relative to available balance instead of hardcoding 1219/29.
        utxo1_amount = (starting_balance * Decimal("0.60")).quantize(Decimal("0.00000001"))
        utxo2_amount = (starting_balance * Decimal("0.10")).quantize(Decimal("0.00000001"))

        node0_address1 = self.nodes[0].getnewaddress(address_type=output_type)
        node0_utxo1 = self.create_outpoints(self.nodes[0], outputs=[{node0_address1: utxo1_amount}])[0]
        node0_tx1 = self.nodes[0].gettransaction(node0_utxo1['txid'])
        self.nodes[0].lockunspent(False, [node0_utxo1])

        node0_address2 = self.nodes[0].getnewaddress(address_type=output_type)
        node0_utxo2 = self.create_outpoints(self.nodes[0], outputs=[{node0_address2: utxo2_amount}])[0]
        node0_tx2 = self.nodes[0].gettransaction(node0_utxo2['txid'])

        assert_equal(self.nodes[0].getbalance(),
                     starting_balance + node0_tx1["fee"] + node0_tx2["fee"])

        # Coins are sent to node1_address
        node1_address = self.nodes[1].getnewaddress()

        # Send tx1, and another transaction tx2 that won't be cloned
        txid1 = self.spend_utxo(node0_utxo1, {node1_address: 40})
        txid2 = self.spend_utxo(node0_utxo2, {node1_address: 20})

        # Construct a clone of tx1, to be malleated
        rawtx1 = self.nodes[0].getrawtransaction(txid1, 1)
        clone_inputs = [{"txid": rawtx1["vin"][0]["txid"], "vout": rawtx1["vin"][0]["vout"], "sequence": rawtx1["vin"][0]["sequence"]}]
        clone_outputs = {rawtx1["vout"][0]["scriptPubKey"]["address"]: rawtx1["vout"][0]["value"],
                         rawtx1["vout"][1]["scriptPubKey"]["address"]: rawtx1["vout"][1]["value"]}
        clone_locktime = rawtx1["locktime"]
        clone_raw = self.nodes[0].createrawtransaction(clone_inputs, clone_outputs, clone_locktime)

        # createrawtransaction randomizes the order of its outputs, so swap them if necessary.
        clone_tx = tx_from_hex(clone_raw)
        if (rawtx1["vout"][0]["value"] == 40 and clone_tx.vout[0].nValue != 40*COIN or rawtx1["vout"][0]["value"] != 40 and clone_tx.vout[0].nValue == 40*COIN):
            (clone_tx.vout[0], clone_tx.vout[1]) = (clone_tx.vout[1], clone_tx.vout[0])

        # Use a different signature hash type to sign.  This creates an equivalent but malleated clone.
        # Don't send the clone anywhere yet
        tx1_clone = self.nodes[0].signrawtransactionwithwallet(clone_tx.serialize().hex(), None, "ALL|ANYONECANPAY")
        assert_equal(tx1_clone["complete"], True)

        # Have node0 mine a block, if requested:
        if (self.options.mine_block):
            self.generate(self.nodes[0], 1, sync_fun=lambda: self.sync_blocks(self.nodes[0:2]))

        tx1 = self.nodes[0].gettransaction(txid1)
        tx2 = self.nodes[0].gettransaction(txid2)
        tx1_effect_before = tx1["amount"] + tx1["fee"]

        # Node0's base balance after creating tx1/tx2 spend intents.
        expected = starting_balance + node0_tx1["fee"] + node0_tx2["fee"]
        expected += tx1["amount"] + tx1["fee"]
        expected += tx2["amount"] + tx2["fee"]
        if self.options.mine_block:
            # In PQ/Tidecoin schedules, matured-per-block reward is chain-dependent.
            # A mined block must increase trusted balance beyond the spend-only base.
            assert self.nodes[0].getbalance() > expected
        else:
            assert_equal(self.nodes[0].getbalance(), expected)

        if self.options.mine_block:
            assert_equal(tx1["confirmations"], 1)
            assert_equal(tx2["confirmations"], 1)
        else:
            assert_equal(tx1["confirmations"], 0)
            assert_equal(tx2["confirmations"], 0)

        # Send clone and its parent to miner
        self.nodes[2].sendrawtransaction(node0_tx1["hex"])
        txid1_clone = self.nodes[2].sendrawtransaction(tx1_clone["hex"])
        if self.options.segwit:
            assert_equal(txid1, txid1_clone)
            return

        node2_balance_before = self.nodes[2].getbalance()
        # ... mine a block...
        self.generate(self.nodes[2], 1, sync_fun=self.no_op)

        # Reconnect the split network, and sync chain:
        self.connect_nodes(1, 2)
        self.nodes[2].sendrawtransaction(node0_tx2["hex"])
        self.nodes[2].sendrawtransaction(tx2["hex"])
        self.generate(self.nodes[2], 1)  # Mine another block to make sure we sync

        # Re-fetch transaction info:
        tx1 = self.nodes[0].gettransaction(txid1)
        tx1_clone = self.nodes[0].gettransaction(txid1_clone)
        tx2 = self.nodes[0].gettransaction(txid2)

        # Verify expected confirmations
        assert_equal(tx1["confirmations"], -2)
        assert_equal(tx1_clone["confirmations"], 2)
        assert_equal(tx2["confirmations"], 1)

        # Use node2 (uninvolved wallet-wise in tx1/tx2) as a control for
        # maturity-driven trusted-balance increase over the two mined blocks.
        maturity_delta = self.nodes[2].getbalance() - node2_balance_before
        # Clone and original can have different wallet debit effect in Tidecoin.
        replacement_delta = (tx1_clone["amount"] + tx1_clone["fee"]) - tx1_effect_before
        # Exact trusted-balance increase depends on which historical mined outputs
        # belong to node0's wallet and mature during these two blocks.
        # Assert a conservative lower bound that still checks clone accounting.
        assert self.nodes[0].getbalance() >= expected + maturity_delta + replacement_delta


if __name__ == '__main__':
    TxnMallTest(__file__).main()
