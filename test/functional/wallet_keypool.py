#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet keypool and interaction with wallet encryption/locking."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import WalletUnlock


class KeyPoolTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        nodes = self.nodes

        # Encrypt wallet and wait to terminate
        nodes[0].encryptwallet('test')

        # Refill a small keypool to make exhaustion deterministic
        with WalletUnlock(nodes[0], 'test'):
            nodes[0].keypoolrefill(6)

        # Drain internal keys
        for _ in range(6):
            nodes[0].getrawchangeaddress()
        assert_raises_rpc_error(-12, "Keypool ran out", nodes[0].getrawchangeaddress)

        # Drain external keys
        addr = set()
        for _ in range(6):
            addr.add(nodes[0].getnewaddress(address_type="bech32"))
        assert_equal(len(addr), 6)
        assert_raises_rpc_error(-12, "Keypool ran out", nodes[0].getnewaddress)

        # Refill keypool with three new addresses
        with WalletUnlock(nodes[0], 'test'):
            nodes[0].keypoolrefill(3)

        # Test walletpassphrase timeout (unlock should expire)
        nodes[0].wait_until(lambda: nodes[0].getwalletinfo()["unlocked_until"] == 0, timeout=5)

        # Drain the keypool
        for _ in range(3):
            nodes[0].getnewaddress()
        assert_raises_rpc_error(-12, "Keypool ran out", nodes[0].getnewaddress)

        # Refill enough keys for later operations
        with WalletUnlock(nodes[0], 'test'):
            nodes[0].keypoolrefill(100)

        # Create a blank watch-only wallet
        nodes[0].createwallet(wallet_name='w2', blank=True, disable_private_keys=True)
        w2 = nodes[0].get_wallet_rpc('w2')

        # Refer to initial wallet as w1
        w1 = nodes[0].get_wallet_rpc(self.default_wallet_name)

        # Mine spendable coins to w1
        self.generatetoaddress(nodes[0], 101, w1.getnewaddress())

        # Import a watch-only descriptor into w2 and fund it
        address = addr.pop()
        desc = w1.getaddressinfo(address)['desc']
        res = w2.importdescriptors([{'desc': desc, 'timestamp': 'now'}])
        assert_equal(res[0]['success'], True)

        with WalletUnlock(w1, 'test'):
            w1.sendtoaddress(address=address, amount=0.01000000)
        self.generate(nodes[0], 1)
        destination = addr.pop()

        # Using a fee rate (10 sat / byte) well above the minimum relay rate
        # creating a transaction with change should not be possible
        assert_raises_rpc_error(-4, "Transaction needs a change address, but we can't generate it.", w2.walletcreatefundedpsbt, inputs=[], outputs=[{addr.pop(): 0.00500000}], subtractFeeFromOutputs=[0], feeRate=0.00010)

        # creating a transaction without change, with a manual input, should still be possible
        res = w2.walletcreatefundedpsbt(inputs=w2.listunspent(), outputs=[{destination: 0.01000000}], subtractFeeFromOutputs=[0], feeRate=0.00010)
        assert_equal("psbt" in res, True)

        # creating a transaction without change should still be possible
        res = w2.walletcreatefundedpsbt(inputs=[], outputs=[{destination: 0.01000000}], subtractFeeFromOutputs=[0], feeRate=0.00010)
        assert_equal("psbt" in res, True)
        # should work without subtractFeeFromOutputs if the exact fee is subtracted from the amount
        res = w2.walletcreatefundedpsbt(inputs=[], outputs=[{destination: 0.00989000}], feeRate=0.00010)
        assert_equal("psbt" in res, True)

        # dust change should be removed
        res = w2.walletcreatefundedpsbt(inputs=[], outputs=[{destination: 0.00988000}], feeRate=0.00010)
        assert_equal("psbt" in res, True)

        # create a transaction without change at the maximum fee rate, such that the output is still spendable:
        res = w2.walletcreatefundedpsbt(inputs=[], outputs=[{destination: 0.01000000}], subtractFeeFromOutputs=[0], feeRate=0.0008823)
        assert_equal("psbt" in res, True)
        assert res["fee"] > Decimal("0")

        # creating a transaction with a manual change address should be possible
        res = w2.walletcreatefundedpsbt(inputs=[], outputs=[{destination: 0.01000000}], subtractFeeFromOutputs=[0], feeRate=0.00010, changeAddress=addr.pop())
        assert_equal("psbt" in res, True)


if __name__ == '__main__':
    KeyPoolTest(__file__).main()
