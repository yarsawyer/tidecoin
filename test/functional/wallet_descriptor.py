#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test descriptor wallet function (PQHD-only build)."""

try:
    import sqlite3  # noqa: F401
except ImportError:
    pass

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import WalletUnlock


class WalletDescriptorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-keypool=100']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_py_sqlite3()

    def test_parent_descriptors(self):
        self.log.info("Check that parent_descs is the same for all RPCs")
        self.nodes[0].createwallet(wallet_name="parent_descs")
        wallet = self.nodes[0].get_wallet_rpc("parent_descs")
        default_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)

        addr = wallet.getnewaddress()
        parent_desc = wallet.getaddressinfo(addr)["parent_desc"]

        since_block = self.nodes[0].getbestblockhash()
        txid = default_wallet.sendtoaddress(addr, 1)
        self.generate(self.nodes[0], 1)

        unspent = wallet.listunspent()
        assert_equal(len(unspent), 1)
        assert_equal(unspent[0]["parent_descs"], [parent_desc])

        txs = wallet.listtransactions()
        assert_equal(len(txs), 1)
        assert_equal(txs[0]["parent_descs"], [parent_desc])

        txs = wallet.listsinceblock(since_block)["transactions"]
        assert_equal(len(txs), 1)
        assert_equal(txs[0]["parent_descs"], [parent_desc])

        tx = wallet.gettransaction(txid=txid, verbose=True)
        assert_equal(tx["details"][0]["parent_descs"], [parent_desc])

        wallet.unloadwallet()

    def run_test(self):
        self.generate(self.nodes[0], COINBASE_MATURITY + 1)

        self.log.info("Making a descriptor wallet")
        self.nodes[0].createwallet(wallet_name="desc1")
        wallet = self.nodes[0].get_wallet_rpc("desc1")

        self.log.info("Checking wallet info")
        wallet_info = wallet.getwalletinfo()
        assert_equal(wallet_info['format'], 'sqlite')
        assert wallet_info['keypoolsize'] > 0
        assert wallet_info['keypoolsize_hd_internal'] > 0
        assert 'keypoololdest' not in wallet_info

        self.log.info("Test that getnewaddress and getrawchangeaddress work")
        addr = wallet.getnewaddress("", "legacy")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('pkh(')

        addr = wallet.getnewaddress("", "p2sh-segwit")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('sh(wpkh(')

        addr = wallet.getnewaddress("", "bech32")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('wpkh(')

        addr = wallet.getrawchangeaddress("legacy")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('pkh(')

        addr = wallet.getrawchangeaddress("p2sh-segwit")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('sh(wpkh(')

        addr = wallet.getrawchangeaddress("bech32")
        addr_info = wallet.getaddressinfo(addr)
        assert addr_info['desc'].startswith('wpkh(')

        # Make a wallet to receive coins at
        self.nodes[0].createwallet(wallet_name="desc2")
        recv_wrpc = self.nodes[0].get_wallet_rpc("desc2")
        send_wrpc = self.nodes[0].get_wallet_rpc("desc1")

        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 1, send_wrpc.getnewaddress())

        self.log.info("Test sending and receiving")
        addr = recv_wrpc.getnewaddress()
        send_balance = send_wrpc.getbalance()
        send_amt = min(Decimal("10"), send_balance - Decimal("0.01"))
        assert send_amt > 0
        send_wrpc.sendtoaddress(addr, send_amt)

        self.log.info("Test encryption")
        send_wrpc.encryptwallet('pass')
        with WalletUnlock(send_wrpc, "pass"):
            send_wrpc.getnewaddress()

        self.log.info("Test born encrypted wallets")
        self.nodes[0].createwallet('desc_enc', False, False, 'pass', False, True)
        enc_rpc = self.nodes[0].get_wallet_rpc('desc_enc')
        enc_rpc.getnewaddress()

        self.log.info("Test blank descriptor wallets")
        self.nodes[0].createwallet(wallet_name='desc_blank', blank=True)
        blank_rpc = self.nodes[0].get_wallet_rpc('desc_blank')
        assert_raises_rpc_error(-4, 'This wallet has no available keys', blank_rpc.getnewaddress)

        self.log.info("Test descriptor wallet with disabled private keys")
        self.nodes[0].createwallet(wallet_name='desc_no_priv', disable_private_keys=True)
        nopriv_rpc = self.nodes[0].get_wallet_rpc('desc_no_priv')
        assert_raises_rpc_error(-4, 'This wallet has no available keys', nopriv_rpc.getnewaddress)

        self.log.info("Test listdescriptors private flag does not reveal secrets")
        self.nodes[0].createwallet(wallet_name='desc_export')
        exp_rpc = self.nodes[0].get_wallet_rpc('desc_export')
        descs_pub = exp_rpc.listdescriptors(False)
        descs_priv = exp_rpc.listdescriptors(True)
        assert_equal(descs_pub, descs_priv)

        self.test_parent_descriptors()


if __name__ == '__main__':
    WalletDescriptorTest(__file__).main()
