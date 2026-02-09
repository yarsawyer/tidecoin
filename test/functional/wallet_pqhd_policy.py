#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test PQHD policy RPC behavior on post-auxpow regtest."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def pubkey_scheme_prefix(node, addr):
    info = node.getaddressinfo(addr)
    assert "pubkey" in info
    return int(info["pubkey"][:2], 16)


class WalletPQHDPolicyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        wallet_name = "pqhdpol"
        self.nodes[0].createwallet(wallet_name=wallet_name)
        wallet = self.nodes[0].get_wallet_rpc(wallet_name)

        self.log.info("Reject unknown scheme ids")
        assert_raises_rpc_error(
            -8, "Unknown scheme id", wallet.setpqhdpolicy, "nope", "falcon512"
        )

        self.log.info("Accept post-auxpow policy update on regtest")
        policy = wallet.setpqhdpolicy("mldsa44", "mldsa65")
        assert_equal(policy["receive_scheme_id"], 0x09)
        assert_equal(policy["change_scheme_id"], 0x0A)

        self.log.info("Per-call override must produce requested scheme")
        receive_override = wallet.getnewaddress("", "bech32", "mldsa44")
        change_override = wallet.getrawchangeaddress("bech32", "mldsa65")
        assert_equal(pubkey_scheme_prefix(wallet, receive_override), 0x09)
        assert_equal(pubkey_scheme_prefix(wallet, change_override), 0x0A)

        self.log.info("Per-call scheme override works repeatedly")
        override = wallet.getnewaddress("", "bech32", "falcon512")
        assert_equal(pubkey_scheme_prefix(wallet, override), 0x07)
        override_change = wallet.getrawchangeaddress("bech32", "falcon512")
        assert_equal(pubkey_scheme_prefix(wallet, override_change), 0x07)

        self.log.info("Policy persists across restart")
        self.restart_node(0)
        if wallet_name not in self.nodes[0].listwallets():
            self.nodes[0].loadwallet(wallet_name)
        wallet = self.nodes[0].get_wallet_rpc(wallet_name)

        receive_restart = wallet.getnewaddress("", "bech32", "mldsa44")
        change_restart = wallet.getrawchangeaddress("bech32", "mldsa65")
        assert_equal(pubkey_scheme_prefix(wallet, receive_restart), 0x09)
        assert_equal(pubkey_scheme_prefix(wallet, change_restart), 0x0A)


if __name__ == "__main__":
    WalletPQHDPolicyTest(__file__).main()
