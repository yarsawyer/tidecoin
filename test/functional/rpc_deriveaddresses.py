#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the deriveaddresses rpc call."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.descriptors import descsum_create
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.address import key_to_p2pkh, key_to_p2sh_p2wpkh, key_to_p2wpkh
from test_framework.wallet_util import generate_keypair

class DeriveaddressesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        pass

    def run_test(self):
        assert_raises_rpc_error(-5, "Missing checksum", self.nodes[0].deriveaddresses, "a")

        priv_wif, pubkey = generate_keypair(wif=True)
        address = key_to_p2wpkh(pubkey)
        descriptor_pubkey = descsum_create(f"wpkh({pubkey.hex()})")
        assert_equal(self.nodes[0].deriveaddresses(descriptor_pubkey), [address])

        descriptor_wif = descsum_create(f"wpkh({priv_wif})")
        assert_equal(self.nodes[0].deriveaddresses(descriptor_wif), [address])

        # Unranged descriptors should reject range arguments
        assert_raises_rpc_error(-8, "Range should not be specified for an un-ranged descriptor",
                                self.nodes[0].deriveaddresses, descriptor_pubkey, [0, 2])

        combo_descriptor = descsum_create(f"combo({priv_wif})")
        assert_equal(self.nodes[0].deriveaddresses(combo_descriptor),
                     [key_to_p2wpkh(pubkey), key_to_p2pkh(pubkey), key_to_p2sh_p2wpkh(pubkey)])

        # P2PK does not have a valid address
        assert_raises_rpc_error(-5, "Descriptor does not have a corresponding address",
                                self.nodes[0].deriveaddresses, descsum_create(f"pk({pubkey.hex()})"))

if __name__ == '__main__':
    DeriveaddressesTest(__file__).main()
