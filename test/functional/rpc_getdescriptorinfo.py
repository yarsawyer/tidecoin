#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getdescriptorinfo RPC.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.descriptors import descsum_create
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import generate_keypair


class DescriptorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-disablewallet"]]
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        pass

    def test_desc(self, desc, isrange, issolvable, hasprivatekeys, expanded_descs=None):
        info = self.nodes[0].getdescriptorinfo(desc)
        assert_equal(info, self.nodes[0].getdescriptorinfo(descsum_create(desc)))
        if expanded_descs is not None:
            assert_equal(info["descriptor"], descsum_create(expanded_descs[0]))
            assert_equal(info["multipath_expansion"], [descsum_create(x) for x in expanded_descs])
        else:
            assert_equal(info['descriptor'], descsum_create(desc))
            assert "multipath_expansion" not in info
        assert_equal(info['isrange'], isrange)
        assert_equal(info['issolvable'], issolvable)
        assert_equal(info['hasprivatekeys'], hasprivatekeys)

    def run_test(self):
        assert_raises_rpc_error(-1, 'getdescriptorinfo', self.nodes[0].getdescriptorinfo)
        # cli handles wrong types differently
        if not self.options.usecli:
            assert_raises_rpc_error(-3, 'JSON value of type number is not of expected type string', self.nodes[0].getdescriptorinfo, 1)
        assert_raises_rpc_error(-5, "'' is not a valid descriptor function", self.nodes[0].getdescriptorinfo, "")
        priv_key, pubkey = generate_keypair(wif=True)
        pub_hex = pubkey.hex()
        assert_raises_rpc_error(-5, f"pk(): Key ' {pub_hex}' is invalid due to whitespace", self.nodes[0].getdescriptorinfo, f"pk( {pub_hex})")
        assert_raises_rpc_error(-5, f"pk(): Key '{pub_hex} ' is invalid due to whitespace", self.nodes[0].getdescriptorinfo, f"pk({pub_hex} )")
        assert_raises_rpc_error(-5, f"pk(): Key ' {priv_key}' is invalid due to whitespace", self.nodes[0].getdescriptorinfo, f"pk( {priv_key})")

        self.test_desc(f"pk({pub_hex})", isrange=False, issolvable=True, hasprivatekeys=False)
        self.test_desc(f"pkh({pub_hex})", isrange=False, issolvable=True, hasprivatekeys=False)
        self.test_desc(f"wpkh({pub_hex})", isrange=False, issolvable=True, hasprivatekeys=False)
        self.test_desc(f"sh(wpkh({pub_hex}))", isrange=False, issolvable=True, hasprivatekeys=False)
        self.test_desc(f"combo({pub_hex})", isrange=False, issolvable=True, hasprivatekeys=False)
        self.test_desc(f"sh(wsh(pkh({pub_hex})))", isrange=False, issolvable=True, hasprivatekeys=False)

        priv_key2, pubkey2 = generate_keypair(wif=True)
        self.test_desc(f"multi(1,{pub_hex},{pubkey2.hex()})", isrange=False, issolvable=True, hasprivatekeys=False)
        self.test_desc(f"sh(multi(2,{pub_hex},{pubkey2.hex()}))", isrange=False, issolvable=True, hasprivatekeys=False)
        self.test_desc(f"wsh(multi(2,{pub_hex},{pubkey2.hex()}))", isrange=False, issolvable=True, hasprivatekeys=False)
        self.test_desc(f"sh(wsh(multi(1,{pub_hex},{pubkey2.hex()})))", isrange=False, issolvable=True, hasprivatekeys=False)

        # Private key descriptors should be marked as having private keys
        self.test_desc(f"wpkh({priv_key})", isrange=False, issolvable=True, hasprivatekeys=True)


if __name__ == '__main__':
    DescriptorTest(__file__).main()
