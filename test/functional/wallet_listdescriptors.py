#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the listdescriptors RPC (PQHD-only build)."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_not_equal, assert_raises_rpc_error


class ListDescriptorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # do not create any wallet by default
    def init_wallet(self, *, node):
        return

    def run_test(self):
        node = self.nodes[0]
        assert_raises_rpc_error(-18, 'No wallet is loaded.', node.listdescriptors)

        self.log.info('Test the command for empty descriptors wallet.')
        node.createwallet(wallet_name='w2', blank=True)
        assert_equal(0, len(node.get_wallet_rpc('w2').listdescriptors()['descriptors']))

        self.log.info('Test the command for a default descriptors wallet.')
        node.createwallet(wallet_name='w3')
        wallet = node.get_wallet_rpc('w3')
        result = wallet.listdescriptors()
        assert_equal('w3', result['wallet_name'])
        assert result['descriptors']
        for item in result['descriptors']:
            assert_not_equal(item['desc'], '')
            assert item['timestamp'] is not None
        descriptor_strings = [descriptor['desc'] for descriptor in result['descriptors']]
        assert_equal(descriptor_strings, sorted(descriptor_strings))

        self.log.info('Test listdescriptors with private=true returns same descriptors in PQHD-only mode')
        result_private = wallet.listdescriptors(True)
        assert_equal(result, result_private)

        self.log.info('Test listdescriptors with encrypted wallet')
        wallet.encryptwallet('pass')
        assert_equal(result, wallet.listdescriptors())
        # Private flag should still return public descriptors only
        assert_equal(result, wallet.listdescriptors(True))


if __name__ == '__main__':
    ListDescriptorsTest(__file__).main()
