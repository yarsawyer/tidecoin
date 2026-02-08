#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that fast rescan using block filters for descriptor wallets detects
   top-ups correctly and finds the same transactions than the slow variant."""
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import get_generate_key, set_keygen_node


KEYPOOL_SIZE = 2     # tiny keypool to force frequent top-ups
NUM_DESCRIPTORS = 9  # number of descriptors (8 default ranged ones + 1 fixed non-ranged one)
NUM_BLOCKS = 6       # number of blocks to mine


class WalletFastRescanTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[f'-keypool={KEYPOOL_SIZE}', '-blockfilterindex=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def get_wallet_txids(self, node: TestNode, wallet_name: str) -> list[str]:
        w = node.get_wallet_rpc(wallet_name)
        txs = w.listtransactions('*', 1000000)
        return [tx['txid'] for tx in txs]

    def descriptor_output_type(self, desc: str) -> str:
        if desc.startswith("pkh("):
            return "legacy"
        if desc.startswith("sh(wpkh("):
            return "p2sh-segwit"
        if desc.startswith("wpkh("):
            return "bech32"
        if desc.startswith("wsh512(pk("):
            return "bech32pq"
        raise AssertionError(f"Unsupported descriptor type in test: {desc}")

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        set_keygen_node(None)

        self.log.info("Create descriptor wallet with backup")
        WALLET_BACKUP_FILENAME = node.datadir_path / 'wallet.bak'
        node.createwallet(wallet_name='topup_test')
        w = node.get_wallet_rpc('topup_test')
        fixed_key = get_generate_key()
        w.importdescriptors([{"desc": descsum_create(f"wpkh({fixed_key.privkey})"), "timestamp": "now"}])
        descriptors = w.listdescriptors()['descriptors']
        descriptors_priv = w.listdescriptors(True)['descriptors']
        assert_equal(len(descriptors), NUM_DESCRIPTORS)
        w.backupwallet(WALLET_BACKUP_FILENAME)

        self.log.info("Create txs sending to end range address of each descriptor, triggering top-ups")
        for i in range(NUM_BLOCKS):
            self.log.info(f"Block {i+1}/{NUM_BLOCKS}")
            for desc_info in descriptors_priv:
                if 'range' in desc_info:
                    out_type = self.descriptor_output_type(desc_info['desc'])
                    if desc_info.get('internal', False):
                        addr = w.getrawchangeaddress(address_type=out_type)
                    else:
                        addr = w.getnewaddress(address_type=out_type)
                    spk = bytes.fromhex(w.getaddressinfo(addr)["scriptPubKey"])
                    self.log.info(f"-> {out_type} {'internal' if desc_info.get('internal', False) else 'external'} {addr}")
                else:
                    spk = bytes.fromhex(fixed_key.p2wpkh_script)
                    self.log.info(f"-> fixed non-range descriptor address {fixed_key.p2wpkh_addr}")
                wallet.send_to(from_node=node, scriptPubKey=spk, amount=1_000_000)
            self.generate(node, 1)

        self.log.info("Import wallet backup with block filter index")
        with node.assert_debug_log(['fast variant using block filters']):
            node.restorewallet('rescan_fast', WALLET_BACKUP_FILENAME)
        txids_fast = self.get_wallet_txids(node, 'rescan_fast')

        self.log.info("Import non-active descriptors with block filter index")
        node.createwallet(wallet_name='rescan_fast_nonactive', disable_private_keys=True, blank=True)
        with node.assert_debug_log(['fast variant using block filters']):
            w = node.get_wallet_rpc('rescan_fast_nonactive')
            w.importdescriptors([{"desc": descriptor['desc'], "timestamp": 0} for descriptor in descriptors])
        txids_fast_nonactive = self.get_wallet_txids(node, 'rescan_fast_nonactive')

        self.restart_node(0, [f'-keypool={KEYPOOL_SIZE}', '-blockfilterindex=0'])
        self.log.info("Import wallet backup w/o block filter index")
        with node.assert_debug_log(['slow variant inspecting all blocks']):
            node.restorewallet("rescan_slow", WALLET_BACKUP_FILENAME)
        txids_slow = self.get_wallet_txids(node, 'rescan_slow')

        self.log.info("Import non-active descriptors w/o block filter index")
        node.createwallet(wallet_name='rescan_slow_nonactive', disable_private_keys=True, blank=True)
        with node.assert_debug_log(['slow variant inspecting all blocks']):
            w = node.get_wallet_rpc('rescan_slow_nonactive')
            w.importdescriptors([{"desc": descriptor['desc'], "timestamp": 0} for descriptor in descriptors])
        txids_slow_nonactive = self.get_wallet_txids(node, 'rescan_slow_nonactive')

        self.log.info("Verify that all rescans found the same txs in slow and fast variants")
        txids_slow_set = set(txids_slow)
        txids_fast_set = set(txids_fast)
        txids_slow_nonactive_set = set(txids_slow_nonactive)
        txids_fast_nonactive_set = set(txids_fast_nonactive)
        assert txids_slow_set
        assert txids_fast_set
        assert txids_slow_nonactive_set
        assert txids_fast_nonactive_set
        assert_equal(txids_slow_set, txids_fast_set)
        assert_equal(txids_slow_nonactive_set, txids_fast_nonactive_set)


if __name__ == '__main__':
    WalletFastRescanTest(__file__).main()
