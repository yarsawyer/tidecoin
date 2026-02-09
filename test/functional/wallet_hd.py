#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Hierarchical Deterministic wallet function."""

import shutil

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletHDTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[], ['-keypool=0']]
        # whitelist peers to speed up tx relay / mempool sync
        self.noban_tx_relay = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_pqhd_address_origin(self, info, expected_seed_id, expected_branch=None, expected_index=None):
        assert "pqhd_seedid" in info
        assert "pqhd_path" in info
        assert_equal(info["pqhd_seedid"], expected_seed_id)

        parts = info["pqhd_path"].split("/")
        # Path shape: .../<account>h/<branch>h/<index>h
        assert len(parts) >= 2
        assert parts[-1].endswith("h")
        assert parts[-2].endswith("h")

        branch = int(parts[-2][:-1])
        index = int(parts[-1][:-1])
        if expected_branch is not None:
            assert_equal(branch, expected_branch)
        if expected_index is not None:
            assert_equal(index, expected_index)

        return branch, index

    def run_test(self):
        seeds = self.nodes[1].listpqhdseeds()
        default_seed = next((s for s in seeds if s["default_receive"]), None)
        assert default_seed is not None
        expected_seed_id = default_seed["seed_id"]

        # Establish the wallet's external descriptor chain metadata.
        ext_info = self.nodes[1].getaddressinfo(self.nodes[1].getnewaddress())
        assert 'parent_desc' in ext_info
        ext_parent_desc = ext_info['parent_desc']
        self.assert_pqhd_address_origin(ext_info, expected_seed_id, expected_branch=0, expected_index=0)

        # create an internal key
        change_addr = self.nodes[1].getrawchangeaddress()
        change_addrV = self.nodes[1].getaddressinfo(change_addr)
        assert_equal(change_addrV["ischange"], True)
        assert 'parent_desc' in change_addrV
        change_parent_desc = change_addrV['parent_desc']
        assert ext_parent_desc != change_parent_desc
        self.assert_pqhd_address_origin(change_addrV, expected_seed_id, expected_branch=1, expected_index=0)

        # Take a wallet backup before deriving addresses, then verify deterministic
        # derivation and recovery after restore/rescan.
        self.nodes[1].backupwallet(self.nodes[1].datadir_path / "hd.bak")

        # Derive some HD addresses and remember the last
        # Also send funds to each add
        self.generate(self.nodes[0], COINBASE_MATURITY + 1)
        hd_add = None
        hd_add_list = []
        hd_path_list = []
        NUM_HD_ADDS = 10
        for i in range(1, NUM_HD_ADDS + 1):
            hd_add = self.nodes[1].getnewaddress()
            hd_info = self.nodes[1].getaddressinfo(hd_add)
            assert 'parent_desc' in hd_info
            assert_equal(hd_info["parent_desc"], ext_parent_desc)
            _, addr_index = self.assert_pqhd_address_origin(hd_info, expected_seed_id, expected_branch=0)
            assert_equal(addr_index, i)
            hd_add_list.append(hd_add)
            hd_path_list.append(hd_info["pqhd_path"])
            self.nodes[0].sendtoaddress(hd_add, 1)
            self.generate(self.nodes[0], 1)
        # create an internal key (again)
        change_addr = self.nodes[1].getrawchangeaddress()
        change_addrV = self.nodes[1].getaddressinfo(change_addr)
        assert_equal(change_addrV["ischange"], True)
        assert_equal(change_addrV["parent_desc"], change_parent_desc)
        self.assert_pqhd_address_origin(change_addrV, expected_seed_id, expected_branch=1, expected_index=1)

        self.sync_all()
        assert_equal(self.nodes[1].getbalance(), NUM_HD_ADDS)

        self.log.info("Restore backup ...")
        self.stop_node(1)
        # we need to delete the complete chain directory
        # otherwise node1 would auto-recover all funds in flag the keypool keys as used
        shutil.rmtree(self.nodes[1].blocks_path)
        shutil.rmtree(self.nodes[1].chain_path / "chainstate")
        shutil.copyfile(
            self.nodes[1].datadir_path / "hd.bak",
            self.nodes[1].wallets_path / self.default_wallet_name / self.wallet_data_filename
        )
        self.start_node(1)

        # Assert that derivation is deterministic
        hd_add_2 = None
        for i in range(1, NUM_HD_ADDS + 1):
            hd_add_2 = self.nodes[1].getnewaddress()
            assert_equal(hd_add_2, hd_add_list[i - 1])
            restored_info = self.nodes[1].getaddressinfo(hd_add_2)
            self.assert_pqhd_address_origin(restored_info, expected_seed_id, expected_branch=0, expected_index=i)
            assert_equal(restored_info["pqhd_path"], hd_path_list[i - 1])
        assert_equal(hd_add, hd_add_2)
        self.connect_nodes(0, 1)
        self.sync_all()

        # Needs rescan
        self.nodes[1].rescanblockchain()
        assert_equal(self.nodes[1].getbalance(), NUM_HD_ADDS)

        # Try a RPC based rescan
        self.stop_node(1)
        shutil.rmtree(self.nodes[1].blocks_path)
        shutil.rmtree(self.nodes[1].chain_path / "chainstate")
        shutil.copyfile(
            self.nodes[1].datadir_path / "hd.bak",
            self.nodes[1].wallets_path / self.default_wallet_name / self.wallet_data_filename
        )
        self.start_node(1, extra_args=self.extra_args[1])
        self.connect_nodes(0, 1)
        self.sync_all()
        # Wallet automatically scans blocks older than key on startup
        assert_equal(self.nodes[1].getbalance(), NUM_HD_ADDS)
        out = self.nodes[1].rescanblockchain(0, 1)
        assert_equal(out['start_height'], 0)
        assert_equal(out['stop_height'], 1)
        out = self.nodes[1].rescanblockchain()
        assert_equal(out['start_height'], 0)
        assert_equal(out['stop_height'], self.nodes[1].getblockcount())
        assert_equal(self.nodes[1].getbalance(), NUM_HD_ADDS)

        # send a tx and make sure its using the internal chain for the changeoutput
        txid = self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        outs = self.nodes[1].gettransaction(txid=txid, verbose=True)['decoded']['vout']
        found_change = False
        for out in outs:
            if out['value'] == 1 or 'address' not in out['scriptPubKey']:
                continue
            info = self.nodes[1].getaddressinfo(out['scriptPubKey']['address'])
            if info.get("ismine") and info.get("ischange"):
                found_change = True
        assert_equal(found_change, True)


if __name__ == '__main__':
    WalletHDTest(__file__).main()
