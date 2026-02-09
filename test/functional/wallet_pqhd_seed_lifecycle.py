#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify PQHD seed import/list/select/remove lifecycle behavior."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import WalletUnlock


class WalletPQHDSeedLifecycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        wallet_name = "pqhdseed"
        self.nodes[0].createwallet(wallet_name=wallet_name)
        wallet = self.nodes[0].get_wallet_rpc(wallet_name)

        self.log.info("Initial descriptor wallet has exactly one default PQHD seed")
        initial = wallet.listpqhdseeds()
        assert_equal(len(initial), 1)
        initial_seed_id = initial[0]["seed_id"]
        assert initial[0]["default_receive"]
        assert initial[0]["default_change"]

        self.log.info("Import two deterministic seeds; re-import is idempotent")
        seed_a_hex = "11" * 32
        seed_b_hex = "22" * 32
        imported_a = wallet.importpqhdseed(seed_a_hex)
        assert imported_a["inserted"]
        imported_a_again = wallet.importpqhdseed(seed_a_hex)
        assert not imported_a_again["inserted"]
        assert_equal(imported_a_again["seed_id"], imported_a["seed_id"])
        imported_b = wallet.importpqhdseed(seed_b_hex)
        assert imported_b["inserted"]

        self.log.info("Unknown seed id must be rejected by setpqhdseed")
        assert_raises_rpc_error(
            -4,
            "Receive seed id not found in wallet",
            wallet.setpqhdseed,
            "00" * 32,
        )

        self.log.info("Switch defaults to imported seed and verify policy flags")
        wallet.setpqhdseed(imported_a["seed_id"])
        listed = wallet.listpqhdseeds()
        defaults = {entry["seed_id"]: (entry["default_receive"], entry["default_change"]) for entry in listed}
        assert_equal(defaults[imported_a["seed_id"]], (True, True))
        assert_equal(defaults[initial_seed_id], (False, False))

        self.log.info("Scheme-override derivation uses current default seed id")
        addr = wallet.getnewaddress("", "bech32", "falcon512")
        info = wallet.getaddressinfo(addr)
        assert_equal(info["pqhd_seedid"], imported_a["seed_id"])
        info_no_origin = wallet.getaddressinfo(addr, {"include_pqhd_origin": False})
        assert "pqhd_seedid" not in info_no_origin
        assert "pqhd_path" not in info_no_origin

        self.log.info("walletprocesspsbt can suppress PQHD origin metadata")
        self.generatetoaddress(self.nodes[0], 101, wallet.getnewaddress())
        outpoint = self.create_outpoints(wallet, outputs=[{wallet.getnewaddress(): 1}])[0]
        self.generate(self.nodes[0], 1)
        psbt = wallet.createpsbt([outpoint], {wallet.getnewaddress(): 0.999})
        with_origin = wallet.walletprocesspsbt(psbt, False, "ALL", False, True)
        without_origin = wallet.walletprocesspsbt(psbt, False, "ALL", False, False)
        decoded_with_origin = self.nodes[0].decodepsbt(with_origin["psbt"])
        decoded_without_origin = self.nodes[0].decodepsbt(without_origin["psbt"])
        assert "pqhd_origins" in decoded_with_origin["inputs"][0]
        assert "pqhd_origins" in decoded_with_origin["outputs"][0]
        assert "pqhd_origins" not in decoded_without_origin["inputs"][0]
        assert "pqhd_origins" not in decoded_without_origin["outputs"][0]

        self.log.info("Removing an unreferenced non-default seed succeeds")
        removed = wallet.removepqhdseed(imported_b["seed_id"])
        assert removed["removed"]
        remaining_ids = {entry["seed_id"] for entry in wallet.listpqhdseeds()}
        assert imported_b["seed_id"] not in remaining_ids

        self.log.info("Cannot remove default seed; cannot remove descriptor-referenced seed")
        assert_raises_rpc_error(
            -4,
            "Cannot remove active default PQHD seed",
            wallet.removepqhdseed,
            imported_a["seed_id"],
        )
        wallet.setpqhdseed(initial_seed_id)
        assert_raises_rpc_error(
            -4,
            "Cannot remove PQHD seed referenced by wallet descriptors",
            wallet.removepqhdseed,
            imported_a["seed_id"],
        )

        self.log.info("Encrypted wallet import path requires unlock")
        locked_wallet_name = "pqhdseedlocked"
        self.nodes[0].createwallet(wallet_name=locked_wallet_name, passphrase="pass")
        locked_wallet = self.nodes[0].get_wallet_rpc(locked_wallet_name)
        assert_raises_rpc_error(
            -4,
            "Cannot import PQHD seed while wallet is locked",
            locked_wallet.importpqhdseed,
            "33" * 32,
        )
        with WalletUnlock(locked_wallet, "pass"):
            imported_locked = locked_wallet.importpqhdseed("33" * 32)
            assert imported_locked["inserted"]


if __name__ == "__main__":
    WalletPQHDSeedLifecycleTest(__file__).main()
