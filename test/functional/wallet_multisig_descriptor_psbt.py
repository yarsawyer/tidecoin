#!/usr/bin/env python3
# Copyright (c) 2021-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a basic M-of-N multisig setup between multiple people using descriptor wallets and PSBTs, as well as a signing flow.

This is meant to be documentation as much as functional tests, so it is kept as simple and readable as possible.
"""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_approx,
    assert_equal,
)
from test_framework.wallet_util import generate_keypair


class WalletMultisigDescriptorPSBTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.wallet_names = []
        self.extra_args = [["-keypool=100"]] * self.num_nodes

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def _check_psbt(psbt, to, value, multisig):
        """Helper function for any of the N participants to check the psbt with decodepsbt and verify it is OK before signing."""
        tx = multisig.decodepsbt(psbt)["tx"]
        amount = 0
        for vout in tx["vout"]:
            address = vout["scriptPubKey"]["address"]
            assert_equal(multisig.getaddressinfo(address)["ischange"], address != to)
            if address == to:
                amount += vout["value"]
        assert_approx(amount, float(value), vspan=0.001)

    def participants_create_multisigs(self, external_xpubs, internal_xpubs):
        """The multisig is created by importing the following descriptors. The resulting wallet is watch-only and every participant can do this."""
        for i, node in enumerate(self.nodes):
            node.createwallet(wallet_name=f"{self.name}_{i}", blank=True, disable_private_keys=True)
            multisig = node.get_wallet_rpc(f"{self.name}_{i}")
            external = multisig.getdescriptorinfo(f"wsh(sortedmulti({self.M},{','.join(external_xpubs)}))")
            internal = multisig.getdescriptorinfo(f"wsh(sortedmulti({self.M},{','.join(internal_xpubs)}))")
            result = multisig.importdescriptors([
                {  # receiving addresses (internal: False)
                    "desc": external["descriptor"],
                    "active": True,
                    "internal": False,
                    "timestamp": "now",
                },
                {  # change addresses (internal: True)
                    "desc": internal["descriptor"],
                    "active": True,
                    "internal": True,
                    "timestamp": "now",
                },
            ])
            assert all(r["success"] for r in result)
            yield multisig

    def run_test(self):
        self.M = 2
        self.N = self.num_nodes
        self.name = f"{self.M}_of_{self.N}_multisig"
        self.log.info(f"Testing {self.name}...")

        # Generate deterministic PQ keypairs for all participants
        keypairs = [generate_keypair() for _ in range(self.N)]
        pubkeys = [pub.hex() for _, pub in keypairs]

        participants = {
            # Every participant imports its own private key (WIF) to sign.
            "signers": [node.get_wallet_rpc(node.createwallet(wallet_name=f"participant_{self.nodes.index(node)}")["name"]) for node in self.nodes],
            "multisigs": []
        }

        self.log.info("Import participant private keys (WIF) into signer wallets...")
        for signer, (wif, _) in zip(participants["signers"], keypairs):
            res = signer.importdescriptors([{
                "desc": descsum_create(f"wpkh({wif})"),
                "timestamp": "now",
                "active": False,
            }])
            assert all(r["success"] for r in res)

        self.log.info("Generate and exchange pubkeys...")
        external_xpubs = pubkeys
        internal_xpubs = pubkeys

        self.log.info("Every participant imports the following descriptors to create the watch-only multisig...")
        participants["multisigs"] = list(self.participants_create_multisigs(external_xpubs, internal_xpubs))

        self.log.info("Check that every participant's multisig generates the same addresses...")
        for _ in range(10):  # we check that the first 10 generated addresses are the same for all participant's multisigs
            receive_addresses = [multisig.getnewaddress() for multisig in participants["multisigs"]]
            assert all(address == receive_addresses[0] for address in receive_addresses)
            change_addresses = [multisig.getrawchangeaddress() for multisig in participants["multisigs"]]
            assert all(address == change_addresses[0] for address in change_addresses)

        self.log.info("Get a mature utxo to send to the multisig...")
        coordinator_wallet = participants["signers"][0]
        self.generatetoaddress(self.nodes[0], 101, coordinator_wallet.getnewaddress())

        deposit_amount = 6.15
        multisig_receiving_address = participants["multisigs"][0].getnewaddress()
        self.log.info("Send funds to the resulting multisig receiving address...")
        coordinator_wallet.sendtoaddress(multisig_receiving_address, deposit_amount)
        self.generate(self.nodes[0], 1)
        for participant in participants["multisigs"]:
            assert_approx(participant.getbalance(), deposit_amount, vspan=0.001)

        self.log.info("Send a transaction from the multisig!")
        to = participants["signers"][self.N - 1].getnewaddress()
        value = 1
        self.log.info("First, make a sending transaction, created using `walletcreatefundedpsbt` (anyone can initiate this)...")
        psbt = participants["multisigs"][0].walletcreatefundedpsbt(inputs=[], outputs={to: value}, feeRate=0.00010)

        psbts = []
        self.log.info("Now at least M users check the psbt with decodepsbt and (if OK) signs it with walletprocesspsbt...")
        for m in range(self.M):
            signers_multisig = participants["multisigs"][m]
            self._check_psbt(psbt["psbt"], to, value, signers_multisig)
            signing_wallet = participants["signers"][m]
            partially_signed_psbt = signing_wallet.walletprocesspsbt(psbt["psbt"])
            psbts.append(partially_signed_psbt["psbt"])

        self.log.info("Finally, collect the signed PSBTs with combinepsbt, finalizepsbt, then broadcast the resulting transaction...")
        combined = coordinator_wallet.combinepsbt(psbts)
        finalized = coordinator_wallet.finalizepsbt(combined)
        coordinator_wallet.sendrawtransaction(finalized["hex"])

        self.log.info("Check that balances are correct after the transaction has been included in a block.")
        self.generate(self.nodes[0], 1)
        assert_approx(participants["multisigs"][0].getbalance(), deposit_amount - value, vspan=0.001)
        assert_equal(participants["signers"][self.N - 1].getbalance(), value)

        self.log.info("Send another transaction from the multisig, this time with a daisy chained signing flow (one after another in series)!")
        psbt = participants["multisigs"][0].walletcreatefundedpsbt(inputs=[], outputs={to: value}, feeRate=0.00010)
        for m in range(self.M):
            signers_multisig = participants["multisigs"][m]
            self._check_psbt(psbt["psbt"], to, value, signers_multisig)
            signing_wallet = participants["signers"][m]
            psbt = signing_wallet.walletprocesspsbt(psbt["psbt"])
            assert_equal(psbt["complete"], m == self.M - 1)
        coordinator_wallet.sendrawtransaction(psbt["hex"])

        self.log.info("Check that balances are correct after the transaction has been included in a block.")
        self.generate(self.nodes[0], 1)
        assert_approx(participants["multisigs"][0].getbalance(), deposit_amount - (value * 2), vspan=0.001)
        assert_equal(participants["signers"][self.N - 1].getbalance(), value * 2)


if __name__ == "__main__":
    WalletMultisigDescriptorPSBTTest(__file__).main()
