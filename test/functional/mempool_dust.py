#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test dust limit mempool policy (`-dustrelayfee` parameter)"""
from decimal import Decimal

from test_framework.messages import (
    COIN,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_0,
    OP_1,
    OP_RETURN,
    OP_TRUE,
)
from test_framework.script_util import (
    key_to_p2pk_script,
    key_to_p2pkh_script,
    key_to_p2wpkh_script,
    keys_to_multisig_script,
    script_to_p2sh_script,
    script_to_p2wsh_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_equal,
    get_fee,
)
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair


DUST_RELAY_TX_FEE = 3000  # default setting [sat/kvB]
# Keep in sync with src/pq/*/api.h and src/policy/policy.cpp
MAX_KNOWN_PQ_SIG_BYTES = 4627
MAX_KNOWN_PQ_PUBKEY_BYTES = 2592


def compact_size_len(size: int) -> int:
    if size < 253:
        return 1
    if size <= 0xFFFF:
        return 3
    if size <= 0xFFFFFFFF:
        return 5
    return 9


def script_push_len(payload_size: int) -> int:
    if payload_size < 0x4C:
        return 1 + payload_size
    if payload_size <= 0xFF:
        return 2 + payload_size
    if payload_size <= 0xFFFF:
        return 3 + payload_size
    return 5 + payload_size


def p2wpkh_pq_witness_bytes() -> int:
    sig_len = MAX_KNOWN_PQ_SIG_BYTES + 1  # + sighash
    pub_len = MAX_KNOWN_PQ_PUBKEY_BYTES + 1  # + scheme prefix
    return compact_size_len(2) + compact_size_len(sig_len) + sig_len + compact_size_len(pub_len) + pub_len


def p2wsh_pq_witness_bytes() -> int:
    sig_len = MAX_KNOWN_PQ_SIG_BYTES + 1  # + sighash
    pub_len = MAX_KNOWN_PQ_PUBKEY_BYTES + 1  # + scheme prefix
    witness_script_len = script_push_len(pub_len) + 1  # <pubkey> OP_CHECKSIG
    return (compact_size_len(2) + compact_size_len(sig_len) + sig_len +
            compact_size_len(witness_script_len) + witness_script_len)

def non_witness_pq_scriptsig_bytes() -> int:
    sig_len = MAX_KNOWN_PQ_SIG_BYTES + 1  # + sighash
    pub_len = MAX_KNOWN_PQ_PUBKEY_BYTES + 1  # + scheme prefix
    return compact_size_len(sig_len) + sig_len + compact_size_len(pub_len) + pub_len


class DustRelayFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-permitbaremultisig']]

    def test_dust_output(self, node: TestNode, dust_relay_fee: Decimal,
                         output_script: CScript, type_desc: str) -> None:
        # determine dust threshold (see `GetDustThreshold`)
        if output_script[0] == OP_RETURN:
            dust_threshold = 0
        else:
            tx_size = len(CTxOut(nValue=0, scriptPubKey=output_script).serialize())
            if output_script.IsWitnessProgram():
                if output_script[0] == OP_0 and output_script[1] == 20:
                    tx_size += 32 + 4 + 1 + (p2wpkh_pq_witness_bytes() // 4) + 4
                elif ((output_script[0] == OP_0 and output_script[1] == 32) or
                      (output_script[0] == OP_1 and output_script[1] == 64)):
                    tx_size += 32 + 4 + 1 + (p2wsh_pq_witness_bytes() // 4) + 4
                else:
                    tx_size += 32 + 4 + 1 + (p2wsh_pq_witness_bytes() // 4) + 4
            else:
                tx_size += 32 + 4 + 1 + non_witness_pq_scriptsig_bytes() + 4
            dust_threshold = int(get_fee(tx_size, dust_relay_fee) * COIN)
        self.log.info(f"-> Test {type_desc} output (size {len(output_script)}, limit {dust_threshold})")

        # amount right on the dust threshold should pass
        tx = self.wallet.create_self_transfer()["tx"]
        tx.vout.append(CTxOut(nValue=dust_threshold, scriptPubKey=output_script))
        tx.vout[0].nValue -= dust_threshold  # keep total output value constant
        tx_good_hex = tx.serialize().hex()
        res = node.testmempoolaccept([tx_good_hex])[0]
        assert_equal(res['allowed'], True)

        # amount just below the dust threshold should fail
        if dust_threshold > 0:
            tx.vout[1].nValue -= 1
            res = node.testmempoolaccept([tx.serialize().hex()])[0]
            assert_equal(res['allowed'], False)
            assert_equal(res['reject-reason'], 'dust')

        # finally send the transaction to avoid running out of MiniWallet UTXOs
        self.wallet.sendrawtransaction(from_node=node, tx_hex=tx_good_hex)

    def test_dustrelay(self):
        self.log.info("Test that small outputs are acceptable when dust relay rate is set to 0 that would otherwise trigger ephemeral dust rules")

        self.restart_node(0, extra_args=["-dustrelayfee=0"])

        assert_equal(self.nodes[0].getrawmempool(), [])

        # Create two dust outputs. Transaction has zero fees. both dust outputs are unspent, and would have failed individual checks.
        # The amount is 1 satoshi because create_self_transfer_multi disallows 0.
        dusty_tx = self.wallet.create_self_transfer_multi(fee_per_output=1000, amount_per_output=1, num_outputs=2)
        dust_txid = self.nodes[0].sendrawtransaction(hexstring=dusty_tx["hex"], maxfeerate=0)

        assert_equal(self.nodes[0].getrawmempool(), [dust_txid])

        # Spends one dust along with fee input, leave other dust unspent to check ephemeral dust checks aren't being enforced
        sweep_tx = self.wallet.create_self_transfer_multi(utxos_to_spend=[self.wallet.get_utxo(), dusty_tx["new_utxos"][0]])
        sweep_txid = self.nodes[0].sendrawtransaction(sweep_tx["hex"])

        mempool_entries = self.nodes[0].getrawmempool()
        assert dust_txid in mempool_entries
        assert sweep_txid in mempool_entries
        assert_equal(len(mempool_entries), 2)

        # Wipe extra arg to reset dust relay
        self.restart_node(0, extra_args=[])

        assert_equal(self.nodes[0].getrawmempool(), [])

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.test_dustrelay()
        # test_dustrelay() restarts without -permitbaremultisig; restore it for
        # subsequent bare-multisig dust threshold checks.
        self.restart_node(0, extra_args=["-permitbaremultisig"])

        # prepare output scripts of each standard type
        _, pubkey = generate_keypair()

        output_scripts = (
            (key_to_p2pk_script(pubkey),                       "P2PK"),
            (key_to_p2pkh_script(pubkey),                      "P2PKH"),
            (script_to_p2sh_script(CScript([OP_TRUE])),        "P2SH"),
            (key_to_p2wpkh_script(pubkey),                     "P2WPKH"),
            (script_to_p2wsh_script(CScript([OP_TRUE])),       "P2WSH"),
            # largest possible output script considered standard
            (keys_to_multisig_script([pubkey]*3),              "bare multisig (m-of-3)"),
            (CScript([OP_RETURN, b'superimportanthash']),      "null data (OP_RETURN)"),
        )

        # test default (no parameter), disabled (=0) and a bunch of arbitrary dust fee rates [sat/kvB]
        for dustfee_sat_kvb in (DUST_RELAY_TX_FEE, 0, 1, 66, 500, 1337, 12345, 21212, 333333):
            dustfee_btc_kvb = dustfee_sat_kvb / Decimal(COIN)
            if dustfee_sat_kvb == DUST_RELAY_TX_FEE:
                self.log.info(f"Test default dust limit setting ({dustfee_sat_kvb} sat/kvB)...")
            else:
                dust_parameter = f"-dustrelayfee={dustfee_btc_kvb:.8f}"
                self.log.info(f"Test dust limit setting {dust_parameter} ({dustfee_sat_kvb} sat/kvB)...")
                self.restart_node(0, extra_args=[dust_parameter, "-permitbaremultisig"])

            for output_script, description in output_scripts:
                self.test_dust_output(self.nodes[0], dustfee_btc_kvb, output_script, description)
            self.generate(self.nodes[0], 1)


if __name__ == '__main__':
    DustRelayFeeTest(__file__).main()
