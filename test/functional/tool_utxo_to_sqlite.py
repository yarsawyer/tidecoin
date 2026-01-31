#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test utxo-to-sqlite conversion tool"""
import os.path
try:
    import sqlite3
except ImportError:
    pass
import subprocess
import sys

from test_framework.messages import (
    COutPoint,
    CTxOut,
)
from test_framework.crypto.muhash import MuHash3072
from test_framework.script import (
    CScript,
    CScriptOp,
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
from test_framework.util import (
    assert_equal,
)
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair


def calculate_muhash_from_sqlite_utxos(filename):
    muhash = MuHash3072()
    con = sqlite3.connect(filename)
    cur = con.cursor()
    for (txid_hex, vout, value, coinbase, height, spk_hex) in cur.execute("SELECT * FROM utxos"):
        # serialize UTXO for MuHash (see function `TxOutSer` in the  coinstats module)
        utxo_ser = COutPoint(int(txid_hex, 16), vout).serialize()
        utxo_ser += (height * 2 + coinbase).to_bytes(4, 'little')
        utxo_ser += CTxOut(value, bytes.fromhex(spk_hex)).serialize()
        muhash.insert(utxo_ser)
    con.close()
    return muhash.digest()[::-1].hex()


class UtxoToSqliteTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # we want to create some UTXOs with non-standard output scripts
        self.extra_args = [['-acceptnonstdtxn=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_py_sqlite3()

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.log.info('Create UTXOs with various output script types')
        for i in range(1, 10+1):
            _, pubkey = generate_keypair(wif=True)
            _, pubkey2 = generate_keypair(wif=True)

            # add output scripts for P2PKH, P2SH, P2PK, multisig, segwit, and large scripts
            output_scripts = (
                key_to_p2pkh_script(pubkey),
                script_to_p2sh_script(key_to_p2pkh_script(pubkey)),
                key_to_p2pk_script(pubkey),
                keys_to_multisig_script([pubkey, pubkey2][:max(1, i % 2 + 1)]),
                key_to_p2wpkh_script(pubkey),
                script_to_p2wsh_script(key_to_p2pkh_script(pubkey)),
                CScript([CScriptOp.encode_op_n(i)]*(1000*i)),  # large script (up to 10000 bytes)
            )

            # create outputs and mine them in a block
            for output_script in output_scripts:
                wallet.send_to(from_node=node, scriptPubKey=output_script, amount=i, fee=20000)
            self.generate(wallet, 1)

        self.log.info('Dump UTXO set via `dumptxoutset` RPC')
        input_filename = os.path.join(self.options.tmpdir, "utxos.dat")
        node.dumptxoutset(input_filename, "latest")

        self.log.info('Convert UTXO set from compact-serialized format to sqlite format')
        output_filename = os.path.join(self.options.tmpdir, "utxos.sqlite")
        base_dir = self.config["environment"]["SRCDIR"]
        utxo_to_sqlite_path = os.path.join(base_dir, "contrib", "utxo-tools", "utxo_to_sqlite.py")
        subprocess.run([sys.executable, utxo_to_sqlite_path, input_filename, output_filename],
                       check=True, stderr=subprocess.STDOUT)

        self.log.info('Verify that both UTXO sets match by comparing their MuHash')
        muhash_sqlite = calculate_muhash_from_sqlite_utxos(output_filename)
        muhash_compact_serialized = node.gettxoutsetinfo('muhash')['muhash']
        assert_equal(muhash_sqlite, muhash_compact_serialized)


if __name__ == "__main__":
    UtxoToSqliteTest(__file__).main()
