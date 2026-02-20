#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate raw PQ script-assets corpus entries for script_assets minimization.

Run with --dumptests and set TEST_DUMP_DIR to emit one JSON object line per file,
formatted for src/test/fuzz/script_assets_test_minimizer.cpp merge flow.
"""

from decimal import Decimal
import json
import os
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.messages import (
    COIN,
    CTxOut,
    tx_from_hex,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_greater_than


class PQScriptAssetsDumper(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.uses_wallet = True
        self.setup_clean_chain = False

    def add_options(self, parser):
        parser.add_argument(
            "--dumptests",
            action="store_true",
            default=False,
            help="Dump raw script-assets corpus entries into TEST_DUMP_DIR",
        )

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _to_sats(self, amount):
        return int(Decimal(str(amount)) * COIN)

    def _mutate_hex(self, hex_data):
        raw = bytearray.fromhex(hex_data)
        if not raw:
            return "00"
        raw[0] ^= 0x01
        return raw.hex()

    def _mutate_witness(self, witness_stack_hex):
        mutated = list(witness_stack_hex)
        for i, item in enumerate(mutated):
            if item:
                mutated[i] = self._mutate_hex(item)
                return mutated
        mutated.append("00")
        return mutated

    def _to_tx_without_witness(self, signed_hex):
        tx = tx_from_hex(signed_hex)
        return tx, tx.serialize_without_witness().hex()

    def _make_asset_entry(self, *, signed_hex, utxo, flags, comment):
        tx, tx_nowit_hex = self._to_tx_without_witness(signed_hex)
        vin_index = 0

        script_sig_hex = tx.vin[vin_index].scriptSig.hex()
        witness = []
        if vin_index < len(tx.wit.vtxinwit):
            witness = [item.hex() for item in tx.wit.vtxinwit[vin_index].scriptWitness.stack]

        bad_script_sig = script_sig_hex
        bad_witness = list(witness)
        if bad_witness:
            bad_witness = self._mutate_witness(bad_witness)
        elif bad_script_sig:
            bad_script_sig = self._mutate_hex(bad_script_sig)
        else:
            bad_script_sig = "00"

        prevout = CTxOut(
            nValue=self._to_sats(utxo["amount"]),
            scriptPubKey=bytes.fromhex(utxo["scriptPubKey"]),
        ).serialize().hex()

        return {
            "tx": tx_nowit_hex,
            "prevouts": [prevout],
            "index": vin_index,
            "flags": flags,
            "comment": comment,
            "success": {
                "scriptSig": script_sig_hex,
                "witness": witness,
            },
            "failure": {
                "scriptSig": bad_script_sig,
                "witness": bad_witness,
            },
        }

    def _find_exact_utxo(self, node, *, address, txid):
        utxos = node.listunspent(1, 9999999, [address])
        for utxo in utxos:
            if utxo["txid"] == txid:
                return utxo
        raise AssertionError(f"UTXO for address {address} and txid {txid} not found")

    def _create_signed_single_input_spend(self, node, *, utxo, destination, sighashtype):
        amount_out = Decimal(str(utxo["amount"])) - Decimal("0.00005")
        assert_greater_than(amount_out, Decimal("0"))
        raw = node.createrawtransaction(
            inputs=[{"txid": utxo["txid"], "vout": utxo["vout"]}],
            outputs=[{destination: amount_out}],
        )
        signed = node.signrawtransactionwithwallet(raw, [], sighashtype)
        assert signed["complete"]
        tx = tx_from_hex(signed["hex"])
        assert len(tx.vin) == 1
        return signed["hex"]

    def _get_destination_address(self, node, *, tag):
        for address_type in ("bech32", "legacy"):
            try:
                return node.getnewaddress(f"pq-assets-dst-{tag}", address_type)
            except JSONRPCException:
                continue
        raise AssertionError("No supported destination address type found")

    def _build_entries(self, node):
        templates = [
            ("legacy", "legacy"),
            ("p2sh-segwit", "p2sh-witness"),
            ("bech32", "witness"),
        ]
        sighash_modes = [
            ("ALL", "SIGHASH_ALL"),
            ("NONE", "SIGHASH_NONE"),
            ("SINGLE", "SIGHASH_SINGLE"),
            ("ALL|ANYONECANPAY", "SIGHASH_ALL|ANYONECANPAY"),
            ("NONE|ANYONECANPAY", "SIGHASH_NONE|ANYONECANPAY"),
            ("SINGLE|ANYONECANPAY", "SIGHASH_SINGLE|ANYONECANPAY"),
        ]
        funded = []

        for address_type, tag in templates:
            try:
                recv_addr = node.getnewaddress(f"pq-assets-{tag}", address_type)
            except JSONRPCException as e:
                self.log.info(f"Skipping unsupported address type '{address_type}': {e.error['message']}")
                continue
            fund_txid = node.sendtoaddress(recv_addr, Decimal("1.0"))
            funded.append((address_type, tag, recv_addr, fund_txid))

        assert funded, "No supported address types available for PQ script-assets dump generation"
        self.generate(node, 1)

        entries = []
        for address_type, tag, recv_addr, fund_txid in funded:
            utxo = self._find_exact_utxo(node, address=recv_addr, txid=fund_txid)
            spend_addr = self._get_destination_address(node, tag=tag)
            base_flags = "PQ_STRICT" if address_type == "legacy" else "P2SH,WITNESS,PQ_STRICT"

            for rpc_mode, label in sighash_modes:
                signed_hex = self._create_signed_single_input_spend(
                    node,
                    utxo=utxo,
                    destination=spend_addr,
                    sighashtype=rpc_mode,
                )
                entries.append(
                    self._make_asset_entry(
                        signed_hex=signed_hex,
                        utxo=utxo,
                        flags=base_flags,
                        comment=f"PQ {tag} spend ({label})",
                    )
                )

        return entries

    def _write_entries(self, entries, output_dir):
        output_dir.mkdir(parents=True, exist_ok=True)
        existing = sorted(output_dir.glob("pq_script_assets_*.json"))
        start = 0
        if existing:
            last = existing[-1].stem.rsplit("_", 1)[-1]
            start = int(last) + 1
        for i, entry in enumerate(entries):
            path = output_dir / f"pq_script_assets_{start + i:04d}.json"
            path.write_text(json.dumps(entry, sort_keys=True) + ",\n", encoding="utf-8")

    def _validate_dump_files(self, output_dir):
        files = sorted(output_dir.glob("pq_script_assets_*.json"))
        assert files, f"No script-assets dump files written to {output_dir}"
        for path in files:
            data = path.read_text(encoding="utf-8")
            assert data.endswith(",\n")
            json.loads(data[:-2])
        return files

    def run_test(self):
        node = self.nodes[0]
        entries = self._build_entries(node)
        assert_greater_than(len(entries), 0)

        if self.options.dumptests:
            dump_dir_env = os.getenv("TEST_DUMP_DIR")
            assert dump_dir_env, "TEST_DUMP_DIR must be set when using --dumptests"
            dump_dir = Path(dump_dir_env)
            self._write_entries(entries, dump_dir)
            files = self._validate_dump_files(dump_dir)
            self.log.info(f"Wrote {len(files)} script-assets raw corpus entries to {dump_dir}")
            return

        # Non-dump mode performs an internal schema sanity check in the temp dir.
        sanity_dir = Path(self.options.tmpdir) / "script_assets_dump_sanity"
        self._write_entries(entries, sanity_dir)
        files = self._validate_dump_files(sanity_dir)
        self.log.info(f"Validated {len(files)} script-assets corpus entries")


if __name__ == "__main__":
    PQScriptAssetsDumper(__file__).main()
