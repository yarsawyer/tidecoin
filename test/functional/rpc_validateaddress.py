#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test validateaddress for main chain"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.descriptors import descsum_create
from test_framework.wallet_util import generate_keypair
from test_framework.script_util import key_to_p2pkh_script, key_to_p2wpkh_script

from test_framework.util import assert_equal

INVALID_DATA = [
    # BIP 173
    (
        "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # Invalid hrp
        [],
    ),
    ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "Invalid Bech32 checksum", [41]),
    (
        "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
        "Invalid Bech32 address witness version",
        [],
    ),
    (
        "bc1rw5uspcuh",
        "Unsupported Segwit witness version",  # Invalid program length (v1 unsupported)
        [],
    ),
    (
        "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
        "Unsupported Segwit witness version",  # Invalid program length (v1 unsupported)
        [],
    ),
    (
        "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
        "Invalid Bech32 v0 address program size (16 bytes), per BIP141",
        [],
    ),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # tb1, Mixed case
        [],
    ),
    (
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3t4",
        "Invalid character or mixed case",  # bc1, Mixed case, not in BIP 173 test vectors
        [40],
    ),
    (
        "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
        "Unsupported Segwit witness version",  # Wrong padding (v1 unsupported)
        [],
    ),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # tb1, Non-zero padding in 8-to-5 conversion
        [],
    ),
    ("bc1gmk9yu", "Empty Bech32 data section", []),
    # BIP 350
    (
        "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # Invalid human-readable part
        [],
    ),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
        "Unsupported Segwit witness version",  # v1 uses Bech32 checksum here
        [],
    ),
    (
        "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # tb1, Invalid checksum (Bech32 instead of Bech32m)
        [],
    ),
    (
        "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
        "Unsupported Segwit witness version",  # v1 uses Bech32 checksum here
        [],
    ),
    (
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
        "Version 0 witness address must use Bech32 checksum",  # Invalid checksum (Bech32m instead of Bech32)
        [],
    ),
    (
        "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # tb1, Invalid checksum (Bech32m instead of Bech32)
        [],
    ),
    (
        "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
        "Invalid Base 32 character",  # Invalid character in checksum
        [59],
    ),
    (
        "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
        "Invalid Bech32 address witness version",
        [],
    ),
    ("bc1pw5dgrnzv", "Unsupported Segwit witness version", []),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
        "Unsupported Segwit witness version",
        [],
    ),
    (
        "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
        "Invalid Bech32 v0 address program size (16 bytes), per BIP141",
        [],
    ),
    (
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # tb1, Mixed case
        [],
    ),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
        "Unsupported Segwit witness version",  # zero padding of more than 4 bits (v1 unsupported)
        [],
    ),
    (
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # tb1, Non-zero padding in 8-to-5 conversion
        [],
    ),
    ("bc1gmk9yu", "Empty Bech32 data section", []),
    (
        "bc1pfeessrawgf",
        "Unsupported Segwit witness version",
        [],
    ),
]
class ValidateAddressMainTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.chain = ""  # main
        self.num_nodes = 1
        self.extra_args = [["-prune=899"]] * self.num_nodes

    def check_valid(self, addr, spk):
        info = self.nodes[0].validateaddress(addr)
        assert_equal(info["isvalid"], True)
        assert_equal(info["scriptPubKey"], spk)
        assert "error" not in info
        assert "error_locations" not in info

    def check_invalid(self, addr, error_str, error_locations):
        res = self.nodes[0].validateaddress(addr)
        assert_equal(res["isvalid"], False)
        if res["error"] != error_str:
            # Tidecoin rejects non-network HRP strings earlier in DecodeDestination,
            # which maps many Bitcoin-vector failures to one generic decode error.
            assert res["error"] in {
                "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
                "Invalid checksum or length of Base58 address (P2PKH or P2SH)",
                "Invalid or unsupported Base58-encoded address.",
                "Invalid length for Base58 address (P2PKH or P2SH)",
            }
            assert_equal(res["error_locations"], [])
            return
        assert_equal(res["error_locations"], error_locations)

    def test_validateaddress(self):
        for (addr, error, locs) in INVALID_DATA:
            self.check_invalid(addr, error, locs)

        # Use chain-native vectors for valid address checks.
        _, pub = generate_keypair()
        valid_data = [
            (
                self.nodes[0].deriveaddresses(descsum_create(f"pkh({pub.hex()})"))[0],
                key_to_p2pkh_script(pub).hex(),
            ),
            (
                self.nodes[0].deriveaddresses(descsum_create(f"wpkh({pub.hex()})"))[0],
                key_to_p2wpkh_script(pub).hex(),
            ),
        ]
        for (addr, spk) in valid_data:
            self.check_valid(addr, spk)

    def run_test(self):
        self.test_validateaddress()


if __name__ == "__main__":
    ValidateAddressMainTest(__file__).main()
