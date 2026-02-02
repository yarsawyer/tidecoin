// Copyright (c) 2026 The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pq/pq_txsize.h>

#include <consensus/validation.h>
#include <policy/policy.h>
#include <script/script.h>
#include <primitives/transaction.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(pq_txsize_tests)

static CTxIn MakeP2WPKHInputWithSizes(size_t sig_len, size_t pubkey_len)
{
    CTxIn in;
    in.scriptSig.clear();
    in.scriptWitness.stack.resize(2);
    in.scriptWitness.stack[0] = std::vector<unsigned char>(sig_len);
    in.scriptWitness.stack[1] = std::vector<unsigned char>(pubkey_len);
    return in;
}

static CTxIn MakeP2SHP2WPKHInputWithSizes(size_t sig_len, size_t pubkey_len)
{
    CTxIn in;
    std::vector<unsigned char> redeem_script(22, 0);
    redeem_script[1] = 0x14; // Match 0x00 0x14 <20-byte keyhash>
    in.scriptSig = CScript() << redeem_script;
    in.scriptWitness.stack.resize(2);
    in.scriptWitness.stack[0] = std::vector<unsigned char>(sig_len);
    in.scriptWitness.stack[1] = std::vector<unsigned char>(pubkey_len);
    return in;
}

BOOST_AUTO_TEST_CASE(pq_input_vsize_matches_serialized_weight)
{
    const pq::SchemeInfo* const schemes[] = {
        &pq::kFalcon512Info,
        &pq::kFalcon1024Info,
        &pq::kMLDSA44Info,
        &pq::kMLDSA65Info,
        &pq::kMLDSA87Info,
    };

    for (const auto* info : schemes) {
        const size_t pubkey_len = pq::PubKeyLenWithPrefix(*info);
        const size_t sig_len = pq::SigLenMaxInScript(*info);

        const int64_t expected_p2wpkh = pq::VSizeP2WPKHInput(sig_len, pubkey_len);
        const int64_t expected_nested = pq::VSizeP2SH_P2WPKHInput(sig_len, pubkey_len);

        const CTxIn p2wpkh = MakeP2WPKHInputWithSizes(sig_len, pubkey_len);
        const CTxIn nested = MakeP2SHP2WPKHInputWithSizes(sig_len, pubkey_len);

        BOOST_CHECK_EQUAL(expected_p2wpkh, GetVirtualTransactionInputSize(p2wpkh, 0, 0));
        BOOST_CHECK_EQUAL(expected_nested, GetVirtualTransactionInputSize(nested, 0, 0));
    }
}

BOOST_AUTO_TEST_SUITE_END()
