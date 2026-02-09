// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <node/types.h>
#include <addresstype.h>
#include <pq/pqhd_params.h>
#include <psbt.h>
#include <script/script.h>
#include <test/util/test_controls.h>
#include <util/strencodings.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <wallet/test/wallet_test_fixture.h>

using namespace util::hex_literals;

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(psbt_wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(psbt_updater_test)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);

    // Create prevtxs and add to wallet
    DataStream s_prev_tx1{
        "0200000000010158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7501000000171600145f275f436b09a8cc9a2eb2a2f528485c68a56323feffffff02d8231f1b0100000017a914aed962d6654f9a2b36608eb9d64d2b260db4f1118700c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88702483045022100a22edcc6e5bc511af4cc4ae0de0fcd75c7e04d8c1c3a8aa9d820ed4b967384ec02200642963597b9b1bc22c75e9f3e117284a962188bf5e8a74c895089046a20ad770121035509a48eb623e10aace8bfd0212fdb8a8e5af3c94b0b133b95e114cab89e4f7965000000"_hex,
    };
    CTransactionRef prev_tx1;
    s_prev_tx1 >> TX_WITH_WITNESS(prev_tx1);
    m_wallet.mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(prev_tx1->GetHash()), std::forward_as_tuple(prev_tx1, TxStateInactive{}));

    DataStream s_prev_tx2{
        "0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000"_hex,
    };
    CTransactionRef prev_tx2;
    s_prev_tx2 >> TX_WITH_WITNESS(prev_tx2);
    m_wallet.mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(prev_tx2->GetHash()), std::forward_as_tuple(prev_tx2, TxStateInactive{}));

    // Call FillPSBT
    PartiallySignedTransaction psbtx;
    DataStream ssData{
        "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000"_hex,
    };
    ssData >> psbtx;

    // Fill transaction with wallet data. Tidecoin PSBT does not emit BIP32 derivations.
    bool complete = true;
    const auto err = m_wallet.FillPSBT(psbtx, complete, std::nullopt, /*sign=*/false);
    BOOST_REQUIRE(!err);
    BOOST_CHECK(!complete);
}

BOOST_AUTO_TEST_CASE(psbt_fill_and_sign_pq_p2wpkh)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    // Create a wallet-owned destination and a corresponding P2WPKH scriptPubKey.
    const CTxDestination dest = *Assert(m_wallet.GetNewDestination(OutputType::BECH32, ""));
    const CScript script_pub_key = GetScriptForDestination(dest);

    // Spend a dummy UTXO paying to our wallet. Provide the input value via witness_utxo so
    // the wallet can produce a segwit signature.
    CMutableTransaction mtx;
    mtx.vin.emplace_back(CTxIn{Txid::FromUint256(uint256::ONE), 0});
    mtx.vout.emplace_back(CTxOut{1, CScript() << OP_TRUE});
    PartiallySignedTransaction psbtx{mtx};
    psbtx.inputs.at(0).witness_utxo = CTxOut{1 * COIN, script_pub_key};

    bool complete{false};
    const auto err = m_wallet.FillPSBT(psbtx, complete, std::nullopt, /*sign=*/true);
    BOOST_REQUIRE(!err);
    BOOST_CHECK(complete);
    BOOST_CHECK(psbtx.inputs.at(0).final_script_sig.empty());
    BOOST_CHECK_EQUAL(psbtx.inputs.at(0).final_script_witness.stack.size(), 2U);
}

BOOST_AUTO_TEST_CASE(psbt_fill_emits_pqhd_origin_records)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    LOCK(m_wallet.cs_wallet);
    m_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    m_wallet.SetupDescriptorScriptPubKeyMans();

    const CTxDestination input_dest = *Assert(m_wallet.GetNewDestination(OutputType::BECH32, ""));
    const CTxDestination output_dest = *Assert(m_wallet.GetNewDestination(OutputType::BECH32, ""));
    const CScript input_script = GetScriptForDestination(input_dest);
    const CScript output_script = GetScriptForDestination(output_dest);

    CMutableTransaction mtx;
    mtx.vin.emplace_back(CTxIn{Txid::FromUint256(uint256::ONE), 0});
    mtx.vout.emplace_back(CTxOut{1, output_script});
    PartiallySignedTransaction psbtx{mtx};
    psbtx.inputs.at(0).witness_utxo = CTxOut{1 * COIN, input_script};

    bool complete{false};
    const auto err = m_wallet.FillPSBT(psbtx, complete, std::nullopt, /*sign=*/false, /*n_signed=*/nullptr, /*finalize=*/true, /*include_pqhd_origins=*/true);
    BOOST_REQUIRE(!err);
    BOOST_CHECK(!complete);

    auto extract_origin = [](const std::set<PSBTProprietary>& records) -> std::optional<psbt::tidecoin::PQHDOrigin> {
        for (const auto& record : records) {
            if (auto decoded = psbt::tidecoin::DecodePQHDOrigin(record)) return decoded;
        }
        return std::nullopt;
    };

    const auto input_origin = extract_origin(psbtx.inputs.at(0).m_proprietary);
    const auto output_origin = extract_origin(psbtx.outputs.at(0).m_proprietary);
    BOOST_REQUIRE(input_origin);
    BOOST_REQUIRE(output_origin);

    BOOST_CHECK_EQUAL(input_origin->path_hardened.size(), output_origin->path_hardened.size());
    BOOST_CHECK(input_origin->path_hardened.size() >= 3);
    BOOST_CHECK_EQUAL(input_origin->path_hardened.at(0), 0x80000000U | pqhd::PURPOSE);
    BOOST_CHECK_EQUAL(input_origin->path_hardened.at(1), 0x80000000U | pqhd::COIN_TYPE);
    BOOST_CHECK_EQUAL(output_origin->path_hardened.at(0), 0x80000000U | pqhd::PURPOSE);
    BOOST_CHECK_EQUAL(output_origin->path_hardened.at(1), 0x80000000U | pqhd::COIN_TYPE);

    // Current wallet default scheme for receive/change is Falcon-512.
    BOOST_CHECK_EQUAL(input_origin->pubkey[0], static_cast<uint8_t>(pq::SchemeId::FALCON_512));
    BOOST_CHECK_EQUAL(output_origin->pubkey[0], static_cast<uint8_t>(pq::SchemeId::FALCON_512));
    BOOST_CHECK_EQUAL(input_origin->path_hardened.at(2), 0x80000000U | static_cast<uint8_t>(pq::SchemeId::FALCON_512));
    BOOST_CHECK_EQUAL(output_origin->path_hardened.at(2), 0x80000000U | static_cast<uint8_t>(pq::SchemeId::FALCON_512));

    // Metadata emission is configurable and can be disabled for privacy-sensitive flows.
    PartiallySignedTransaction psbtx_no_origin{mtx};
    psbtx_no_origin.inputs.at(0).witness_utxo = CTxOut{1 * COIN, input_script};
    complete = false;
    const auto err_no_origin = m_wallet.FillPSBT(psbtx_no_origin, complete, std::nullopt, /*sign=*/false, /*n_signed=*/nullptr, /*finalize=*/true, /*include_pqhd_origins=*/false);
    BOOST_REQUIRE(!err_no_origin);
    BOOST_CHECK(!complete);
    BOOST_CHECK(psbtx_no_origin.inputs.at(0).m_proprietary.empty());
    BOOST_CHECK(psbtx_no_origin.outputs.at(0).m_proprietary.empty());
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
