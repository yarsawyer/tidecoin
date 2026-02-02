// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <pq/pq_scheme.h>
#include <pq/pqhd_params.h>
#include <test/util/test_controls.h>
#include <wallet/test/wallet_test_fixture.h>
#include <script/solver.h>
#include <util/string.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>
#include <wallet/test/util.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(scriptpubkeyman_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(DescriptorScriptPubKeyManTests)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet keystore(chain.get(), "", CreateMockableWalletDatabase());
    auto key_scriptpath = GenerateRandomKey(pq::SchemeId::FALCON_512);

    // Verify that a SigningProvider for a pubkey is only returned if its corresponding private key is available
    auto key_internal = GenerateRandomKey(pq::SchemeId::FALCON_512);
    std::string desc_str = "wpkh(" + EncodeSecret(key_internal) + ")";
    auto spk_man1 = CreateDescriptor(keystore, desc_str, true);
    BOOST_CHECK(spk_man1 != nullptr);
    auto signprov_keypath_spendable = spk_man1->GetSigningProvider(key_internal.GetPubKey());
    BOOST_CHECK(signprov_keypath_spendable != nullptr);

    desc_str = "wpkh(" + HexStr(key_scriptpath.GetPubKey()) + ")";
    auto spk_man2 = CreateDescriptor(keystore, desc_str, true);
    BOOST_CHECK(spk_man2 != nullptr);
    auto signprov_keypath_pubonly = spk_man2->GetSigningProvider(key_scriptpath.GetPubKey());
    BOOST_CHECK(signprov_keypath_pubonly == nullptr);
}

BOOST_AUTO_TEST_CASE(PQHDSchemeGatePreAuxpow)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }

    uint256 seed_id;
    {
        LOCK(wallet.cs_wallet);
        auto policy = wallet.GetPQHDPolicy();
        BOOST_REQUIRE(policy);
        seed_id = policy->default_seed_id;
    }

    const std::string desc_str = strprintf("wpkh(pqhd(%s)/%uh/%uh/9h/0h/0h/*h)",
                                           seed_id.ToString(), pqhd::PURPOSE, pqhd::COIN_TYPE);
    auto spk_man = CreateDescriptor(wallet, desc_str, true);
    BOOST_REQUIRE(spk_man != nullptr);

    auto res = spk_man->GetNewDestination(OutputType::BECH32);
    const Consensus::Params& params = Params().GetConsensus();
    const int target_height = wallet.GetTargetHeightForOutputs();
    const bool allowed = pq::IsSchemeAllowedAtHeight(pq::SchemeId::MLDSA_44, params, target_height);
    if (allowed) {
        BOOST_CHECK(res.has_value());
    } else {
        BOOST_CHECK(!res);
    }
}

BOOST_AUTO_TEST_CASE(PQHDInternalDescriptorUsesDefaultScheme)
{
    REQUIRE_WALLET_TESTS_ENABLED();
    std::unique_ptr<interfaces::Chain>& chain = m_node.chain;

    CWallet wallet(chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }

    auto spk_man = wallet.GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true);
    BOOST_REQUIRE(spk_man);
    auto* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
    BOOST_REQUIRE(desc_spk_man);

    LOCK(desc_spk_man->cs_desc_man);
    const std::optional<uint8_t> scheme_prefix = desc_spk_man->GetWalletDescriptor().descriptor->GetPQHDSchemePrefix();
    BOOST_REQUIRE(scheme_prefix);
    BOOST_CHECK_EQUAL(*scheme_prefix, static_cast<uint8_t>(pq::SchemeId::FALCON_512));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
