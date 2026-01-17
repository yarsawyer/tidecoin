#include <key.h>
#include <pq/pq_api.h>
#include <pq/randombytes.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

BOOST_AUTO_TEST_SUITE(pq_random_key_tests)

BOOST_AUTO_TEST_CASE(generate_keypair_smoke_all_schemes)
{
    const std::array<pq::SchemeId, 5> schemes{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_1024,
        pq::SchemeId::MLDSA_44,
        pq::SchemeId::MLDSA_65,
        pq::SchemeId::MLDSA_87,
    };

    for (const auto scheme_id : schemes) {
        const pq::SchemeInfo* info = pq::SchemeFromId(scheme_id);
        BOOST_REQUIRE(info);

        std::vector<unsigned char> pk(info->pubkey_bytes);
        std::vector<unsigned char> sk(info->seckey_bytes);
        BOOST_CHECK(pq::GenerateKeyPair(*info, pk, sk));

        // Spot-check that the keys look well-formed for this scheme.
        BOOST_CHECK(pq::IsSecretKeyEncodingValid(*info, sk));
        BOOST_CHECK_EQUAL(pk.size(), info->pubkey_bytes);
        BOOST_CHECK_EQUAL(sk.size(), info->seckey_bytes);
    }
}

BOOST_AUTO_TEST_CASE(generate_random_key_smoke)
{
    // Ensure we can generate a non-empty private key and access its pubkey
    // without triggering assertions used by wallet create paths.
    CKey key = GenerateRandomKey(pq::SchemeId::FALCON_512);
    BOOST_REQUIRE_MESSAGE(key.IsValid(), "GenerateRandomKey(pq::SchemeId::FALCON_512) produced an invalid key");

    const CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(pubkey.IsValid());
    BOOST_CHECK(key.VerifyPubKey(pubkey));
}

BOOST_AUTO_TEST_CASE(falcon_strict_sign_retry)
{
    constexpr std::array<pq::SchemeId, 2> schemes{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_1024,
    };

    std::array<unsigned char, 32> msg{};
    for (const auto scheme_id : schemes) {
        const pq::SchemeInfo* info = pq::SchemeFromId(scheme_id);
        BOOST_REQUIRE(info);

        std::vector<unsigned char> pk(info->pubkey_bytes);
        std::vector<unsigned char> sk(info->seckey_bytes);
        BOOST_REQUIRE(pq::GenerateKeyPair(*info, pk, sk));

        pq::SetFalconSignTestFailCount(1);
        std::vector<unsigned char> sig;
        BOOST_CHECK(pq::Sign(*info,
                             std::span<const unsigned char>(msg),
                             std::span<const unsigned char>(sk),
                             sig,
                             /*legacy_mode=*/false));
        BOOST_CHECK_EQUAL(pq::GetFalconSignTestFailCount(), 0);
        BOOST_CHECK(!sig.empty());
    }
}

BOOST_AUTO_TEST_CASE(falcon_strict_sign_exhausts_failures)
{
    const pq::SchemeInfo* info = pq::SchemeFromId(pq::SchemeId::FALCON_512);
    BOOST_REQUIRE(info);

    std::vector<unsigned char> pk(info->pubkey_bytes);
    std::vector<unsigned char> sk(info->seckey_bytes);
    BOOST_REQUIRE(pq::GenerateKeyPair(*info, pk, sk));

    std::array<unsigned char, 32> msg{};
    pq::SetFalconSignTestFailCount(static_cast<int>(pq::kFalconSignMaxAttempts));
    std::vector<unsigned char> sig;
    BOOST_CHECK(!pq::Sign(*info,
                          std::span<const unsigned char>(msg),
                          std::span<const unsigned char>(sk),
                          sig,
                          /*legacy_mode=*/false));
}

BOOST_AUTO_TEST_SUITE_END()
