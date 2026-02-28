#include <pq/pq_api.h>
#include <pq/pqhd_kdf.h>
#include <pq/pqhd_params.h>

#include <crypto/hex_base.h>
#include <crypto/sha256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace {

template <size_t N>
std::array<uint8_t, N> ParseHexArray(std::string_view hex)
{
    const auto v = ParseHex<uint8_t>(hex);
    BOOST_REQUIRE_EQUAL(v.size(), N);
    std::array<uint8_t, N> out{};
    std::copy(v.begin(), v.end(), out.begin());
    return out;
}

std::string Sha256Hex(std::span<const uint8_t> data)
{
    std::array<uint8_t, 32> out{};
    CSHA256().Write(data.data(), data.size()).Finalize(out.data());
    return HexStr(std::span<const uint8_t, 32>(out));
}

constexpr uint32_t HARDENED = 0x80000000U;

} // namespace

BOOST_AUTO_TEST_SUITE(pqhd_keygen_tests)

BOOST_AUTO_TEST_CASE(rejects_unsupported_version)
{
    const std::array<uint8_t, 64> key_material{};
    std::vector<uint8_t> pk{1, 2, 3};
    pq::SecureKeyBytes sk{4, 5, 6};
    BOOST_CHECK(!pq::KeyGenFromSeed(/*pqhd_version=*/0, pq::SchemeId::FALCON_512, std::span<const uint8_t, 64>(key_material), pk, sk));
    BOOST_CHECK(pk.empty());
    BOOST_CHECK(sk.empty());
}

BOOST_AUTO_TEST_CASE(rejects_wrong_key_material_length)
{
    const std::array<uint8_t, 63> key_material{};
    std::vector<uint8_t> pk{1, 2, 3};
    pq::SecureKeyBytes sk{4, 5, 6};
    BOOST_CHECK(!pq::KeyGenFromSeedBytes(/*pqhd_version=*/1, pq::SchemeId::FALCON_512, key_material, pk, sk));
    BOOST_CHECK(pk.empty());
    BOOST_CHECK(sk.empty());
}

BOOST_AUTO_TEST_CASE(v1_vectors_master_seed_0_all_schemes_hashes)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));

    auto run = [&](pq::SchemeId scheme_id,
                   std::array<uint32_t, 6> path,
                   std::string_view expected_pk_sha256,
                   std::string_view expected_sk_sha256) {
        const auto leaf = pqhd::DerivePath(master, path);
        BOOST_REQUIRE(leaf);
        const auto stream_key = pqhd::DeriveKeygenStreamKey(std::span<const uint8_t, 32>(leaf->node_secret),
                                                            std::span<const uint32_t>(path));
        BOOST_REQUIRE(stream_key);
        std::vector<uint8_t> pk;
        pq::SecureKeyBytes sk;
        BOOST_REQUIRE(pq::KeyGenFromSeed(/*pqhd_version=*/1, scheme_id, stream_key->Span(), pk, sk));
        BOOST_CHECK_EQUAL(Sha256Hex(pk), expected_pk_sha256);
        BOOST_CHECK_EQUAL(Sha256Hex(sk), expected_sk_sha256);
    };

    // purpose' and coin_type' are centralized in `src/pq/pqhd_params.h` (see `doc/design/pqhd.md`).
    run(pq::SchemeId::FALCON_512,
        {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 7U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U},
        "cb72ac890ce605a32850b885abcd4e83a3e30bcc68f08eaacc342bfdd30ebba5",
        "935f9316ecc62adb2b2c5ce7b2b948d848d1884528a79c3162a2e25989e84f35");

    run(pq::SchemeId::FALCON_1024,
        {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 8U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U},
        "ec638e05cfb547b3315bcd798002e512869782382cbc290561df9435fe2ba7f1",
        "dcbc3734ce83292c3efede196ac38bbc9b6f92f153974507b86b379415a1d42c");

    run(pq::SchemeId::MLDSA_44,
        {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 9U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U},
        "e507351f4903882e597367309d0f1a25053200b39c93ed5288cb8b9821ff749b",
        "3364238c559c07268cde4e7b4bb8f54c46e944804a93abaada81a0645bca26e7");

    run(pq::SchemeId::MLDSA_65,
        {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 10U, HARDENED | 2U, HARDENED | 1U, HARDENED | 5U},
        "3ef25f8229327412340beac8b81af09482e5f7b15f040e919c38cd913045fbbd",
        "f7cac55ef3f5c164e4e17a801ebd7b2cc24aabf236443761427b28c8f2e4d10e");

    run(pq::SchemeId::MLDSA_87,
        {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 11U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U},
        "1288715e0d9a64a30ab5066536b5a7a50af1a882e193ec67433a675da7b36237",
        "7b5d56dd11ae1afd25e51b27f014492742b2ca2ebca324efdb0cdcee6a40cf98");
}

BOOST_AUTO_TEST_CASE(deterministic_keypair_rejects_wrong_seed_length)
{
    {
        std::array<uint8_t, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES> pk{};
        std::array<uint8_t, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES> sk{};
        std::array<uint8_t, 47> seed{};
        BOOST_CHECK_EQUAL(PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_deterministic(pk.data(), sk.data(),
                                                                                   seed.data(), seed.size()),
                          -1);
    }
    {
        std::array<uint8_t, PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES> pk{};
        std::array<uint8_t, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES> sk{};
        std::array<uint8_t, 49> seed{};
        BOOST_CHECK_EQUAL(PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair_deterministic(pk.data(), sk.data(),
                                                                                    seed.data(), seed.size()),
                          -1);
    }
    {
        std::array<uint8_t, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES> pk{};
        std::array<uint8_t, PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES> sk{};
        std::array<uint8_t, 31> seed{};
        BOOST_CHECK_EQUAL(PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_deterministic(pk.data(), sk.data(),
                                                                                 seed.data(), seed.size()),
                          -1);
    }
    {
        std::array<uint8_t, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES> pk{};
        std::array<uint8_t, PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES> sk{};
        std::array<uint8_t, 33> seed{};
        BOOST_CHECK_EQUAL(PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_deterministic(pk.data(), sk.data(),
                                                                                  seed.data(), seed.size()),
                          -1);
    }
    {
        std::array<uint8_t, PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES> pk{};
        std::array<uint8_t, PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES> sk{};
        std::array<uint8_t, 33> seed{};
        BOOST_CHECK_EQUAL(PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair_deterministic(pk.data(), sk.data(),
                                                                                  seed.data(), seed.size()),
                          -1);
    }
}

BOOST_AUTO_TEST_SUITE_END()
