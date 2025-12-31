#include <pq/pq_api.h>
#include <pq/pqhd_kdf.h>
#include <pq/pqhd_params.h>

#include <psbt.h>

#include <script/keyorigin.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace {

template <size_t N>
std::array<uint8_t, N> ParseHexArray(const std::string_view hex)
{
    const auto v = ParseHex<uint8_t>(hex);
    BOOST_REQUIRE_EQUAL(v.size(), N);
    std::array<uint8_t, N> out{};
    std::copy(v.begin(), v.end(), out.begin());
    return out;
}

constexpr uint32_t HARDENED = 0x80000000U;

CPubKey DerivePQPubKeyV1(pq::SchemeId scheme_id, std::span<const uint32_t, 6> path_hardened)
{
    const auto master_seed = ParseHexArray<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto master = pqhd::MakeMasterNode(std::span<const uint8_t, 32>(master_seed));

    const auto leaf = pqhd::DerivePath(master, path_hardened);
    BOOST_REQUIRE(leaf);
    const auto material = pqhd::DeriveLeafMaterialV1(std::span<const uint8_t, 32>(leaf->node_secret), path_hardened);
    BOOST_REQUIRE(material);
    BOOST_REQUIRE(material->scheme_id == scheme_id);

    std::vector<uint8_t> pk;
    pq::SecureKeyBytes sk;
    BOOST_REQUIRE(pq::KeyGenFromSeed(/*pqhd_version=*/1, scheme_id, material->stream_key.Span(), pk, sk));

    const pq::SchemeInfo* scheme = pq::SchemeFromId(scheme_id);
    BOOST_REQUIRE(scheme);
    BOOST_REQUIRE_EQUAL(pk.size(), scheme->pubkey_bytes);

    std::vector<uint8_t> prefixed_pubkey(pk.size() + 1);
    prefixed_pubkey[0] = scheme->prefix;
    std::copy(pk.begin(), pk.end(), prefixed_pubkey.begin() + 1);
    return CPubKey{prefixed_pubkey};
}

} // namespace

BOOST_AUTO_TEST_SUITE(psbt_pq_keypaths_tests)

BOOST_AUTO_TEST_CASE(hd_keypaths_roundtrip_accepts_large_pq_pubkeys)
{
    struct Vector {
        pq::SchemeId scheme_id;
        std::array<uint32_t, 6> path;
    };

    const std::array<Vector, 2> vectors{{
        {pq::SchemeId::FALCON_512, {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 7U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U}},
        {pq::SchemeId::MLDSA_87,   {HARDENED | pqhd::PURPOSE, HARDENED | pqhd::COIN_TYPE, HARDENED | 11U, HARDENED | 0U, HARDENED | 0U, HARDENED | 0U}},
    }};

    for (const auto& vec : vectors) {
        const CPubKey pubkey = DerivePQPubKeyV1(vec.scheme_id, std::span<const uint32_t, 6>(vec.path));
        BOOST_REQUIRE(pubkey.IsValid());

        KeyOriginInfo origin;
        origin.fingerprint[0] = 0xde;
        origin.fingerprint[1] = 0xad;
        origin.fingerprint[2] = 0xbe;
        origin.fingerprint[3] = 0xef;
        origin.path = {HARDENED | 1U, HARDENED | 2U, HARDENED | 3U};

        std::map<CPubKey, KeyOriginInfo> hd_keypaths;
        hd_keypaths.emplace(pubkey, origin);

        DataStream ds;
        SerializeHDKeypaths(ds, hd_keypaths, CompactSizeWriter(PSBT_IN_BIP32_DERIVATION));

        std::vector<unsigned char> key;
        ds >> key;

        std::map<CPubKey, KeyOriginInfo> decoded;
        DeserializeHDKeypaths(ds, key, decoded);

        BOOST_CHECK(ds.empty());
        BOOST_CHECK_EQUAL(decoded.size(), 1U);
        BOOST_CHECK(decoded.begin()->first == pubkey);
        BOOST_CHECK(decoded.begin()->second == origin);
    }
}

BOOST_AUTO_TEST_SUITE_END()
