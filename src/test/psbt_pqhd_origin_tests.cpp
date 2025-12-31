#include <pq/pq_scheme.h>
#include <pq/pqhd_params.h>

#include <psbt.h>

#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <span>
#include <vector>

namespace {

constexpr uint32_t HARDENED = 0x80000000U;

CPubKey MakeDummyTidePubKey(pq::SchemeId scheme_id)
{
    const pq::SchemeInfo* scheme = pq::SchemeFromId(scheme_id);
    BOOST_REQUIRE(scheme);

    std::vector<unsigned char> bytes(scheme->pubkey_bytes + 1);
    bytes[0] = scheme->prefix;
    for (size_t i = 1; i < bytes.size(); ++i) bytes[i] = 0x42;
    return CPubKey{bytes};
}

std::vector<uint32_t> MakePQHDPathForScheme(pq::SchemeId scheme_id)
{
    return {
        HARDENED | pqhd::PURPOSE,
        HARDENED | pqhd::COIN_TYPE,
        HARDENED | static_cast<uint32_t>(static_cast<uint8_t>(scheme_id)),
        HARDENED | 0U,
        HARDENED | 0U,
        HARDENED | 0U,
    };
}

PartiallySignedTransaction MakeMinimalPSBT()
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(CTxIn{Txid::FromUint256(uint256::ONE), 0});
    mtx.vout.emplace_back(CTxOut{1, CScript{}});
    return PartiallySignedTransaction{mtx};
}

} // namespace

BOOST_AUTO_TEST_SUITE(psbt_pqhd_origin_tests)

BOOST_AUTO_TEST_CASE(pqhd_origin_roundtrip_input_and_output)
{
    auto psbtx = MakeMinimalPSBT();

    const auto pubkey_in = MakeDummyTidePubKey(pq::SchemeId::FALCON_512);
    const auto pubkey_out = MakeDummyTidePubKey(pq::SchemeId::MLDSA_65);
    const uint256 seed_id = uint256::ONE;

    const auto path_in = MakePQHDPathForScheme(pq::SchemeId::FALCON_512);
    const auto path_out = MakePQHDPathForScheme(pq::SchemeId::MLDSA_65);

    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(psbtx.inputs.at(0).m_proprietary, PSBT_IN_PROPRIETARY, pubkey_in, seed_id, path_in));
    BOOST_REQUIRE(psbt::tidecoin::AddPQHDOrigin(psbtx.outputs.at(0).m_proprietary, PSBT_OUT_PROPRIETARY, pubkey_out, seed_id, path_out));

    DataStream ds;
    ds << psbtx;

    PartiallySignedTransaction decoded;
    ds >> decoded;

    BOOST_CHECK(ds.empty());
    BOOST_CHECK_EQUAL(decoded.inputs.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.outputs.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.inputs.at(0).m_proprietary.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.outputs.at(0).m_proprietary.size(), 1U);

    const auto origin_in = psbt::tidecoin::DecodePQHDOrigin(*decoded.inputs.at(0).m_proprietary.begin());
    BOOST_REQUIRE(origin_in);
    BOOST_CHECK(origin_in->pubkey == pubkey_in);
    BOOST_CHECK(origin_in->seed_id == seed_id);
    BOOST_CHECK(origin_in->path_hardened == path_in);

    const auto origin_out = psbt::tidecoin::DecodePQHDOrigin(*decoded.outputs.at(0).m_proprietary.begin());
    BOOST_REQUIRE(origin_out);
    BOOST_CHECK(origin_out->pubkey == pubkey_out);
    BOOST_CHECK(origin_out->seed_id == seed_id);
    BOOST_CHECK(origin_out->path_hardened == path_out);
}

BOOST_AUTO_TEST_CASE(pqhd_origin_decode_rejects_wrong_identifier_or_subtype)
{
    PSBTProprietary entry;
    entry.identifier.assign({'n','o','t','t','i','d','e'});
    entry.subtype = psbt::tidecoin::SUBTYPE_PQHD_ORIGIN;
    entry.key = psbt::tidecoin::MakeProprietaryKey(PSBT_IN_PROPRIETARY,
                                                   std::span<const unsigned char>(entry.identifier.data(), entry.identifier.size()),
                                                   entry.subtype,
                                                   std::span<const unsigned char>());
    entry.value = psbt::tidecoin::MakePQHDOriginValue(uint256::ONE, std::span<const uint32_t>());
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));

    entry.identifier.assign(psbt::tidecoin::PROPRIETARY_IDENTIFIER.begin(), psbt::tidecoin::PROPRIETARY_IDENTIFIER.end());
    entry.subtype = psbt::tidecoin::SUBTYPE_PQHD_ORIGIN + 1;
    entry.key = psbt::tidecoin::MakeProprietaryKey(PSBT_IN_PROPRIETARY,
                                                   std::span<const unsigned char>(entry.identifier.data(), entry.identifier.size()),
                                                   entry.subtype,
                                                   std::span<const unsigned char>());
    entry.value = psbt::tidecoin::MakePQHDOriginValue(uint256::ONE, std::span<const uint32_t>());
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));
}

BOOST_AUTO_TEST_CASE(pqhd_origin_decode_rejects_malformed_values)
{
    const auto pubkey = MakeDummyTidePubKey(pq::SchemeId::FALCON_512);
    PSBTProprietary entry;
    entry.identifier.assign(psbt::tidecoin::PROPRIETARY_IDENTIFIER.begin(), psbt::tidecoin::PROPRIETARY_IDENTIFIER.end());
    entry.subtype = psbt::tidecoin::SUBTYPE_PQHD_ORIGIN;
    entry.key = psbt::tidecoin::MakeProprietaryKey(PSBT_IN_PROPRIETARY,
                                                   std::span<const unsigned char>(entry.identifier.data(), entry.identifier.size()),
                                                   entry.subtype,
                                                   std::span<const unsigned char>(pubkey.data(), pubkey.size()));

    // Too short to contain SeedID32.
    entry.value = {0x01, 0x02, 0x03};
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));

    // Non-hardened path elements should be rejected.
    const std::vector<uint32_t> non_hardened_path{0U, 1U, 2U};
    entry.value = psbt::tidecoin::MakePQHDOriginValue(uint256::ONE, non_hardened_path);
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));

    // Hardened path, but scheme mismatch between path[2] and pubkey prefix.
    const std::vector<uint32_t> mismatch_scheme_path{
        HARDENED | pqhd::PURPOSE,
        HARDENED | pqhd::COIN_TYPE,
        HARDENED | 0x0AU, // ML-DSA-65
    };
    entry.value = psbt::tidecoin::MakePQHDOriginValue(uint256::ONE, mismatch_scheme_path);
    BOOST_CHECK(!psbt::tidecoin::DecodePQHDOrigin(entry));
}

BOOST_AUTO_TEST_SUITE_END()
