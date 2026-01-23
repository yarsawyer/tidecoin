// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/key_io_invalid.json.h>
#include <test/data/key_io_valid.json.h>

#include <base58.h>
#include <bech32.h>
#include <key.h>
#include <key_io.h>
#include <pq/pq_scheme.h>
#include <script/script.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

BOOST_FIXTURE_TEST_SUITE(key_io_tests, BasicTestingSetup)

// Goal: check that parsed keys match test payload
BOOST_AUTO_TEST_CASE(key_io_valid_parse)
{
    UniValue tests = read_json(json_tests::key_io_valid);
    CKey privkey;
    CTxDestination destination;
    SelectParams(ChainType::MAIN);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) { // Allow for extra stuff (useful for comments)
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        const std::vector<std::byte> exp_payload{ParseHex<std::byte>(test[1].get_str())};
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        bool try_case_flip = metadata.find_value("tryCaseFlip").isNull() ? false : metadata.find_value("tryCaseFlip").get_bool();
        if (isPrivkey) {
            // Skip legacy private key vectors; PQ WIF coverage is handled separately.
            continue;
        } else {
            // Must be valid public key
            destination = DecodeDestination(exp_base58string);
            CScript script = GetScriptForDestination(destination);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination), "!IsValid:" + strTest);
            BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));

            // Try flipped case version
            for (char& c : exp_base58string) {
                if (c >= 'a' && c <= 'z') {
                    c = (c - 'a') + 'A';
                } else if (c >= 'A' && c <= 'Z') {
                    c = (c - 'A') + 'a';
                }
            }
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination) == try_case_flip, "!IsValid case flipped:" + strTest);
            if (IsValidDestination(destination)) {
                script = GetScriptForDestination(destination);
                BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));
            }

            // Public key must be invalid private key
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid pubkey as privkey:" + strTest);
        }
    }
}

// Goal: check that generated keys match test vectors
BOOST_AUTO_TEST_CASE(key_io_valid_gen)
{
    UniValue tests = read_json(json_tests::key_io_valid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        std::vector<unsigned char> exp_payload = ParseHex(test[1].get_str());
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        if (isPrivkey) {
            // Skip legacy private key vectors; PQ WIF coverage is handled separately.
            continue;
        } else {
            CTxDestination dest;
            CScript exp_script(exp_payload.begin(), exp_payload.end());
            BOOST_CHECK(ExtractDestination(exp_script, dest));
            std::string address = EncodeDestination(dest);

            BOOST_CHECK_EQUAL(address, exp_base58string);
        }
    }

    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(key_io_pq_privkey_roundtrip)
{
    SelectParams(ChainType::MAIN);

    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);
    BOOST_REQUIRE(key.IsValid());

    const std::string encoded = EncodeSecret(key);
    CKey decoded = DecodeSecret(encoded);
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK(key == decoded);

    // WIF strings must not parse as destinations.
    BOOST_CHECK(!IsValidDestination(DecodeDestination(encoded)));
}

BOOST_AUTO_TEST_CASE(key_io_pq_privkey_roundtrip_large)
{
    SelectParams(ChainType::MAIN);

    CKey key;
    key.MakeNewKey(pq::SchemeId::MLDSA_87);
    BOOST_REQUIRE(key.IsValid());

    const std::string encoded = EncodeSecret(key);
    BOOST_TEST_MESSAGE("ML-DSA-87 WIF length=" << encoded.size());

    CKey decoded = DecodeSecret(encoded);
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK(key == decoded);
}

BOOST_AUTO_TEST_CASE(key_io_pq_privkey_roundtrip_all_schemes)
{
    SelectParams(ChainType::MAIN);

    const std::array<pq::SchemeId, 5> schemes{
        pq::SchemeId::FALCON_512,
        pq::SchemeId::FALCON_1024,
        pq::SchemeId::MLDSA_44,
        pq::SchemeId::MLDSA_65,
        pq::SchemeId::MLDSA_87,
    };

    for (const auto scheme : schemes) {
        CKey key;
        key.MakeNewKey(scheme);
        BOOST_REQUIRE_MESSAGE(key.IsValid(), "key invalid for scheme " << static_cast<int>(scheme));

        const std::string encoded = EncodeSecret(key);
        CKey decoded = DecodeSecret(encoded);
        BOOST_REQUIRE_MESSAGE(decoded.IsValid(), "decode failed for scheme " << static_cast<int>(scheme));
        BOOST_CHECK_MESSAGE(key == decoded, "roundtrip mismatch for scheme " << static_cast<int>(scheme));
    }
}

BOOST_AUTO_TEST_CASE(key_io_pq_legacy_wif_roundtrip)
{
    SelectParams(ChainType::MAIN);

    CKey key;
    key.MakeNewKey(pq::SchemeId::FALCON_512);
    BOOST_REQUIRE(key.IsValid());

    const std::string legacy = EncodeSecretLegacy(key);
    BOOST_REQUIRE(!legacy.empty());

    CKey decoded = DecodeSecret(legacy);
    BOOST_REQUIRE(decoded.IsValid());
    BOOST_CHECK(key == decoded);

    // Legacy WIF for non-Falcon schemes should be rejected.
    CKey mldsa;
    mldsa.MakeNewKey(pq::SchemeId::MLDSA_44);
    BOOST_REQUIRE(mldsa.IsValid());
    const CPubKey pubkey = mldsa.GetPubKey();
    const pq::SchemeInfo* scheme = pq::SchemeFromPrefix(pubkey[0]);
    BOOST_REQUIRE(scheme != nullptr);

    CPrivKey priv = mldsa.GetPrivKey();
    std::span<const unsigned char> raw = priv;
    if (raw.size() == scheme->seckey_bytes + 1 && raw[0] == scheme->prefix) {
        raw = raw.subspan(1);
    }
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::SECRET_KEY);
    data.insert(data.end(), raw.begin(), raw.end());
    data.push_back(1);
    data.insert(data.end(), pubkey.begin(), pubkey.end());
    const std::string legacy_bad = EncodeBase58Check(data);

    CKey decoded_bad = DecodeSecret(legacy_bad);
    BOOST_CHECK(!decoded_bad.IsValid());
}


// Goal: check that base58 parsing code is robust against a variety of corrupted data
BOOST_AUTO_TEST_CASE(key_io_invalid)
{
    UniValue tests = read_json(json_tests::key_io_invalid); // Negative testcases
    CKey privkey;
    CTxDestination destination;

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();

        // must be invalid as public and as private key
        for (const auto& chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
            SelectParams(chain);
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid pubkey in mainnet:" + strTest);
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid privkey in mainnet:" + strTest);
        }
    }
}

BOOST_AUTO_TEST_CASE(key_io_bech32pq_v1)
{
    SelectParams(ChainType::MAIN);
    const auto& params = Params();

    CScript witness_script;
    witness_script << OP_TRUE;
    const WitnessV1ScriptHash512 wit_hash{witness_script};

    const std::string addr = EncodeDestination(wit_hash);
    BOOST_CHECK(addr.rfind(params.Bech32PQHRP(), 0) == 0);

    std::string error;
    auto decoded = DecodeDestination(addr, error);
    BOOST_TEST_MESSAGE("bech32pq addr=" << addr << " error=" << error);
    BOOST_CHECK(error.empty());
    BOOST_REQUIRE(std::holds_alternative<WitnessV1ScriptHash512>(decoded));
    BOOST_CHECK(std::get<WitnessV1ScriptHash512>(decoded) == wit_hash);

    // PQ HRP must not accept v0 witness programs.
    std::vector<unsigned char> program20(20, 0x42);
    std::vector<unsigned char> data_v0{0};
    ConvertBits<8, 5, true>([&](unsigned char c) { data_v0.push_back(c); }, program20.begin(), program20.end());
    const std::string pq_v0 = bech32::Encode(bech32::Encoding::BECH32M, params.Bech32PQHRP(), data_v0);
    decoded = DecodeDestination(pq_v0, error);
    BOOST_CHECK(!IsValidDestination(decoded));

    // Legacy HRP must not accept v1 witness programs.
    std::vector<unsigned char> program64(64, 0x11);
    std::vector<unsigned char> data_v1{1};
    ConvertBits<8, 5, true>([&](unsigned char c) { data_v1.push_back(c); }, program64.begin(), program64.end());
    const std::string legacy_v1 = bech32::Encode(bech32::Encoding::BECH32M, params.Bech32HRP(), data_v1);
    decoded = DecodeDestination(legacy_v1, error);
    BOOST_CHECK(!IsValidDestination(decoded));
}

BOOST_AUTO_TEST_SUITE_END()
