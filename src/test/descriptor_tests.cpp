// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <pq/pq_scheme.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

/** Compare two descriptors. If only one of them has a checksum, the checksum is ignored. */
bool EqualDescriptor(std::string a, std::string b)
{
    const bool a_check{a.size() > 9 && a[a.size() - 9] == '#'};
    const bool b_check{b.size() > 9 && b[b.size() - 9] == '#'};
    if (a_check != b_check) {
        if (a_check) a = a.substr(0, a.size() - 9);
        if (b_check) b = b.substr(0, b.size() - 9);
    }
    return a == b;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(descriptor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(descriptor_pqhd_key_expression_parsing)
{
    FlatSigningProvider out;
    std::string error;

    const std::string seedid{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"};

    const std::string ranged{"wpkh(pqhd(" + seedid + ")/10007h/6868h/7h/0h/0h/*h)"};
    auto parsed_ranged = Parse(ranged, out, error);
    BOOST_REQUIRE_MESSAGE(!parsed_ranged.empty(), error);
    BOOST_CHECK_MESSAGE(EqualDescriptor(ranged, parsed_ranged.at(0)->ToString()), parsed_ranged.at(0)->ToString());
    BOOST_CHECK(parsed_ranged.at(0)->IsRange());
    BOOST_CHECK(out.keys.empty());
    const auto ranged_prefix = parsed_ranged.at(0)->GetPQHDSchemePrefix();
    BOOST_REQUIRE(ranged_prefix.has_value());
    BOOST_CHECK_EQUAL(*ranged_prefix, static_cast<uint8_t>(pq::SchemeId::FALCON_512));

    const std::string fixed{"wpkh(pqhd(" + seedid + ")/10007h/6868h/7h/0h/0h/0h)"};
    out = FlatSigningProvider{};
    auto parsed_fixed = Parse(fixed, out, error);
    BOOST_REQUIRE_MESSAGE(!parsed_fixed.empty(), error);
    BOOST_CHECK_MESSAGE(EqualDescriptor(fixed, parsed_fixed.at(0)->ToString()), parsed_fixed.at(0)->ToString());
    BOOST_CHECK(!parsed_fixed.at(0)->IsRange());
    BOOST_CHECK(out.keys.empty());
    const auto fixed_prefix = parsed_fixed.at(0)->GetPQHDSchemePrefix();
    BOOST_REQUIRE(fixed_prefix.has_value());
    BOOST_CHECK_EQUAL(*fixed_prefix, static_cast<uint8_t>(pq::SchemeId::FALCON_512));

    const auto must_fail = [&](const std::string& s, const std::string& needle) {
        out = FlatSigningProvider{};
        error.clear();
        auto parsed = Parse(s, out, error);
        BOOST_CHECK(parsed.empty());
        BOOST_CHECK_MESSAGE(!error.empty(), "expected parse error");
        const bool has_expected = error.find(needle) != std::string::npos;
        const bool has_fallback = error.find("Key path value") != std::string::npos;
        BOOST_CHECK_MESSAGE(has_expected || has_fallback, error);
    };

    must_fail("wpkh(pqhd(" + seedid + ")/10007/6868h/7h/0h/0h/*h)", "hardened-only");
    must_fail("wpkh(pqhd(" + seedid + ")/10007h/6868h/7h/0h/0h/*)", "*h");
    must_fail("wpkh(pqhd(" + seedid + ")/10008h/6868h/7h/0h/0h/*h)", "purpose");
    must_fail("wpkh(pqhd(" + seedid + ")/10007h/6868h/6h/0h/0h/*h)", "not recognized");
    must_fail("wpkh(pqhd(" + seedid.substr(0, 10) + ")/10007h/6868h/7h/0h/0h/*h)", "pqhd() seed id");
}

BOOST_AUTO_TEST_SUITE_END()
