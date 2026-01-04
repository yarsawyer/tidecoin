// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <hash.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(key_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pq_key_sign_verify_roundtrip)
{
    CKey key1 = GenerateRandomKey();
    CKey key2 = GenerateRandomKey();

    BOOST_CHECK(key1.IsValid());
    BOOST_CHECK(key2.IsValid());

    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey2 = key2.GetPubKey();

    BOOST_CHECK(key1.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2));
    BOOST_CHECK(key2.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey1));

    const uint256 hashMsg = Hash("tidecoin pq key test");
    std::vector<unsigned char> sig1;
    std::vector<unsigned char> sig2;

    BOOST_CHECK(key1.Sign(hashMsg, sig1));
    BOOST_CHECK(key2.Sign(hashMsg, sig2));
    BOOST_CHECK(pubkey1.Verify(hashMsg, sig1));
    BOOST_CHECK(!pubkey1.Verify(hashMsg, sig2));
    BOOST_CHECK(pubkey2.Verify(hashMsg, sig2));
    BOOST_CHECK(!pubkey2.Verify(hashMsg, sig1));
}

BOOST_AUTO_TEST_CASE(pq_pubkey_serialize_roundtrip)
{
    CKey key = GenerateRandomKey();
    CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(pubkey.IsValid());

    DataStream stream{};
    stream << pubkey;
    CPubKey pubkey2;
    stream >> pubkey2;
    BOOST_CHECK(pubkey == pubkey2);
}

BOOST_AUTO_TEST_CASE(pq_pubkey_invalid_length)
{
    const unsigned char prefix = pq::kFalcon512Info.prefix;
    std::vector<unsigned char> wrong_len{prefix, 0x00};
    CPubKey bad_pk(wrong_len);
    BOOST_CHECK(!bad_pk.IsValid());
}

BOOST_AUTO_TEST_SUITE_END()
