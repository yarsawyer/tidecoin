// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip324_pq.h>
#include <chainparams.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <array>
#include <cstddef>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

struct BIP324PQTest : BasicTestingSetup {
    BIP324PQTest() : BasicTestingSetup{} { SelectParams(ChainType::MAIN); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(bip324_pq_tests, BIP324PQTest)

BOOST_AUTO_TEST_CASE(cipher_roundtrip)
{
    std::array<std::byte, 32> shared_secret{};
    for (size_t i = 0; i < shared_secret.size(); ++i) {
        shared_secret[i] = std::byte{static_cast<unsigned char>(i)};
    }

    BIP324PQCipher initiator;
    BIP324PQCipher responder;
    initiator.InitializeFromSharedSecret(shared_secret, true);
    responder.InitializeFromSharedSecret(shared_secret, false);

    BOOST_CHECK(initiator);
    BOOST_CHECK(responder);
    BOOST_CHECK(std::ranges::equal(initiator.GetSessionID(), responder.GetSessionID()));
    BOOST_CHECK(std::ranges::equal(initiator.GetSendGarbageTerminator(), responder.GetReceiveGarbageTerminator()));
    BOOST_CHECK(std::ranges::equal(initiator.GetReceiveGarbageTerminator(), responder.GetSendGarbageTerminator()));

    const auto aad = ParseHex<std::byte>("a1b2c3");
    const auto msg = ParseHex<std::byte>("deadbeef");

    std::vector<std::byte> ciphertext(msg.size() + BIP324PQCipher::EXPANSION);
    initiator.Encrypt(msg, aad, false, ciphertext);

    uint32_t len = responder.DecryptLength(std::span{ciphertext}.first(BIP324PQCipher::LENGTH_LEN));
    BOOST_CHECK_EQUAL(len, msg.size());

    std::vector<std::byte> decoded(len);
    bool ignore{false};
    BOOST_CHECK(responder.Decrypt(std::span{ciphertext}.subspan(BIP324PQCipher::LENGTH_LEN), aad, ignore, decoded));
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded.begin(), decoded.end(), msg.begin(), msg.end());
    BOOST_CHECK(!ignore);
}

BOOST_AUTO_TEST_SUITE_END()
