// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/bloom.h>

#include <clientversion.h>
#include <common/system.h>
#include <consensus/merkle.h>
#include <key.h>
#include <pq/pq_api.h>
#include <merkleblock.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <array>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace util::hex_literals;

namespace bloom_tests {
struct BloomTest : public BasicTestingSetup {
    std::vector<unsigned char> RandomData();
};
} // namespace bloom_tests

namespace {
std::array<uint8_t, 64> MakeMaterial(uint8_t tag)
{
    std::array<uint8_t, 64> out{};
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(tag ^ static_cast<uint8_t>(i * 131));
    }
    return out;
}

CPubKey MakePQPubKey(uint8_t tag)
{
    const auto material = MakeMaterial(tag);
    std::vector<uint8_t> pk_raw;
    pq::SecureKeyBytes sk_raw;
    BOOST_REQUIRE(pq::KeyGenFromSeed(/*pqhd_version=*/1,
                                     pq::SchemeId::FALCON_512,
                                     material,
                                     pk_raw,
                                     sk_raw));
    BOOST_REQUIRE_EQUAL(pk_raw.size(), pq::kFalcon512Info.pubkey_bytes);
    std::vector<uint8_t> prefixed(pk_raw.size() + 1);
    prefixed[0] = pq::kFalcon512Info.prefix;
    std::copy(pk_raw.begin(), pk_raw.end(), prefixed.begin() + 1);
    CPubKey pubkey{std::span<const uint8_t>(prefixed)};
    BOOST_REQUIRE(pubkey.IsValid());
    return pubkey;
}

CScript MakeP2PKScript(const CPubKey& pubkey)
{
    return CScript() << std::vector<unsigned char>(pubkey.begin(), pubkey.end()) << OP_CHECKSIG;
}

CScript MakeP2PKHScript(const CPubKey& pubkey)
{
    const auto keyid = pubkey.GetID();
    return CScript() << OP_DUP << OP_HASH160
                     << std::vector<unsigned char>(keyid.begin(), keyid.end())
                     << OP_EQUALVERIFY << OP_CHECKSIG;
}

CMutableTransaction MakeTx(const COutPoint& prevout, const CScript& script_pubkey, const CScript& script_sig = {})
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = prevout;
    tx.vin[0].scriptSig = script_sig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1;
    tx.vout[0].scriptPubKey = script_pubkey;
    return tx;
}

CBlock MakeBlock(const std::vector<CTransactionRef>& txs)
{
    CBlock block;
    block.nVersion = 1;
    block.nTime = 1;
    block.nBits = 0x207fffff;
    block.nNonce = 0;
    block.hashPrevBlock = uint256::ZERO;
    block.vtx = txs;
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

struct PQBlockFixture {
    CBlock block;
    std::vector<Txid> txids;
    CPubKey p2pk_pubkey;
    CPubKey p2pkh_pubkey;
    COutPoint p2pk_outpoint;
    COutPoint p2pkh_outpoint;
};

PQBlockFixture BuildPQBlock()
{
    PQBlockFixture fixture;
    fixture.p2pkh_pubkey = MakePQPubKey(0x21);
    fixture.p2pk_pubkey = MakePQPubKey(0x22);
    const CPubKey spend_pubkey = MakePQPubKey(0x23);

    CMutableTransaction tx0 = MakeTx(COutPoint(Txid::FromUint256(uint256{1}), 0),
                                     MakeP2PKHScript(fixture.p2pkh_pubkey));
    CMutableTransaction tx1 = MakeTx(COutPoint(Txid::FromUint256(uint256{2}), 0),
                                     MakeP2PKScript(fixture.p2pk_pubkey));
    CMutableTransaction tx2 = MakeTx(COutPoint(tx1.GetHash(), 0),
                                     MakeP2PKHScript(spend_pubkey));
    CMutableTransaction tx3 = MakeTx(COutPoint(Txid::FromUint256(uint256{3}), 1),
                                     MakeP2PKScript(fixture.p2pk_pubkey));

    const auto tx0_ref = MakeTransactionRef(tx0);
    const auto tx1_ref = MakeTransactionRef(tx1);
    const auto tx2_ref = MakeTransactionRef(tx2);
    const auto tx3_ref = MakeTransactionRef(tx3);

    fixture.txids = {tx0_ref->GetHash(), tx1_ref->GetHash(), tx2_ref->GetHash(), tx3_ref->GetHash()};
    fixture.p2pkh_outpoint = COutPoint(tx0_ref->GetHash(), 0);
    fixture.p2pk_outpoint = COutPoint(tx1_ref->GetHash(), 0);
    fixture.block = MakeBlock({tx0_ref, tx1_ref, tx2_ref, tx3_ref});
    return fixture;
}

std::pair<CBlock, Txid> BuildSingleTxBlock()
{
    const CPubKey pubkey = MakePQPubKey(0x31);
    CMutableTransaction tx = MakeTx(COutPoint(Txid::FromUint256(uint256{9}), 0),
                                    MakeP2PKHScript(pubkey));
    const auto tx_ref = MakeTransactionRef(tx);
    return {MakeBlock({tx_ref}), tx_ref->GetHash()};
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(bloom_tests, BloomTest)

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize)
{
    CBloomFilter filter(3, 0.01, 0, BLOOM_UPDATE_ALL);

    BOOST_CHECK_MESSAGE( !filter.contains("99108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8), "Bloom filter should be empty!");
    filter.insert("99108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8);
    BOOST_CHECK_MESSAGE( filter.contains("99108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8), "Bloom filter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains("19108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8), "Bloom filter contains something it shouldn't!");

    filter.insert("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"_hex_u8);
    BOOST_CHECK_MESSAGE(filter.contains("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"_hex_u8), "Bloom filter doesn't contain just-inserted object (2)!");

    filter.insert("b9300670b4c5366e95b2699e8b18bc75e5f729c5"_hex_u8);
    BOOST_CHECK_MESSAGE(filter.contains("b9300670b4c5366e95b2699e8b18bc75e5f729c5"_hex_u8), "Bloom filter doesn't contain just-inserted object (3)!");

    DataStream stream{};
    stream << filter;

    constexpr auto expected{"03614e9b050000000000000001"_hex};
    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());

    BOOST_CHECK_MESSAGE( filter.contains("99108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8), "Bloom filter doesn't contain just-inserted object!");
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize_with_tweak)
{
    // Same test as bloom_create_insert_serialize, but we add a nTweak of 100
    CBloomFilter filter(3, 0.01, 2147483649UL, BLOOM_UPDATE_ALL);

    filter.insert("99108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8);
    BOOST_CHECK_MESSAGE( filter.contains("99108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8), "Bloom filter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains("19108ad8ed9bb6274d3980bab5a85c048f0950c8"_hex_u8), "Bloom filter contains something it shouldn't!");

    filter.insert("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"_hex_u8);
    BOOST_CHECK_MESSAGE(filter.contains("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"_hex_u8), "Bloom filter doesn't contain just-inserted object (2)!");

    filter.insert("b9300670b4c5366e95b2699e8b18bc75e5f729c5"_hex_u8);
    BOOST_CHECK_MESSAGE(filter.contains("b9300670b4c5366e95b2699e8b18bc75e5f729c5"_hex_u8), "Bloom filter doesn't contain just-inserted object (3)!");

    DataStream stream{};
    stream << filter;

    constexpr auto expected{"03ce4299050000000100008001"_hex};
    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_key)
{
    const CPubKey pubkey = MakePQPubKey(0x42);
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    CBloomFilter filter(2, 0.001, 0, BLOOM_UPDATE_ALL);
    filter.insert(vchPubKey);
    uint160 hash = pubkey.GetID();
    filter.insert(hash);
    BOOST_CHECK(filter.contains(vchPubKey));
    BOOST_CHECK(filter.contains(hash));

    DataStream stream{};
    stream << filter;

    constexpr auto expected{"034567a5080000000000000001"_hex};
    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_match)
{
    const CPubKey pubkey = MakePQPubKey(0x10);
    const CPubKey spend_pubkey = MakePQPubKey(0x11);

    const std::vector<unsigned char> sig_bytes{0x30, 0x44, 0x01, 0x02, 0x03};
    CScript script_sig;
    script_sig << sig_bytes << std::vector<unsigned char>(pubkey.begin(), pubkey.end());

    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{11}), 0);
    mtx.vin[0].scriptSig = script_sig;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = MakeP2PKHScript(pubkey);
    CTransaction tx(mtx);

    CMutableTransaction spend;
    spend.vin.resize(1);
    spend.vin[0].prevout = COutPoint(tx.GetHash(), 0);
    spend.vin[0].scriptSig = CScript() << std::vector<unsigned char>{0x01, 0x02};
    spend.vout.resize(1);
    spend.vout[0].nValue = 900;
    spend.vout[0].scriptPubKey = MakeP2PKHScript(spend_pubkey);
    CTransaction spendingTx(spend);

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(tx.GetHash().ToUint256());
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    const uint256& tx_hash = tx.GetHash().ToUint256();
    std::vector<unsigned char> txid_bytes(tx_hash.begin(), tx_hash.end());
    filter.insert(txid_bytes);
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match serialized tx hash bytes");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(sig_bytes);
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match input signature bytes");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match input pub key");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(pubkey.GetID());
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match output address");
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(spendingTx), "Simple Bloom filter didn't add output");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    const CPubKey other_pubkey = MakePQPubKey(0x12);
    filter.insert(other_pubkey.GetID());
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched random address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    COutPoint prevOutPoint(Txid::FromUint256(uint256{11}), 0);
    filter.insert(prevOutPoint);
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    {
        std::vector<unsigned char> data(32 + sizeof(unsigned int));
        memcpy(data.data(), prevOutPoint.hash.begin(), 32);
        memcpy(data.data()+32, &prevOutPoint.n, sizeof(unsigned int));
        filter.insert(data);
    }
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match manually serialized COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(uint256{9});
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched random tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(tx.GetHash(), 1));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched COutPoint for an output we didn't care about");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(Txid::FromUint256(uint256{10}), 0));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched COutPoint for an output we didn't care about");
}

BOOST_AUTO_TEST_CASE(merkle_block_1)
{
    const auto fixture = BuildPQBlock();
    const CBlock& block = fixture.block;
    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the last transaction
    filter.insert(fixture.txids.back().ToUint256());

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK_EQUAL(merkleBlock.header.GetHash().GetHex(), block.GetHash().GetHex());

    BOOST_CHECK_EQUAL(merkleBlock.vMatchedTxn.size(), 1U);
    std::pair<unsigned int, Txid> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == fixture.txids.back());
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 3);

    std::vector<Txid> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Also match the 2nd transaction
    filter.insert(fixture.txids[1].ToUint256());
    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1] == pair);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == fixture.txids[1]);
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 1);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_2)
{
    const auto fixture = BuildPQBlock();
    const CBlock& block = fixture.block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the first transaction
    filter.insert(fixture.txids[0].ToUint256());

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    std::pair<unsigned int, Txid> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == fixture.txids[0]);
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    std::vector<Txid> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Match the P2PK output from the second transaction.
    // This should also match the third transaction because it spends the output matched,
    // and it matches the fourth transaction which pays to the same pubkey.
    filter.insert(std::vector<unsigned char>(fixture.p2pk_pubkey.begin(), fixture.p2pk_pubkey.end()));

    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 4);

    BOOST_CHECK(pair == merkleBlock.vMatchedTxn[0]);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1].second == fixture.txids[1]);
    BOOST_CHECK(merkleBlock.vMatchedTxn[1].first == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[2].second == fixture.txids[2]);
    BOOST_CHECK(merkleBlock.vMatchedTxn[2].first == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[3].second == fixture.txids[3]);
    BOOST_CHECK(merkleBlock.vMatchedTxn[3].first == 3);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_2_with_update_none)
{
    const auto fixture = BuildPQBlock();
    const CBlock& block = fixture.block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    // Match the first transaction
    filter.insert(fixture.txids[0].ToUint256());

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    std::pair<unsigned int, Txid> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == fixture.txids[0]);
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    std::vector<Txid> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Match the P2PK output from the second transaction.
    // This should not match the third transaction because UPDATE_NONE does not
    // add outpoints, but it will match the fourth transaction which pays to the
    // same pubkey.
    filter.insert(std::vector<unsigned char>(fixture.p2pk_pubkey.begin(), fixture.p2pk_pubkey.end()));

    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 3);

    BOOST_CHECK(pair == merkleBlock.vMatchedTxn[0]);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1].second == fixture.txids[1]);
    BOOST_CHECK(merkleBlock.vMatchedTxn[1].first == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[2].second == fixture.txids[3]);
    BOOST_CHECK(merkleBlock.vMatchedTxn[2].first == 3);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_3_and_serialize)
{
    const auto [block, txid] = BuildSingleTxBlock();

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the only transaction
    filter.insert(txid.ToUint256());

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == txid);
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    std::vector<Txid> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    DataStream merkleStream{};
    merkleStream << merkleBlock;

    constexpr auto expected{"0100000000000000000000000000000000000000000000000000000000000000000000001bd81ba394424f842946dc5dd064c2de69cb2cbcaa37323618230c6d166d066f01000000ffff7f200000000001000000011bd81ba394424f842946dc5dd064c2de69cb2cbcaa37323618230c6d166d066f0101"_hex};
    BOOST_CHECK_EQUAL_COLLECTIONS(merkleStream.begin(), merkleStream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(merkle_block_4)
{
    const auto fixture = BuildPQBlock();
    const CBlock& block = fixture.block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the last transaction
    filter.insert(fixture.txids[3].ToUint256());

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    std::pair<unsigned int, Txid> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == fixture.txids[3]);
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 3);

    std::vector<Txid> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Also match the 2nd transaction
    filter.insert(fixture.txids[1].ToUint256());
    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == fixture.txids[1]);
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1] == pair);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_4_test_p2pubkey_only)
{
    const auto fixture = BuildPQBlock();
    const CBlock& block = fixture.block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_P2PUBKEY_ONLY);
    // Match the P2PK output
    filter.insert(std::vector<unsigned char>(fixture.p2pk_pubkey.begin(), fixture.p2pk_pubkey.end()));
    // ...and the P2PKH output (should not update outpoints in P2PUBKEY_ONLY)
    filter.insert(fixture.p2pkh_pubkey.GetID());

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 4);
    BOOST_CHECK(filter.contains(fixture.p2pk_outpoint));
    BOOST_CHECK(!filter.contains(fixture.p2pkh_outpoint));
}

BOOST_AUTO_TEST_CASE(merkle_block_4_test_update_none)
{
    const auto fixture = BuildPQBlock();
    const CBlock& block = fixture.block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    // Match the P2PK output
    filter.insert(std::vector<unsigned char>(fixture.p2pk_pubkey.begin(), fixture.p2pk_pubkey.end()));
    // ...and the P2PKH output
    filter.insert(fixture.p2pkh_pubkey.GetID());

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 3);
    // We shouldn't match any outpoints (UPDATE_NONE)
    BOOST_CHECK(!filter.contains(fixture.p2pk_outpoint));
    BOOST_CHECK(!filter.contains(fixture.p2pkh_outpoint));
}

std::vector<unsigned char> BloomTest::RandomData()
{
    uint256 r = m_rng.rand256();
    return std::vector<unsigned char>(r.begin(), r.end());
}

BOOST_AUTO_TEST_CASE(rolling_bloom)
{
    SeedRandomForTest(SeedRand::ZEROS);

    // last-100-entry, 1% false positive:
    CRollingBloomFilter rb1(100, 0.01);

    // Overfill:
    static const int DATASIZE=399;
    std::vector<unsigned char> data[DATASIZE];
    for (int i = 0; i < DATASIZE; i++) {
        data[i] = RandomData();
        rb1.insert(data[i]);
    }
    // Last 100 guaranteed to be remembered:
    for (int i = 299; i < DATASIZE; i++) {
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // false positive rate is 1%, so we should get about 100 hits if
    // testing 10,000 random keys. We get worst-case false positive
    // behavior when the filter is as full as possible, which is
    // when we've inserted one minus an integer multiple of nElement*2.
    unsigned int nHits = 0;
    for (int i = 0; i < 10000; i++) {
        if (rb1.contains(RandomData()))
            ++nHits;
    }
    // Expect about 100 hits
    BOOST_CHECK_EQUAL(nHits, 71U);

    BOOST_CHECK(rb1.contains(data[DATASIZE-1]));
    rb1.reset();
    BOOST_CHECK(!rb1.contains(data[DATASIZE-1]));

    // Now roll through data, make sure last 100 entries
    // are always remembered:
    for (int i = 0; i < DATASIZE; i++) {
        if (i >= 100)
            BOOST_CHECK(rb1.contains(data[i-100]));
        rb1.insert(data[i]);
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // Insert 999 more random entries:
    for (int i = 0; i < 999; i++) {
        std::vector<unsigned char> d = RandomData();
        rb1.insert(d);
        BOOST_CHECK(rb1.contains(d));
    }
    // Sanity check to make sure the filter isn't just filling up:
    nHits = 0;
    for (int i = 0; i < DATASIZE; i++) {
        if (rb1.contains(data[i]))
            ++nHits;
    }
    // Expect about 5 false positives
    BOOST_CHECK_EQUAL(nHits, 3U);

    // last-1000-entry, 0.01% false positive:
    CRollingBloomFilter rb2(1000, 0.001);
    for (int i = 0; i < DATASIZE; i++) {
        rb2.insert(data[i]);
    }
    // ... room for all of them:
    for (int i = 0; i < DATASIZE; i++) {
        BOOST_CHECK(rb2.contains(data[i]));
    }
}

BOOST_AUTO_TEST_SUITE_END()
