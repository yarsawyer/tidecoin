// Copyright (c) 2012-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <clientversion.h>
#include <streams.h>
#include <uint256.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(walletdb_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(walletdb_readkeyvalue)
{
    /**
     * When ReadKeyValue() reads from either a "key" or "wkey" it first reads the DataStream into a
     * CPrivKey or CWalletKey respectively and then reads a hash of the pubkey and privkey into a uint256.
     * Wallets from 0.8 or before do not store the pubkey/privkey hash, trying to read the hash from old
     * wallets throws an exception, for backwards compatibility this read is wrapped in a try block to
     * silently fail. The test here makes sure the type of exception thrown from DataStream::read()
     * matches the type we expect, otherwise we need to update the "key"/"wkey" exception type caught.
     */
    DataStream ssValue{};
    uint256 dummy;
    BOOST_CHECK_THROW(ssValue >> dummy, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(walletdb_keymetadata_pqhd_origin_serialization)
{
    CKeyMetadata meta;
    meta.nCreateTime = 123456;
    meta.has_pqhd_origin = true;
    meta.pqhd_seed_id = uint256::ONE;
    meta.pqhd_path = {0x80002717, 0x80001ad4, 0x80000007, 0x80000000, 0x80000000, 0x80000000};

    DataStream ser;
    ser << meta;

    CKeyMetadata decoded;
    ser >> decoded;

    BOOST_CHECK_EQUAL(decoded.nVersion, CKeyMetadata::CURRENT_VERSION);
    BOOST_CHECK_EQUAL(decoded.nCreateTime, meta.nCreateTime);
    BOOST_CHECK_EQUAL(decoded.has_pqhd_origin, true);
    BOOST_CHECK_EQUAL(decoded.pqhd_seed_id, meta.pqhd_seed_id);
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded.pqhd_path.begin(), decoded.pqhd_path.end(), meta.pqhd_path.begin(), meta.pqhd_path.end());
}

BOOST_AUTO_TEST_CASE(walletdb_pqhd_records_roundtrip)
{
    std::unique_ptr<WalletDatabase> database = CreateMockableWalletDatabase();
    WalletBatch batch(*database);

    uint256 seed_id_a = uint256::ONE;
    PQHDSeed seed_a;
    seed_a.nCreateTime = 111;
    seed_a.seed.assign(32, 0xA5);
    BOOST_CHECK(batch.WritePQHDSeed(seed_id_a, seed_a));

    uint256 seed_id_b{uint8_t{2}};
    PQHDCryptedSeed cseed_b;
    cseed_b.nCreateTime = 222;
    cseed_b.crypted_seed.assign(48, 0x5A);
    BOOST_CHECK(batch.WriteCryptedPQHDSeed(seed_id_b, cseed_b));

    PQHDPolicy policy;
    policy.default_receive_scheme = 0x07;
    policy.default_change_scheme = 0x07;
    policy.default_seed_id = seed_id_a;
    policy.default_change_seed_id = seed_id_a;
    BOOST_CHECK(batch.WritePQHDPolicy(policy));

    auto* mockdb = dynamic_cast<MockableDatabase*>(database.get());
    BOOST_REQUIRE(mockdb != nullptr);

    {
        DataStream key;
        key << std::make_pair(DBKeys::PQHD_SEED, seed_id_a);
        const auto it = mockdb->m_records.find(SerializeData(key.begin(), key.end()));
        BOOST_REQUIRE(it != mockdb->m_records.end());
        DataStream val{it->second};
        PQHDSeed decoded;
        val >> decoded;
        BOOST_CHECK_EQUAL(decoded.nCreateTime, seed_a.nCreateTime);
        BOOST_CHECK_EQUAL_COLLECTIONS(decoded.seed.begin(), decoded.seed.end(), seed_a.seed.begin(), seed_a.seed.end());
    }

    {
        DataStream key;
        key << std::make_pair(DBKeys::PQHD_CRYPTED_SEED, seed_id_b);
        const auto it = mockdb->m_records.find(SerializeData(key.begin(), key.end()));
        BOOST_REQUIRE(it != mockdb->m_records.end());
        DataStream val{it->second};
        PQHDCryptedSeed decoded;
        val >> decoded;
        BOOST_CHECK_EQUAL(decoded.nCreateTime, cseed_b.nCreateTime);
        BOOST_CHECK_EQUAL_COLLECTIONS(decoded.crypted_seed.begin(), decoded.crypted_seed.end(), cseed_b.crypted_seed.begin(), cseed_b.crypted_seed.end());
    }

    {
        DataStream key;
        key << DBKeys::PQHD_POLICY;
        const auto it = mockdb->m_records.find(SerializeData(key.begin(), key.end()));
        BOOST_REQUIRE(it != mockdb->m_records.end());
        DataStream val{it->second};
        PQHDPolicy decoded;
        val >> decoded;
        BOOST_CHECK_EQUAL(decoded.default_receive_scheme, policy.default_receive_scheme);
        BOOST_CHECK_EQUAL(decoded.default_change_scheme, policy.default_change_scheme);
        BOOST_CHECK_EQUAL(decoded.default_seed_id, policy.default_seed_id);
        BOOST_CHECK_EQUAL(decoded.default_change_seed_id, policy.default_change_seed_id);
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
