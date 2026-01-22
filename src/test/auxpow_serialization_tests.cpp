// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>
#include <consensus/merkle.h>
#include <primitives/block.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(auxpow_serialization_tests)

BOOST_AUTO_TEST_CASE(auxpow_roundtrip_with_flag)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot.SetNull();
    header.nTime = 1;
    header.nBits = 0x1d00ffff;
    header.nNonce = 2;
    header.SetBaseVersion(1, 8);
    header.SetAuxpowVersion(true);
    header.auxpow = CAuxPow::createAuxPow(header);

    DataStream stream{};
    stream << header;

    CBlockHeader decoded;
    stream >> decoded;

    BOOST_CHECK(decoded.IsAuxpow());
    BOOST_CHECK(decoded.auxpow);
    BOOST_CHECK_EQUAL(decoded.nVersion, header.nVersion);
    BOOST_CHECK(decoded.auxpow->getParentBlockHash() == header.auxpow->getParentBlockHash());
}

BOOST_AUTO_TEST_CASE(no_auxpow_roundtrip_clears_ptr)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot.SetNull();
    header.nTime = 3;
    header.nBits = 0x1d00ffff;
    header.nNonce = 4;

    DataStream stream{};
    stream << header;

    CBlockHeader decoded;
    stream >> decoded;

    BOOST_CHECK(!decoded.IsAuxpow());
    BOOST_CHECK(!decoded.auxpow);
    BOOST_CHECK_EQUAL(decoded.nVersion, header.nVersion);
}

BOOST_AUTO_TEST_SUITE_END()
