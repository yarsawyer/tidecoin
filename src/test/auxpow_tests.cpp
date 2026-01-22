// Copyright (c) 2024-present The Tidecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>
#include <arith_uint256.h>
#include <chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

namespace auxpow_tests {
class CAuxPowForTest
{
public:
    static CPureBlockHeader& Parent(CAuxPow& auxpow)
    {
        return auxpow.parentBlock;
    }
};
} // namespace auxpow_tests

namespace {
CBlockHeader MakeTestHeader(const Consensus::Params& params)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot.SetNull();
    header.nTime = 1;
    header.nBits = UintToArith256(params.powLimit).GetCompact();
    header.nNonce = 1;
    return header;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(auxpow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(auxpow_missing_header_rejected)
{
    auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    params.fStrictChainId = false;

    CBlockHeader header = MakeTestHeader(params);
    header.SetAuxpowVersion(true);
    header.auxpow = CAuxPow::createAuxPow(header);

    BOOST_CHECK(!header.auxpow->check(header.GetHash(), params.nAuxpowChainId, params));
}

BOOST_AUTO_TEST_CASE(auxpow_parent_chainid_rejected)
{
    auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    params.fStrictChainId = true;

    CBlockHeader header = MakeTestHeader(params);
    header.SetAuxpowVersion(true);
    header.auxpow = CAuxPow::createAuxPow(header);

    CPureBlockHeader& parent = auxpow_tests::CAuxPowForTest::Parent(*header.auxpow);
    parent.SetNull();
    parent.SetBaseVersion(2, params.nAuxpowChainId);
    parent.SetAuxpowVersion(true);

    BOOST_CHECK(!header.auxpow->check(header.GetHash(), params.nAuxpowChainId, params));
}

BOOST_AUTO_TEST_SUITE_END()
