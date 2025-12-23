// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

namespace {
int64_t ClampTimespan(int64_t actual_timespan, const Consensus::Params& params)
{
    if (actual_timespan < params.nPowTargetTimespan / 4) {
        return params.nPowTargetTimespan / 4;
    }
    if (actual_timespan > params.nPowTargetTimespan * 4) {
        return params.nPowTargetTimespan * 4;
    }
    return actual_timespan;
}

arith_uint256 ScaleTarget(arith_uint256 target, int64_t actual_timespan, const Consensus::Params& params)
{
    const arith_uint256 pow_limit = UintToArith256(params.powLimit);
    const bool shift = target.bits() > pow_limit.bits() - 1;
    if (shift) {
        target >>= 1;
    }
    target *= actual_timespan;
    target /= params.nPowTargetTimespan;
    if (shift) {
        target <<= 1;
    }
    if (target > pow_limit) {
        target = pow_limit;
    }
    return target;
}

arith_uint256 CalculateExpectedTarget(uint32_t nBits, int64_t actual_timespan, const Consensus::Params& params)
{
    arith_uint256 target;
    target.SetCompact(nBits);
    return ScaleTarget(target, ClampTimespan(actual_timespan, params), params);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();
    CBlockIndex pindexLast;
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    arith_uint256 start_target = pow_limit >> 4;
    pindexLast.nHeight = consensus.DifficultyAdjustmentInterval() - 1;
    pindexLast.nTime = 1'000'000;
    pindexLast.nBits = start_target.GetCompact();
    int64_t nLastRetargetTime = pindexLast.nTime - consensus.nPowTargetTimespan;

    unsigned int expected_nbits = start_target.GetCompact();
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();
    CBlockIndex pindexLast;
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    pindexLast.nHeight = consensus.DifficultyAdjustmentInterval() - 1;
    pindexLast.nTime = consensus.nPowTargetTimespan * 12;
    pindexLast.nBits = pow_limit.GetCompact();
    int64_t nLastRetargetTime = pindexLast.nTime - (consensus.nPowTargetTimespan * 10);

    unsigned int expected_nbits = pow_limit.GetCompact();
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();
    CBlockIndex pindexLast;
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    arith_uint256 start_target = pow_limit >> 4;
    pindexLast.nHeight = consensus.DifficultyAdjustmentInterval() - 1;
    pindexLast.nTime = 3'000'000;
    pindexLast.nBits = start_target.GetCompact();
    int64_t nLastRetargetTime = pindexLast.nTime - (consensus.nPowTargetTimespan / 10);

    const arith_uint256 expected_target = CalculateExpectedTarget(pindexLast.nBits, pindexLast.GetBlockTime() - nLastRetargetTime, consensus);
    unsigned int expected_nbits = expected_target.GetCompact();
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1, pindexLast.nBits, expected_nbits));
    // Test that reducing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = (expected_target >> 1).GetCompact();
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1, pindexLast.nBits, invalid_nbits));
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();
    CBlockIndex pindexLast;
    const arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
    arith_uint256 start_target = pow_limit >> 6;
    pindexLast.nHeight = consensus.DifficultyAdjustmentInterval() - 1;
    pindexLast.nTime = consensus.nPowTargetTimespan * 12;
    pindexLast.nBits = start_target.GetCompact();
    int64_t nLastRetargetTime = pindexLast.nTime - (consensus.nPowTargetTimespan * 10);

    const arith_uint256 expected_target = CalculateExpectedTarget(pindexLast.nBits, pindexLast.GetBlockTime() - nLastRetargetTime, consensus);
    unsigned int expected_nbits = expected_target.GetCompact();
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1, pindexLast.nBits, expected_nbits));
    // Test that increasing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = (expected_target << 1).GetCompact();
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1, pindexLast.nBits, invalid_nbits));
}

BOOST_AUTO_TEST_CASE(get_next_work_first_retarget_period)
{
    Consensus::Params params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    params.nPowTargetTimespan = 10;
    params.nPowTargetSpacing = 1;
    params.fPowAllowMinDifficultyBlocks = false;
    params.fPowNoRetargeting = false;

    const int interval = params.DifficultyAdjustmentInterval();
    std::vector<CBlockIndex> blocks(interval);
    for (int i = 0; i < interval; ++i) {
        blocks[i].nHeight = i;
        blocks[i].nTime = 1000 + i;
        blocks[i].nBits = UintToArith256(params.powLimit).GetCompact();
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].BuildSkip();
    }

    CBlockHeader dummy;
    dummy.nTime = blocks.back().nTime + params.nPowTargetSpacing;
    unsigned int expected = CalculateNextWorkRequired(&blocks.back(), blocks.front().GetBlockTime(), params);
    unsigned int actual = GetNextWorkRequired(&blocks.back(), &dummy, params);
    BOOST_CHECK_EQUAL(actual, expected);
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p3 = &blocks[m_rng.randrange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // ensure scaling doesn't exceed pow_limit and stays consistent with overflow guard
    if (!consensus.fPowNoRetargeting) {
        arith_uint256 pow_limit = UintToArith256(consensus.powLimit);
        arith_uint256 scaled = ScaleTarget(pow_limit, consensus.nPowTargetTimespan * 4, consensus);
        BOOST_CHECK_EQUAL(scaled, pow_limit);
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

BOOST_AUTO_TEST_SUITE_END()
