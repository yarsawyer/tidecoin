// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <primitives/pureheader.h>

#include <crypto/yespower/tidecoin_pow.h>
#include <hash.h>
#include <streams.h>
#include <tinyformat.h>

namespace {
CPureBlockHeader MakePureHeader(const CBlockHeader& header)
{
    CPureBlockHeader pure;
    pure.nVersion = header.nVersion;
    pure.hashPrevBlock = header.hashPrevBlock;
    pure.hashMerkleRoot = header.hashMerkleRoot;
    pure.nTime = header.nTime;
    pure.nBits = header.nBits;
    pure.nNonce = header.nNonce;
    return pure;
}
} // namespace

uint256 CBlockHeader::GetHash() const
{
    return MakePureHeader(*this).GetHash();
}

uint256 CBlockHeader::GetPoWHash() const
{
    return MakePureHeader(*this).GetPoWHash();
}

uint256 CBlockHeader::GetScryptPoWHash() const
{
    return MakePureHeader(*this).GetScryptPoWHash();
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
