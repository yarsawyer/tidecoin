// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/pureheader.h>

#include <crypto/scrypt.h>
#include <crypto/yespower/tidecoin_pow.h>
#include <hash.h>
#include <streams.h>

uint256 CPureBlockHeader::GetHash() const
{
    HashWriter writer;
    writer << *this;
    return writer.GetHash();
}

uint256 CPureBlockHeader::GetPoWHash() const
{
    DataStream stream{};
    stream << *this;
    uint256 pow_hash;
    assert(TidecoinYespowerHash(MakeUCharSpan(stream), pow_hash));
    return pow_hash;
}

uint256 CPureBlockHeader::GetScryptPoWHash() const
{
    DataStream stream{};
    stream << *this;
    assert(stream.size() == 80);
    uint256 pow_hash;
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(stream.data()),
                        reinterpret_cast<char*>(pow_hash.begin()));
    return pow_hash;
}
