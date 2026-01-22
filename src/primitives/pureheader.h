// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_PUREHEADER_H
#define BITCOIN_PRIMITIVES_PUREHEADER_H

#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

#include <cassert>

/**
 * A block header without auxpow information.
 *
 * This avoids a cyclic dependency between auxpow (which references a parent
 * header) and the block header (which references an auxpow).
 */
class CPureBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CPureBlockHeader()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CPureBlockHeader, obj)
    {
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce);
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;
    uint256 GetPoWHash() const;
    uint256 GetScryptPoWHash() const;

    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }

    int64_t GetBlockTime() const
    {
        return static_cast<int64_t>(nTime);
    }

    // Version / auxpow helpers.
    static constexpr int32_t VERSION_AUXPOW = (1 << 8);
    static constexpr uint8_t VERSION_START_BIT = 16;
    static constexpr int32_t VERSION_CHAIN_START = (1 << VERSION_START_BIT);
    static constexpr int32_t VERSIONAUXPOW_TOP_MASK = (1 << 28) | (1 << 29) | (1 << 30);
    static constexpr int32_t MASK_AUXPOW_CHAINID_SHIFTED = (0x001f << VERSION_START_BIT);

    static bool IsAuxpow(int32_t ver)
    {
        return (ver & VERSION_AUXPOW) != 0;
    }

    bool IsAuxpow() const
    {
        return IsAuxpow(nVersion);
    }

    static void SetAuxpowVersion(int32_t& ver, bool auxpow)
    {
        if (auxpow) {
            ver |= VERSION_AUXPOW;
        } else {
            ver &= ~VERSION_AUXPOW;
        }
    }

    void SetAuxpowVersion(bool auxpow)
    {
        SetAuxpowVersion(nVersion, auxpow);
    }

    static int32_t GetBaseVersion(const int32_t& ver)
    {
        return (ver & ~VERSION_AUXPOW) & ~MASK_AUXPOW_CHAINID_SHIFTED;
    }

    int32_t GetBaseVersion() const
    {
        return GetBaseVersion(nVersion);
    }

    static void SetBaseVersion(int32_t& ver, int32_t nBaseVersion, const int32_t& nChainId)
    {
        const int32_t withoutTopMask = nBaseVersion & ~VERSIONAUXPOW_TOP_MASK;
        assert(withoutTopMask >= 0 && withoutTopMask < VERSION_CHAIN_START);
        assert(!IsAuxpow(ver));
        ver = nBaseVersion | (nChainId << VERSION_START_BIT);
    }

    void SetBaseVersion(int32_t nBaseVersion, const int32_t& nChainId)
    {
        SetBaseVersion(nVersion, nBaseVersion, nChainId);
    }

    static int32_t GetChainId(const int32_t& ver)
    {
        if (!IsAuxpow(ver)) {
            return 0;
        }
        return (ver & MASK_AUXPOW_CHAINID_SHIFTED) >> VERSION_START_BIT;
    }

    int32_t GetChainId() const
    {
        return GetChainId(nVersion);
    }

    static void SetChainId(int32_t& ver, const int32_t& chainId)
    {
        ver %= VERSION_CHAIN_START;
        ver |= chainId * VERSION_CHAIN_START;
    }

    void SetChainId(const int32_t& chainId)
    {
        SetChainId(nVersion, chainId);
    }

    static bool IsValidBaseVersion(const int32_t& nBaseVersion)
    {
        return (nBaseVersion & ~VERSIONAUXPOW_TOP_MASK) < VERSION_CHAIN_START;
    }

    static bool IsLegacy(const int32_t& ver)
    {
        return ver == 1;
    }

    bool IsLegacy() const
    {
        return IsLegacy(nVersion);
    }
};

#endif // BITCOIN_PRIMITIVES_PUREHEADER_H
