// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>

#include <hash.h>
#include <pq/pq_api.h>
#include <secp256k1.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_recovery.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <cassert>

namespace {

struct Secp256k1SelfTester
{
    Secp256k1SelfTester() {
        /* Run libsecp256k1 self-test before using the secp256k1_context_static. */
        secp256k1_selftest();
    }
} SECP256K1_SELFTESTER;

} // namespace

bool CPubKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
    if (!IsValid()) {
        return false;
    }
    return pq::VerifyPrefixed(std::span<const unsigned char>{hash.begin(), 32},
                              vchSig,
                              std::span<const unsigned char>{begin(), size()},
                              false);
}

bool CPubKey::Recover(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    if (vchSig.size() <= SIZE - 1) {
        return false;
    }
    unsigned int mlen = vchSig.size() - (SIZE - 1);
    unsigned char *pch = const_cast<unsigned char*>(begin());
    memcpy(pch + 1, vchSig.data() + mlen, SIZE - 1);
    pch[0] = pq::kFalcon512Info.prefix;
    return pq::VerifyPrefixed(std::span<const unsigned char>{hash.begin(), 32},
                              std::span<const unsigned char>{vchSig.data(), mlen},
                              std::span<const unsigned char>{begin(), size()},
                              false);
}

bool CPubKey::IsFullyValid() const {
    return IsValid();
}

bool CPubKey::Derive(CPubKey& pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const {
    (void)pubkeyChild;
    (void)ccChild;
    (void)nChild;
    (void)cc;
    return false;
}

EllSwiftPubKey::EllSwiftPubKey(std::span<const std::byte> ellswift) noexcept
{
    assert(ellswift.size() == SIZE);
    std::copy(ellswift.begin(), ellswift.end(), m_pubkey.begin());
}

CPubKey EllSwiftPubKey::Decode() const
{
    secp256k1_pubkey pubkey;
    secp256k1_ellswift_decode(secp256k1_context_static, &pubkey, UCharCast(m_pubkey.data()));

    size_t sz = CPubKey::SIZE;
    std::array<uint8_t, CPubKey::SIZE> vch_bytes;

    secp256k1_ec_pubkey_serialize(secp256k1_context_static, vch_bytes.data(), &sz, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(sz == vch_bytes.size());

    return CPubKey{vch_bytes.begin(), vch_bytes.end()};
}

void CExtPubKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    WriteBE32(code+5, nChild);
    memcpy(code+9, chaincode.begin(), 32);
    assert(pubkey.size() == CPubKey::SIZE);
    memcpy(code+41, pubkey.begin(), CPubKey::SIZE);
}

void CExtPubKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = ReadBE32(code+5);
    memcpy(chaincode.begin(), code+9, 32);
    pubkey.Set(code+41, code+BIP32_EXTKEY_SIZE);
    if ((nDepth == 0 && (nChild != 0 || ReadLE32(vchFingerprint) != 0)) || !pubkey.IsFullyValid()) pubkey = CPubKey();
}

void CExtPubKey::EncodeWithVersion(unsigned char code[BIP32_EXTKEY_WITH_VERSION_SIZE]) const
{
    memcpy(code, version, 4);
    Encode(&code[4]);
}

void CExtPubKey::DecodeWithVersion(const unsigned char code[BIP32_EXTKEY_WITH_VERSION_SIZE])
{
    memcpy(version, code, 4);
    Decode(&code[4]);
}

bool CExtPubKey::Derive(CExtPubKey &out, unsigned int _nChild) const {
    if (nDepth == std::numeric_limits<unsigned char>::max()) return false;
    out.nDepth = nDepth + 1;
    CKeyID id = pubkey.GetID();
    memcpy(out.vchFingerprint, &id, 4);
    out.nChild = _nChild;
    return pubkey.Derive(out.pubkey, out.chaincode, _nChild, chaincode);
}
