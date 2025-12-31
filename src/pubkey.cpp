// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>

#include <hash.h>
#include <pq/pq_api.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <array>
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

bool CPubKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig, bool legacy_mode) const {
    if (!IsValid()) {
        return false;
    }
    return pq::VerifyPrefixed(std::span<const unsigned char>{hash.begin(), 32},
                              vchSig,
                              std::span<const unsigned char>{begin(), size()},
                              legacy_mode);
}

bool CPubKey::Recover(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    const auto msg32 = std::span<const unsigned char>{hash.begin(), 32};

    // Tidecoin does not have a recovery ID for PQ signatures. For message signing,
    // recovery is achieved by embedding the raw scheme pubkey bytes in the signature:
    //
    //   sig = signature_bytes || pubkey_bytes_without_prefix
    //
    // This function recovers by trying each known scheme and verifying.
    for (const pq::SchemeInfo* scheme : {&pq::kFalcon512Info, &pq::kFalcon1024Info, &pq::kMLDSA44Info, &pq::kMLDSA65Info, &pq::kMLDSA87Info}) {
        const size_t raw_pk_len = scheme->pubkey_bytes;
        if (vchSig.size() <= raw_pk_len) {
            continue;
        }
        const size_t sig_len = vchSig.size() - raw_pk_len;

        std::array<unsigned char, CPubKey::SIZE> prefixed_pubkey{};
        prefixed_pubkey[0] = scheme->prefix;
        std::memcpy(prefixed_pubkey.data() + 1, vchSig.data() + sig_len, raw_pk_len);

        const std::span<const unsigned char> prefixed_pk_span{prefixed_pubkey.data(), raw_pk_len + 1};
        const std::span<const unsigned char> sig_span{vchSig.data(), sig_len};

        if (pq::VerifyPrefixed(msg32, sig_span, prefixed_pk_span, /*legacy_mode=*/false)) {
            Set(prefixed_pk_span.begin(), prefixed_pk_span.end());
            return true;
        }
    }

    return false;
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

void CExtPubKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    WriteBE32(code+5, nChild);
    memcpy(code+9, chaincode.begin(), 32);
    assert(pubkey.size() == CPubKey::COMPRESSED_SIZE);
    memcpy(code+41, pubkey.begin(), CPubKey::COMPRESSED_SIZE);
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
