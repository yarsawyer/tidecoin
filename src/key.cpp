// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <crypto/common.h>
#include <crypto/hmac_sha512.h>
#include <hash.h>
#include <pq/pq_api.h>
#include <random.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

static secp256k1_context* secp256k1_context_sign = nullptr;

bool CKey::DecodeSecretKey(std::span<const unsigned char> vch,
                           const pq::SchemeInfo*& info,
                           std::span<const unsigned char>& raw)
{
    return pq::DecodeSecretKey(vch, info, raw);
}

bool CKey::SetPubKeyFromSecret()
{
    if (keydata.empty() || pubkeydata.empty()) {
        return false;
    }
    return pq::ComputePublicKeyFromSecret(Scheme(),
                                          std::span<const unsigned char>{keydata.data(), keydata.size()},
                                          std::span<unsigned char>{pubkeydata.data(), pubkeydata.size()});
}

void CKey::MakeNewKey(bool fCompressedIn) {
    const auto& scheme = pq::ActiveScheme();
    (void)fCompressedIn;
    m_scheme = &scheme;
    MakeKeyData();
    const bool ok = pq::GenerateKeyPair(scheme,
                                        std::span<unsigned char>{pubkeydata.data(), pubkeydata.size()},
                                        std::span<unsigned char>{keydata.data(), keydata.size()});
    if (!ok) {
        ClearKeyData();
    }
}

CPrivKey CKey::GetPrivKey() const {
    assert(!keydata.empty());
    CPrivKey seckey;
    if (!pq::EncodeSecretKey(Scheme(),
                             std::span<const unsigned char>{keydata.data(), keydata.size()},
                             seckey)) {
        return {};
    }
    return seckey;
}

CPubKey CKey::GetPubKey() const {
    assert(!keydata.empty());
    assert(!pubkeydata.empty());
    CPubKey result;
    unsigned char* pch = const_cast<unsigned char*>(result.begin());
    memcpy(pch + 1, pubkeydata.data(), pubkeydata.size());
    pch[0] = Scheme().prefix;
    return result;
}

// Check that the sig has a low R value and will be less than 71 bytes
bool SigHasLowR(const secp256k1_ecdsa_signature* sig)
{
    unsigned char compact_sig[64];
    secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_sign, compact_sig, sig);

    // In DER serialization, all values are interpreted as big-endian, signed integers. The highest bit in the integer indicates
    // its signed-ness; 0 is positive, 1 is negative. When the value is interpreted as a negative integer, it must be converted
    // to a positive value by prepending a 0x00 byte so that the highest bit is 0. We can avoid this prepending by ensuring that
    // our highest bit is always 0, and thus we must check that the first byte is less than 0x80.
    return compact_sig[0] < 0x80;
}

bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, bool grind, uint32_t test_case) const {
    (void)grind;
    (void)test_case;
    if (keydata.empty()) {
        return false;
    }
    return pq::Sign(Scheme(), std::span<const unsigned char>{hash.begin(), 32},
                    std::span<const unsigned char>{keydata.data(), keydata.size()}, vchSig, false);
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const {
    unsigned char rnd[8];
    std::string str = "Tidecoin key verification\n";
    GetRandBytes(rnd);
    uint256 hash{Hash(str, rnd)};
    std::vector<unsigned char> vchSig;
    Sign(hash, vchSig);
    return pubkey.Verify(hash, vchSig);
}

bool CKey::Load(const CPrivKey &seckey, const CPubKey &vchPubKey, bool fSkipCheck=false) {
    Set(seckey.begin(), seckey.end(), vchPubKey);
    if (keydata.empty() || pubkeydata.empty()) {
        return false;
    }
    if (fSkipCheck) {
        return true;
    }
    return VerifyPubKey(vchPubKey);
}

bool CKey::Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const {
    assert(IsValid());
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    if (size() != 32) {
        return false;
    }
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKey();
        assert(pubkey.size() == CPubKey::COMPRESSED_SIZE);
        BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, vout.data());
    } else {
        BIP32Hash(cc, nChild, 0, UCharCast(begin()), vout.data());
    }
    memcpy(ccChild.begin(), vout.data()+32, 32);
    keyChild.Set(begin(), begin() + 32);
    bool ret = secp256k1_ec_seckey_tweak_add(secp256k1_context_sign, (unsigned char*)keyChild.begin(), vout.data());
    if (!ret) keyChild.ClearKeyData();
    return ret;
}

CKey GenerateRandomKey(bool compressed) noexcept
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/compressed);
    return key;
}

bool CExtKey::Derive(CExtKey &out, unsigned int _nChild) const {
    if (nDepth == std::numeric_limits<unsigned char>::max()) return false;
    out.nDepth = nDepth + 1;
    CKeyID id = key.GetPubKey().GetID();
    memcpy(out.vchFingerprint, &id, 4);
    out.nChild = _nChild;
    return key.Derive(out.key, out.chaincode, _nChild, chaincode);
}

void CExtKey::SetSeed(std::span<const std::byte> seed)
{
    static const unsigned char hashkey[] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    CHMAC_SHA512{hashkey, sizeof(hashkey)}.Write(UCharCast(seed.data()), seed.size()).Finalize(vout.data());
    key.Set(vout.data(), vout.data() + 32);
    memcpy(chaincode.begin(), vout.data() + 32, 32);
    nDepth = 0;
    nChild = 0;
    memset(vchFingerprint, 0, sizeof(vchFingerprint));
}

CExtPubKey CExtKey::Neuter() const {
    CExtPubKey ret;
    ret.nDepth = nDepth;
    memcpy(ret.vchFingerprint, vchFingerprint, 4);
    ret.nChild = nChild;
    ret.pubkey = key.GetPubKey();
    ret.chaincode = chaincode;
    return ret;
}

void CExtKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    WriteBE32(code+5, nChild);
    memcpy(code+9, chaincode.begin(), 32);
    code[41] = 0;
    assert(key.size() == 32);
    memcpy(code+42, key.begin(), 32);
}

void CExtKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = ReadBE32(code+5);
    memcpy(chaincode.begin(), code+9, 32);
    key.Set(code+42, code+BIP32_EXTKEY_SIZE);
    if ((nDepth == 0 && (nChild != 0 || ReadLE32(vchFingerprint) != 0)) || code[41] != 0) key = CKey();
}

bool ECC_InitSanityCheck() {
    CKey key = GenerateRandomKey();
    CPubKey pubkey = key.GetPubKey();
    return key.VerifyPubKey(pubkey);
}

/** Initialize the elliptic curve support. May not be called twice without calling ECC_Stop first. */
static void ECC_Start() {
    assert(secp256k1_context_sign == nullptr);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    assert(ctx != nullptr);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
        GetRandBytes(vseed);
        bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }

    secp256k1_context_sign = ctx;
}

/** Deinitialize the elliptic curve support. No-op if ECC_Start wasn't called first. */
static void ECC_Stop() {
    secp256k1_context *ctx = secp256k1_context_sign;
    secp256k1_context_sign = nullptr;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}

ECC_Context::ECC_Context()
{
    ECC_Start();
}

ECC_Context::~ECC_Context()
{
    ECC_Stop();
}
