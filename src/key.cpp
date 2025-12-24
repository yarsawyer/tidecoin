// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <crypto/common.h>
#include <crypto/hmac_sha512.h>
#include <hash.h>
#include <random.h>
#include <sign/falcon-512/api.h>

extern "C" {
#include <sign/falcon-512/inner.h>
}

#include <secp256k1.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_recovery.h>

static secp256k1_context* secp256k1_context_sign = nullptr;

namespace {
    bool ComputeFalconPublicKey(const unsigned char* sk, size_t sk_len, std::array<unsigned char, CKey::PUB_KEY_SIZE>& pk_out)
    {
        if (sk_len != CKey::PRIVATE_KEY_SIZE) {
            return false;
        }
        if (sk[0] != 0x50 + 9) {
            return false;
        }

        int8_t f[512];
        int8_t g[512];
        uint16_t h[512];
        alignas(16) uint8_t tmp[2 * 512 * sizeof(uint16_t)];

        size_t u = 1;
        size_t v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
            f, 9, PQCLEAN_FALCON512_CLEAN_max_fg_bits[9],
            sk + u, sk_len - u);
        if (v == 0) {
            return false;
        }
        u += v;
        v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
            g, 9, PQCLEAN_FALCON512_CLEAN_max_fg_bits[9],
            sk + u, sk_len - u);
        if (v == 0) {
            return false;
        }

        if (!PQCLEAN_FALCON512_CLEAN_compute_public(h, f, g, 9, tmp)) {
            return false;
        }

        pk_out[0] = 0x00 + 9;
        v = PQCLEAN_FALCON512_CLEAN_modq_encode(
            pk_out.data() + 1, pk_out.size() - 1, h, 9);
        return v == pk_out.size() - 1;
    }
} // namespace



bool CKey::Check(const unsigned char *vch) {
    return vch != nullptr && vch[0] == 0x50 + 9;
}

bool CKey::SetPubKeyFromSecret()
{
    if (!keydata || !pubkeydata) {
        return false;
    }
    return ComputeFalconPublicKey(keydata->data(), keydata->size(), *pubkeydata);
}

void CKey::MakeNewKey(bool fCompressedIn) {
    unsigned char sk[PRIVATE_KEY_SIZE];
    unsigned char pk[PUB_KEY_SIZE];
    const int status = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
    assert(status == 0);
    MakeKeyData();
    memcpy(keydata->data(), sk, PRIVATE_KEY_SIZE);
    memcpy(pubkeydata->data(), pk, PUB_KEY_SIZE);
}

CPrivKey CKey::GetPrivKey() const {
    assert(keydata);
    CPrivKey seckey;
    seckey.resize(PRIVATE_KEY_SIZE);
    memcpy(seckey.data(), keydata->data(), keydata->size());
    return seckey;
}

CPubKey CKey::GetPubKey() const {
    assert(keydata);
    assert(pubkeydata);
    CPubKey result;
    unsigned char* pch = const_cast<unsigned char*>(result.begin());
    memcpy(pch + 1, pubkeydata->data(), pubkeydata->size());
    pch[0] = 7;
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
    if (!keydata) {
        return false;
    }

    size_t sig_len = 0;
    vchSig.resize(PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES);
    const int r = PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
        vchSig.data(), &sig_len, hash.begin(), 32, keydata->data());
    if (r != 0) {
        return false;
    }
    vchSig.resize(sig_len);
    return true;
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
    if (seckey.size() != PRIVATE_KEY_SIZE) {
        ClearKeyData();
        return false;
    }
    Set(seckey.begin(), seckey.end(), vchPubKey);
    if (!keydata || !pubkeydata) {
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
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKey();
        assert(pubkey.size() == CPubKey::SIZE);
        BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, vout.data());
    } else {
        assert(size() == 32);
        BIP32Hash(cc, nChild, 0, UCharCast(begin()), vout.data());
    }
    memcpy(ccChild.begin(), vout.data()+32, 32);
    keyChild.Set(begin(), begin() + 32);
    bool ret = secp256k1_ec_seckey_tweak_add(secp256k1_context_sign, (unsigned char*)keyChild.begin(), vout.data());
    if (!ret) keyChild.ClearKeyData();
    return ret;
}

EllSwiftPubKey CKey::EllSwiftCreate(std::span<const std::byte> ent32) const
{
    assert(keydata);
    assert(ent32.size() == 32);
    std::array<std::byte, EllSwiftPubKey::size()> encoded_pubkey;

    auto success = secp256k1_ellswift_create(secp256k1_context_sign,
                                             UCharCast(encoded_pubkey.data()),
                                             keydata->data(),
                                             UCharCast(ent32.data()));

    // Should always succeed for valid keys (asserted above).
    assert(success);
    return {encoded_pubkey};
}

ECDHSecret CKey::ComputeBIP324ECDHSecret(const EllSwiftPubKey& their_ellswift, const EllSwiftPubKey& our_ellswift, bool initiating) const
{
    assert(keydata);

    ECDHSecret output;
    // BIP324 uses the initiator as party A, and the responder as party B. Remap the inputs
    // accordingly:
    bool success = secp256k1_ellswift_xdh(secp256k1_context_sign,
                                          UCharCast(output.data()),
                                          UCharCast(initiating ? our_ellswift.data() : their_ellswift.data()),
                                          UCharCast(initiating ? their_ellswift.data() : our_ellswift.data()),
                                          keydata->data(),
                                          initiating ? 0 : 1,
                                          secp256k1_ellswift_xdh_hash_function_bip324,
                                          nullptr);
    // Should always succeed for valid keys (assert above).
    assert(success);
    return output;
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
