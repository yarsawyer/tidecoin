// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEY_H
#define BITCOIN_KEY_H

#include <pubkey.h>
#include <serialize.h>
#include <sign/falcon-512/api.h>
#include <support/allocators/secure.h>
#include <uint256.h>

#include <stdexcept>
#include <vector>


/**
 * CPrivKey is a serialized private key, with all parameters included
 * (SIZE bytes)
 */
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;

/** Size of ECDH shared secrets. */
constexpr static size_t ECDH_SECRET_SIZE = CSHA256::OUTPUT_SIZE;

// Used to represent ECDH shared secret (ECDH_SECRET_SIZE bytes)
using ECDHSecret = std::array<std::byte, ECDH_SECRET_SIZE>;

/** An encapsulated private key. */
class CKey
{
public:
    static constexpr unsigned int PRIVATE_KEY_SIZE = PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES;
    static constexpr unsigned int COMPRESSED_PRIVATE_KEY_SIZE = PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES;
    static constexpr unsigned int PUB_KEY_SIZE = PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES;
    static constexpr unsigned int SIGN_SIZE = PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES;
    static constexpr unsigned int SIZE = PRIVATE_KEY_SIZE;
    static constexpr unsigned int COMPRESSED_SIZE = COMPRESSED_PRIVATE_KEY_SIZE;
    /**
     * see www.keylength.com
     * script supports up to 75 for single byte push
     */
    static_assert(
        PRIVATE_KEY_SIZE >= COMPRESSED_PRIVATE_KEY_SIZE,
        "COMPRESSED_PRIVATE_KEY_SIZE is larger than PRIVATE_KEY_SIZE");

private:
    /** Internal data container for private key material. */
    using KeyTypeSk = std::array<unsigned char, PRIVATE_KEY_SIZE>;
    using KeyTypePk = std::array<unsigned char, PUB_KEY_SIZE>;

    //! Whether the public key corresponding to this private key is (to be) compressed.
    bool fCompressed{false};

    //! The actual byte data. nullptr for invalid keys.
    secure_unique_ptr<KeyTypeSk> keydata;
    secure_unique_ptr<KeyTypePk> pubkeydata;

    //! Check whether the 32-byte array pointed to by vch is valid keydata.
    bool static Check(const unsigned char* vch);
    bool SetPubKeyFromSecret();

    void MakeKeyData()
    {
        if (!keydata) keydata = make_secure_unique<KeyTypeSk>();
        if (!pubkeydata) pubkeydata = make_secure_unique<KeyTypePk>();
    }

    void ClearKeyData()
    {
        keydata.reset();
        pubkeydata.reset();
    }

public:
    CKey() noexcept = default;
    CKey(CKey&&) noexcept = default;
    CKey& operator=(CKey&&) noexcept = default;

    CKey& operator=(const CKey& other)
    {
        if (this != &other) {
            if (other.keydata && other.pubkeydata) {
                MakeKeyData();
                *keydata = *other.keydata;
                *pubkeydata = *other.pubkeydata;
            } else {
                ClearKeyData();
            }
            fCompressed = other.fCompressed;
        }
        return *this;
    }

    CKey(const CKey& other) { *this = other; }

    friend bool operator==(const CKey& a, const CKey& b)
    {
        return a.fCompressed == b.fCompressed &&
            a.size() == b.size() &&
            memcmp(a.data(), b.data(), a.size()) == 0;
    }

    //! Initialize using begin and end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend, bool fCompressedIn)
    {
        if (size_t(pend - pbegin) != std::tuple_size_v<KeyTypeSk>) {
            ClearKeyData();
        } else if (Check(UCharCast(&pbegin[0]))) {
            MakeKeyData();
            memcpy(keydata->data(), (unsigned char*)&pbegin[0], keydata->size());
            fCompressed = fCompressedIn;
            if (!SetPubKeyFromSecret()) {
                ClearKeyData();
            }
        } else {
            ClearKeyData();
        }
    }

    template <typename T>
    void Set(const T pbegin, const T pend, const CPubKey& pubkey, bool fCompressedIn)
    {
        if (size_t(pend - pbegin) != std::tuple_size_v<KeyTypeSk> ||
            pubkey.size() != PUB_KEY_SIZE + 1) {
            ClearKeyData();
        } else if (Check(UCharCast(&pbegin[0]))) {
            MakeKeyData();
            memcpy(keydata->data(), (unsigned char*)&pbegin[0], keydata->size());
            memcpy(pubkeydata->data(), pubkey.data() + 1, pubkeydata->size());
            fCompressed = fCompressedIn;
        } else {
            ClearKeyData();
        }
    }

    //! Simple read-only vector-like interface.
    unsigned int size() const { return keydata ? keydata->size() : 0; }
    const std::byte* data() const { return keydata ? reinterpret_cast<const std::byte*>(keydata->data()) : nullptr; }
    const std::byte* begin() const { return data(); }
    const std::byte* end() const { return data() + size(); }
    unsigned int pksize() const { return pubkeydata ? pubkeydata->size() : 0; }
    const unsigned char* pkbegin() const { return pubkeydata ? pubkeydata->data() : nullptr; }
    const unsigned char* pkend() const { return pubkeydata ? pubkeydata->data() + pubkeydata->size() : nullptr; }

    //! Check whether this private key is valid.
    bool IsValid() const { return !!keydata; }

    //! Check whether the public key corresponding to this private key is (to be) compressed.
    bool IsCompressed() const { return fCompressed; }

    //! Generate a new private key using a cryptographic PRNG.
    void MakeNewKey(bool fCompressed);

    /**
     * Convert the private key to a CPrivKey (serialized OpenSSL private key data).
     * This is expensive.
     */
    CPrivKey GetPrivKey() const;

    /**
     * Compute the public key from a private key.
     * This is expensive.
     */
    CPubKey GetPubKey() const;

    /**
     * Create a DER-serialized signature.
     * The test_case parameter tweaks the deterministic nonce.
     */
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig, bool grind = true, uint32_t test_case = 0) const;

    /**
     * Create a compact signature (65 bytes), which allows reconstructing the used public key.
     * The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
     * The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
     *                  0x1D = second key with even y, 0x1E = second key with odd y,
     *                  add 0x04 for compressed keys.
     */
    bool SignCompact(const uint256& hash, std::vector<unsigned char>& vchSig) const;

    //! Derive BIP32 child key.
    [[nodiscard]] bool Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const;

    /**
     * Verify thoroughly whether a private key and a public key match.
     * This is done using a different mechanism than just regenerating it.
     */
    bool VerifyPubKey(const CPubKey& vchPubKey) const;

    //! Load private key and check that public key matches.
    bool Load(const CPrivKey& privkey, const CPubKey& vchPubKey, bool fSkipCheck);

    /** Create an ellswift-encoded public key for this key, with specified entropy.
     *
     *  entropy must be a 32-byte span with additional entropy to use in the encoding. Every
     *  public key has ~2^256 different encodings, and this function will deterministically pick
     *  one of them, based on entropy. Note that even without truly random entropy, the
     *  resulting encoding will be indistinguishable from uniform to any adversary who does not
     *  know the private key (because the private key itself is always used as entropy as well).
     */
    EllSwiftPubKey EllSwiftCreate(std::span<const std::byte> entropy) const;

    /** Compute a BIP324-style ECDH shared secret.
     *
     *  - their_ellswift: EllSwiftPubKey that was received from the other side.
     *  - our_ellswift: EllSwiftPubKey that was sent to the other side (must have been generated
     *                  from *this using EllSwiftCreate()).
     *  - initiating: whether we are the initiating party (true) or responding party (false).
     */
    ECDHSecret ComputeBIP324ECDHSecret(const EllSwiftPubKey& their_ellswift,
                                       const EllSwiftPubKey& our_ellswift,
                                       bool initiating) const;
};

CKey GenerateRandomKey(bool compressed = true) noexcept;

struct CExtKey {
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    ChainCode chaincode;
    CKey key;

    friend bool operator==(const CExtKey& a, const CExtKey& b)
    {
        return a.nDepth == b.nDepth &&
            memcmp(a.vchFingerprint, b.vchFingerprint, sizeof(vchFingerprint)) == 0 &&
            a.nChild == b.nChild &&
            a.chaincode == b.chaincode &&
            a.key == b.key;
    }

    CExtKey() = default;
    CExtKey(const CExtPubKey& xpub, const CKey& key_in) : nDepth(xpub.nDepth), nChild(xpub.nChild), chaincode(xpub.chaincode), key(key_in)
    {
        std::copy(xpub.vchFingerprint, xpub.vchFingerprint + sizeof(xpub.vchFingerprint), vchFingerprint);
    }

    void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);
    [[nodiscard]] bool Derive(CExtKey& out, unsigned int nChild) const;
    CExtPubKey Neuter() const;
    void SetSeed(std::span<const std::byte> seed);
};

/** Check that required EC support is available at runtime. */
bool ECC_InitSanityCheck();

/**
 * RAII class initializing and deinitializing global state for elliptic curve support.
 * Only one instance may be initialized at a time.
 *
 * In the future global ECC state could be removed, and this class could contain
 * state and be passed as an argument to ECC key functions.
 */
class ECC_Context
{
public:
    ECC_Context();
    ~ECC_Context();
};

#endif // BITCOIN_KEY_H
