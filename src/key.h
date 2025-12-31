// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEY_H
#define BITCOIN_KEY_H

#include <pubkey.h>
#include <pq/pq_scheme.h>
#include <serialize.h>
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
    static constexpr unsigned int SIZE = pq::kFalcon512Info.seckey_bytes;

private:
    using KeyData = std::vector<unsigned char, secure_allocator<unsigned char>>;

    const pq::SchemeInfo* m_scheme{&pq::kFalcon512Info};
    KeyData keydata;
    KeyData pubkeydata;

    //! Decode a potentially prefixed secret key and return the raw bytes.
    bool static DecodeSecretKey(std::span<const unsigned char> vch,
                                const pq::SchemeInfo*& info,
                                std::span<const unsigned char>& raw);
    bool SetPubKeyFromSecret();

    void MakeKeyData()
    {
        if (m_scheme == nullptr) {
            m_scheme = &pq::kFalcon512Info;
        }
        keydata.assign(m_scheme->seckey_bytes, 0);
        pubkeydata.assign(m_scheme->pubkey_bytes, 0);
    }

    void ClearKeyData()
    {
        keydata.clear();
        pubkeydata.clear();
        m_scheme = &pq::kFalcon512Info;
    }

    const pq::SchemeInfo& Scheme() const { return *m_scheme; }

public:
    CKey() noexcept = default;
    CKey(CKey&&) noexcept = default;
    CKey& operator=(CKey&&) noexcept = default;

    CKey& operator=(const CKey& other)
    {
        if (this != &other) {
            if (other.IsValid()) {
                m_scheme = other.m_scheme;
                keydata = other.keydata;
                pubkeydata = other.pubkeydata;
            } else {
                ClearKeyData();
            }
        }
        return *this;
    }

    CKey(const CKey& other) { *this = other; }

    friend bool operator==(const CKey& a, const CKey& b)
    {
        return a.size() == b.size() &&
            memcmp(a.data(), b.data(), a.size()) == 0;
    }

    //! Initialize using begin and end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        if (pbegin == pend) {
            ClearKeyData();
        } else {
            const size_t len = static_cast<size_t>(pend - pbegin);
            const unsigned char* ptr = UCharCast(&pbegin[0]);
            const std::span<const unsigned char> sk{ptr, len};
            const pq::SchemeInfo* info = nullptr;
            std::span<const unsigned char> raw;
            if (DecodeSecretKey(sk, info, raw)) {
                m_scheme = info;
                MakeKeyData();
                memcpy(keydata.data(), raw.data(), keydata.size());
                if (!SetPubKeyFromSecret()) {
                    ClearKeyData();
                }
            } else {
                ClearKeyData();
            }
        }
    }

    template <typename T>
    void Set(const T pbegin, const T pend, const CPubKey& pubkey)
    {
        if (pbegin == pend) {
            ClearKeyData();
            return;
        }
        const size_t len = static_cast<size_t>(pend - pbegin);
        const unsigned char* ptr = UCharCast(&pbegin[0]);
        const pq::SchemeInfo* info = nullptr;
        std::span<const unsigned char> raw;
        if (!DecodeSecretKey(std::span<const unsigned char>{ptr, len}, info, raw) || pubkey.size() == 0) {
            ClearKeyData();
            return;
        }
        const pq::SchemeInfo* pub_info = pq::SchemeFromPrefix(pubkey[0]);
        if (!pub_info || pub_info != info || pubkey.size() != pub_info->pubkey_bytes + 1) {
            ClearKeyData();
            return;
        }
        m_scheme = info;
        MakeKeyData();
        memcpy(keydata.data(), raw.data(), keydata.size());
        memcpy(pubkeydata.data(), pubkey.data() + 1, pubkeydata.size());
    }

    //! Simple read-only vector-like interface.
    unsigned int size() const { return static_cast<unsigned int>(keydata.size()); }
    const std::byte* data() const { return keydata.empty() ? nullptr : reinterpret_cast<const std::byte*>(keydata.data()); }
    const std::byte* begin() const { return data(); }
    const std::byte* end() const { return data() + size(); }
    unsigned int pksize() const { return static_cast<unsigned int>(pubkeydata.size()); }
    const unsigned char* pkbegin() const { return pubkeydata.empty() ? nullptr : pubkeydata.data(); }
    const unsigned char* pkend() const { return pubkeydata.empty() ? nullptr : pubkeydata.data() + pubkeydata.size(); }

    //! Check whether this private key is valid.
    bool IsValid() const { return !keydata.empty(); }

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

    //! Derive BIP32 child key.
    [[nodiscard]] bool Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const;

    /**
     * Verify thoroughly whether a private key and a public key match.
     * This is done using a different mechanism than just regenerating it.
     */
    bool VerifyPubKey(const CPubKey& vchPubKey) const;

    //! Load private key and check that public key matches.
    bool Load(const CPrivKey& privkey, const CPubKey& vchPubKey, bool fSkipCheck);

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
