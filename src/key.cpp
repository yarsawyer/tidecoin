// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <crypto/common.h>
#include <hash.h>
#include <pq/pq_api.h>
#include <random.h>

#include <algorithm>

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

void CKey::MakeNewKey(pq::SchemeId scheme_id) {
    const pq::SchemeInfo* scheme = pq::SchemeFromId(scheme_id);
    if (scheme == nullptr) {
        ClearKeyData();
        return;
    }
    m_scheme = scheme;
    MakeKeyData();
    const bool ok = pq::GenerateKeyPair(*scheme,
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
    std::vector<unsigned char> prefixed_pubkey(pubkeydata.size() + 1);
    prefixed_pubkey[0] = Scheme().prefix;
    std::copy(pubkeydata.begin(), pubkeydata.end(), prefixed_pubkey.begin() + 1);
    return CPubKey(std::span<const uint8_t>(prefixed_pubkey));
}

bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, bool grind, uint32_t test_case, bool legacy_mode) const {
    (void)grind;
    (void)test_case;
    if (keydata.empty()) {
        return false;
    }
    return pq::Sign(Scheme(), std::span<const unsigned char>{hash.begin(), 32},
                    std::span<const unsigned char>{keydata.data(), keydata.size()}, vchSig, legacy_mode);
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

CKey GenerateRandomKey(pq::SchemeId scheme_id) noexcept
{
    CKey key;
    key.MakeNewKey(scheme_id);
    return key;
}
