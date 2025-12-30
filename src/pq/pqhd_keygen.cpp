#include <pq/pq_api.h>

#include <pq/pqhd_kdf.h>

#include <support/cleanse.h>

#include <algorithm>
#include <array>
#include <cstdint>

namespace pq {
namespace {

constexpr uint32_t PQHD_VERSION_V1 = 1;

void WipeAndResetSecret(pq::SecureKeyBytes& sk)
{
    if (sk.data() != nullptr && sk.capacity() > 0) {
        memory_cleanse(sk.data(), sk.capacity());
    }
    pq::SecureKeyBytes{}.swap(sk);
}

} // namespace

bool KeyGenFromSeed(uint32_t pqhd_version,
                    SchemeId scheme_id,
                    std::span<const uint8_t, 64> key_material,
                    std::vector<uint8_t>& pk_out,
                    SecureKeyBytes& sk_out)
{
    pk_out.clear();
    WipeAndResetSecret(sk_out);

    if (pqhd_version != PQHD_VERSION_V1) {
        return false;
    }

    const SchemeInfo* info = SchemeFromId(scheme_id);
    if (!info) {
        return false;
    }

    pqhd::KeygenStreamBlock64 block0 = pqhd::DeriveKeygenStreamBlock(key_material, /*ctr=*/0);

    std::vector<uint8_t> pk_local(info->pubkey_bytes);
    SecureKeyBytes sk_local(info->seckey_bytes);

    int rc = -1;
    bool supported_scheme{true};
    switch (scheme_id) {
    case SchemeId::FALCON_512: {
        std::array<uint8_t, 48> seed{};
        std::copy_n(block0.begin(), seed.size(), seed.begin());
        rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_deterministic(
            pk_local.data(), sk_local.data(), seed.data(), seed.size());
        memory_cleanse(seed.data(), seed.size());
        break;
    }
    case SchemeId::FALCON_1024: {
        std::array<uint8_t, 48> seed{};
        std::copy_n(block0.begin(), seed.size(), seed.begin());
        rc = PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair_deterministic(
            pk_local.data(), sk_local.data(), seed.data(), seed.size());
        memory_cleanse(seed.data(), seed.size());
        break;
    }
    case SchemeId::MLDSA_44: {
        std::array<uint8_t, 32> seed{};
        std::copy_n(block0.begin(), seed.size(), seed.begin());
        rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_deterministic(
            pk_local.data(), sk_local.data(), seed.data(), seed.size());
        memory_cleanse(seed.data(), seed.size());
        break;
    }
    case SchemeId::MLDSA_65: {
        std::array<uint8_t, 32> seed{};
        std::copy_n(block0.begin(), seed.size(), seed.begin());
        rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_deterministic(
            pk_local.data(), sk_local.data(), seed.data(), seed.size());
        memory_cleanse(seed.data(), seed.size());
        break;
    }
    case SchemeId::MLDSA_87: {
        std::array<uint8_t, 32> seed{};
        std::copy_n(block0.begin(), seed.size(), seed.begin());
        rc = PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair_deterministic(
            pk_local.data(), sk_local.data(), seed.data(), seed.size());
        memory_cleanse(seed.data(), seed.size());
        break;
    }
    default:
        supported_scheme = false;
        break;
    }

    memory_cleanse(block0.data(), block0.size());
    if (!supported_scheme) {
        memory_cleanse(sk_local.data(), sk_local.size());
        return false;
    }
    if (rc != 0) {
        memory_cleanse(sk_local.data(), sk_local.size());
        return false;
    }

    pk_out = std::move(pk_local);
    sk_out = std::move(sk_local);
    return true;
}

bool KeyGenFromSeedBytes(uint32_t pqhd_version,
                         SchemeId scheme_id,
                         std::span<const uint8_t> key_material,
                         std::vector<uint8_t>& pk_out,
                         SecureKeyBytes& sk_out)
{
    pk_out.clear();
    WipeAndResetSecret(sk_out);
    if (key_material.size() != 64) {
        return false;
    }
    return KeyGenFromSeed(pqhd_version,
                          scheme_id,
                          std::span<const uint8_t, 64>(key_material.data(), 64),
                          pk_out,
                          sk_out);
}

bool KeyGenFromLeafMaterial(uint32_t pqhd_version,
                            const pqhd::LeafMaterialV1& leaf_material,
                            std::vector<uint8_t>& pk_out,
                            SecureKeyBytes& sk_out)
{
    return KeyGenFromSeed(pqhd_version,
                          leaf_material.scheme_id,
                          leaf_material.stream_key.Span(),
                          pk_out,
                          sk_out);
}

} // namespace pq
