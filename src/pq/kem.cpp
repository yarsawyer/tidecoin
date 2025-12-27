#include <pq/pq_api.h>

#include <support/cleanse.h>

namespace pq {

MLKEM512Keypair::~MLKEM512Keypair()
{
    memory_cleanse(m_pk.data(), m_pk.size());
    memory_cleanse(m_sk.data(), m_sk.size());
}

bool MLKEM512Keypair::Generate()
{
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(m_pk.data(), m_sk.data()) != 0) {
        return false;
    }
    m_initialized = true;
    return true;
}

bool MLKEM512Keypair::GenerateDeterministic(std::span<const uint8_t> coins)
{
    if (coins.size() != MLKEM512_KEYPAIR_COINS_BYTES) {
        return false;
    }
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(m_pk.data(), m_sk.data(), coins.data()) != 0) {
        return false;
    }
    m_initialized = true;
    return true;
}

bool MLKEM512Keypair::Set(std::span<const uint8_t> pk, std::span<const uint8_t> sk)
{
    if (pk.size() != m_pk.size() || sk.size() != m_sk.size()) {
        return false;
    }
    std::copy(pk.begin(), pk.end(), m_pk.begin());
    std::copy(sk.begin(), sk.end(), m_sk.begin());
    m_initialized = true;
    return true;
}

bool MLKEM512Encaps(std::span<const uint8_t> pk,
                    std::span<uint8_t> ct,
                    std::span<uint8_t> ss)
{
    if (pk.size() != MLKEM512_PUBLICKEY_BYTES ||
        ct.size() != MLKEM512_CIPHERTEXT_BYTES ||
        ss.size() != MLKEM512_SHARED_SECRET_BYTES) {
        return false;
    }
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct.data(), ss.data(), pk.data()) == 0;
}

bool MLKEM512EncapsDeterministic(std::span<const uint8_t> pk,
                                 std::span<const uint8_t> coins,
                                 std::span<uint8_t> ct,
                                 std::span<uint8_t> ss)
{
    if (pk.size() != MLKEM512_PUBLICKEY_BYTES ||
        coins.size() != MLKEM512_SHARED_SECRET_BYTES ||
        ct.size() != MLKEM512_CIPHERTEXT_BYTES ||
        ss.size() != MLKEM512_SHARED_SECRET_BYTES) {
        return false;
    }
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(ct.data(), ss.data(), pk.data(), coins.data()) == 0;
}

bool MLKEM512Decaps(std::span<const uint8_t> ct,
                    std::span<const uint8_t> sk,
                    std::span<uint8_t> ss)
{
    if (ct.size() != MLKEM512_CIPHERTEXT_BYTES ||
        sk.size() != MLKEM512_SECRETKEY_BYTES ||
        ss.size() != MLKEM512_SHARED_SECRET_BYTES) {
        return false;
    }
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss.data(), ct.data(), sk.data()) == 0;
}

} // namespace pq
