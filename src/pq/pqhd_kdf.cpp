#include <pq/pqhd_kdf.h>

#include <crypto/common.h>
#include <crypto/hmac_sha512.h>
#include <crypto/sha256.h>

#include <algorithm>
#include <cstring>
#include <vector>

namespace pqhd {
namespace {

constexpr const char* PQHD_MASTER_KEY = "Tidecoin PQHD seed";
constexpr const char* PQHD_HKDF_SALT = "Tidecoin PQHD hkdf v1";
constexpr const char* PQHD_STREAM_INFO = "Tidecoin PQHD stream key v1";
constexpr const char* PQHD_RNG_PREFIX = "Tidecoin PQHD rng v1";
constexpr const char* PQHD_SEEDID_TAG = "Tidecoin PQHD seedid v1";

std::array<uint8_t, 64> HmacSha512(std::span<const uint8_t> key, std::span<const uint8_t> msg)
{
    std::array<uint8_t, 64> out{};
    CHMAC_SHA512(key.data(), key.size()).Write(msg.data(), msg.size()).Finalize(out.data());
    return out;
}

std::array<uint8_t, 32> Sha256(std::span<const uint8_t> msg)
{
    std::array<uint8_t, 32> out{};
    CSHA256().Write(msg.data(), msg.size()).Finalize(out.data());
    return out;
}

std::array<uint8_t, 4> Ser32BE(uint32_t v)
{
    std::array<uint8_t, 4> out{};
    WriteBE32(out.data(), v);
    return out;
}

KeygenStreamKey64 HKDFExpandSha512(std::span<const uint8_t, 64> prk,
                                  std::span<const uint8_t> info,
                                  size_t out_len)
{
    // RFC5869 HKDF-Expand(PRK, info, L). Here we only need L <= 64.
    // T(0) = empty string
    // T(1) = HMAC(PRK, T(0) || info || 0x01)
    if (out_len > KeygenStreamKey64{}.size()) return KeygenStreamKey64{};

    std::vector<uint8_t> msg;
    msg.reserve(info.size() + 1);
    msg.insert(msg.end(), info.begin(), info.end());
    msg.push_back(0x01);

    const auto t1 = HmacSha512(prk, msg);
    KeygenStreamKey64 out{};
    std::copy_n(t1.begin(), out_len, out.begin());
    return out;
}

} // namespace

SeedID32 ComputeSeedID32(std::span<const uint8_t, 32> master_seed)
{
    std::vector<uint8_t> msg;
    msg.reserve(std::strlen(PQHD_SEEDID_TAG) + master_seed.size());
    msg.insert(msg.end(), PQHD_SEEDID_TAG, PQHD_SEEDID_TAG + std::strlen(PQHD_SEEDID_TAG));
    msg.insert(msg.end(), master_seed.begin(), master_seed.end());
    return Sha256(msg);
}

Node MakeMasterNode(std::span<const uint8_t, 32> master_seed)
{
    const std::span<const uint8_t> key{reinterpret_cast<const uint8_t*>(PQHD_MASTER_KEY),
                                       std::strlen(PQHD_MASTER_KEY)};
    const auto I = HmacSha512(key, master_seed);

    Node out{};
    std::copy_n(I.begin(), 32, out.node_secret.begin());
    std::copy_n(I.begin() + 32, 32, out.chain_code.begin());
    return out;
}

Node DeriveChild(const Node& parent, uint32_t index_hardened)
{
    // PQHD v1 is hardened-only.
    if ((index_hardened & 0x80000000U) == 0) return {};

    std::vector<uint8_t> data;
    data.reserve(1 + parent.node_secret.size() + 4);
    data.push_back(0x00);
    data.insert(data.end(), parent.node_secret.begin(), parent.node_secret.end());
    const auto ser = Ser32BE(index_hardened);
    data.insert(data.end(), ser.begin(), ser.end());

    const auto I = HmacSha512(parent.chain_code, data);

    Node out{};
    std::copy_n(I.begin(), 32, out.node_secret.begin());
    std::copy_n(I.begin() + 32, 32, out.chain_code.begin());
    return out;
}

Node DerivePath(const Node& master, std::span<const uint32_t> path_hardened)
{
    Node node = master;
    for (const uint32_t i : path_hardened) {
        node = DeriveChild(node, i);
    }
    return node;
}

KeygenStreamKey64 DeriveKeygenStreamKey(std::span<const uint8_t, 32> node_secret_leaf,
                                        uint8_t scheme_id,
                                        std::span<const uint32_t> path_hardened)
{
    const std::span<const uint8_t> salt{reinterpret_cast<const uint8_t*>(PQHD_HKDF_SALT),
                                        std::strlen(PQHD_HKDF_SALT)};
    const auto prk_full = HmacSha512(salt, node_secret_leaf);

    // info = PQHD_STREAM_INFO || ser32be(scheme_id) || concat(ser32be(path_elem_i))
    std::vector<uint8_t> info;
    info.reserve(std::strlen(PQHD_STREAM_INFO) + 4 + path_hardened.size() * 4);
    info.insert(info.end(), PQHD_STREAM_INFO, PQHD_STREAM_INFO + std::strlen(PQHD_STREAM_INFO));
    const auto ser_scheme = Ser32BE(scheme_id);
    info.insert(info.end(), ser_scheme.begin(), ser_scheme.end());
    for (const uint32_t elem : path_hardened) {
        const auto ser = Ser32BE(elem);
        info.insert(info.end(), ser.begin(), ser.end());
    }

    return HKDFExpandSha512(std::span<const uint8_t, 64>(prk_full.data(), prk_full.size()), info, 64);
}

KeygenStreamBlock64 DeriveKeygenStreamBlock(std::span<const uint8_t, 64> stream_key, uint32_t ctr)
{
    std::vector<uint8_t> msg;
    msg.reserve(std::strlen(PQHD_RNG_PREFIX) + 4);
    msg.insert(msg.end(), PQHD_RNG_PREFIX, PQHD_RNG_PREFIX + std::strlen(PQHD_RNG_PREFIX));
    const auto ser = Ser32BE(ctr);
    msg.insert(msg.end(), ser.begin(), ser.end());

    const auto block = HmacSha512(stream_key, msg);
    KeygenStreamBlock64 out{};
    std::copy(block.begin(), block.end(), out.begin());
    return out;
}

} // namespace pqhd
