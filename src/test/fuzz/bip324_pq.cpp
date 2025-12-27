// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip324_pq.h>
#include <chainparams.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

namespace {

void Initialize()
{
    SelectParams(ChainType::MAIN);
}

}  // namespace

FUZZ_TARGET(bip324_pq_cipher_roundtrip, .init=Initialize)
{
    // Test that BIP324PQCipher's encryption and decryption agree.

    FuzzedDataProvider provider(buffer.data(), buffer.size());
    std::array<std::byte, 32> shared_secret{};
    const auto secret_bytes = provider.ConsumeBytes<std::byte>(shared_secret.size());
    std::copy(secret_bytes.begin(), secret_bytes.end(), shared_secret.begin());

    BIP324PQCipher initiator;
    BIP324PQCipher responder;
    initiator.InitializeFromSharedSecret(shared_secret, true);
    responder.InitializeFromSharedSecret(shared_secret, false);

    // Initialize RNG deterministically, to generate contents and AAD.
    InsecureRandomContext rng(provider.ConsumeIntegral<uint64_t>());

    // Compare session IDs and garbage terminators.
    assert(std::ranges::equal(initiator.GetSessionID(), responder.GetSessionID()));
    assert(std::ranges::equal(initiator.GetSendGarbageTerminator(), responder.GetReceiveGarbageTerminator()));
    assert(std::ranges::equal(initiator.GetReceiveGarbageTerminator(), responder.GetSendGarbageTerminator()));

    LIMITED_WHILE(provider.remaining_bytes(), 1000) {
        // Mode:
        // - Bit 0: whether the ignore bit is set in message
        // - Bit 1: whether the responder (0) or initiator (1) sends
        // - Bit 2: whether this ciphertext will be corrupted (making it the last sent one)
        // - Bit 3-4: controls the maximum aad length (max 4095 bytes)
        // - Bit 5-7: controls the maximum content length (max 16383 bytes, for performance reasons)
        unsigned mode = provider.ConsumeIntegral<uint8_t>();
        bool ignore = mode & 1;
        bool from_init = mode & 2;
        bool damage = mode & 4;
        unsigned aad_length_bits = 4 * ((mode >> 3) & 3);
        unsigned aad_length = provider.ConsumeIntegralInRange<unsigned>(0, (1 << aad_length_bits) - 1);
        unsigned length_bits = 2 * ((mode >> 5) & 7);
        unsigned length = provider.ConsumeIntegralInRange<unsigned>(0, (1 << length_bits) - 1);
        // Generate aad and content.
        auto aad = rng.randbytes<std::byte>(aad_length);
        auto contents = rng.randbytes<std::byte>(length);

        // Pick sides.
        auto& sender{from_init ? initiator : responder};
        auto& receiver{from_init ? responder : initiator};

        // Encrypt
        std::vector<std::byte> ciphertext(length + initiator.EXPANSION);
        sender.Encrypt(contents, aad, ignore, ciphertext);

        // Optionally damage 1 bit in either the ciphertext or the aad.
        if (damage) {
            unsigned damage_bit = provider.ConsumeIntegralInRange<unsigned>(0,
                (ciphertext.size() + aad.size()) * 8U - 1U);
            unsigned damage_pos = damage_bit >> 3;
            std::byte damage_val{(uint8_t)(1U << (damage_bit & 7))};
            if (damage_pos >= ciphertext.size()) {
                aad[damage_pos - ciphertext.size()] ^= damage_val;
            } else {
                ciphertext[damage_pos] ^= damage_val;
            }
        }

        // Decrypt length
        uint32_t dec_length = receiver.DecryptLength(std::span{ciphertext}.first(initiator.LENGTH_LEN));
        if (!damage) {
            assert(dec_length == length);
        } else {
            if (dec_length > 16384 + length) break;
            ciphertext.resize(dec_length + initiator.EXPANSION);
        }

        // Decrypt
        std::vector<std::byte> decrypt(dec_length);
        bool dec_ignore{false};
        bool ok = receiver.Decrypt(std::span{ciphertext}.subspan(initiator.LENGTH_LEN), aad, dec_ignore, decrypt);
        assert(!ok == damage);
        if (!ok) break;
        assert(ignore == dec_ignore);
        assert(decrypt == contents);
    }
}
