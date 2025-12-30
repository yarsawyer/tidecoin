#ifndef TIDECOIN_PQ_PQHD_KDF_H
#define TIDECOIN_PQ_PQHD_KDF_H

#include <array>
#include <cstdint>
#include <span>

/**
 * PQHD KDF primitives (PQHD v1).
 *
 * These are deterministic derivation helpers used to build PQHD (hardened-only)
 * wallets. This module intentionally does not depend on wallet storage or RPC
 * code. It only implements cryptographic derivation primitives and testable
 * vectors described in `ai-docs/pqhd.md`.
 */
namespace pqhd {

using SeedID32 = std::array<uint8_t, 32>;
using NodeSecret = std::array<uint8_t, 32>;
using ChainCode = std::array<uint8_t, 32>;
using KeygenStreamKey64 = std::array<uint8_t, 64>;
using KeygenStreamBlock64 = std::array<uint8_t, 64>;

struct Node {
    NodeSecret node_secret;
    ChainCode chain_code;
};

/** Compute SeedID32 = SHA256("Tidecoin PQHD seedid v1" || master_seed). */
SeedID32 ComputeSeedID32(std::span<const uint8_t, 32> master_seed);

/** Compute PQHD master node (NodeSecret/ChainCode) from master seed. */
Node MakeMasterNode(std::span<const uint8_t, 32> master_seed);

/** Hardened-only child derivation (CKD). `index_hardened` must have bit 31 set. */
Node DeriveChild(const Node& parent, uint32_t index_hardened);

/** Convenience: derive a node by iterating hardened CKD along `path_hardened`. */
Node DerivePath(const Node& master, std::span<const uint32_t> path_hardened);

/**
 * Derive the PQHD v1 64-byte stream key used as internal keygen material.
 *
 * `path_hardened` must be the full hardened path for the leaf (including the
 * scheme element). `scheme_id` is provided explicitly to domain-separate
 * material per scheme.
 */
KeygenStreamKey64 DeriveKeygenStreamKey(std::span<const uint8_t, 32> node_secret_leaf,
                                        uint8_t scheme_id,
                                        std::span<const uint32_t> path_hardened);

/** Derive the PQHD v1 stream block for `ctr` (0,1,2,...) from a stream key. */
KeygenStreamBlock64 DeriveKeygenStreamBlock(std::span<const uint8_t, 64> stream_key, uint32_t ctr);

} // namespace pqhd

#endif // TIDECOIN_PQ_PQHD_KDF_H
