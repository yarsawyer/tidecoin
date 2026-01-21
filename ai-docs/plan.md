# Tidecoin Migration Plan (Bitcoin 0.30 Base)

## Goal
Evolve this Bitcoin 0.30-based node to become a Tidecoin-compatible node with
post-quantum signature support and merged mining, while removing taproot and
preserving Tidecoin network compatibility.

## Inputs and References
- Primary repo: `/home/yaroslav/dev/tidecoin/tidecoin`.
- Reference repos:
  - Old Tidecoin (Falcon-512): `/home/yaroslav/dev/tidecoin/oldtidecoin/tidecoin`
  - Unfinished Tidecoin-to-Bitcoin upgrade: `/home/yaroslav/dev/tidecoin/newtidecoin`
- Network parameters will be sourced from the old Tidecoin repo.
- Signature libraries will be upgraded; exact repos will be provided later.
- Merged mining reference repo is deferred for now (not using Bellscoin yet).

## Guiding Constraints
- Maintain sync and consensus with existing Tidecoin network.
- Gate new signature schemes (Falcon-1024, ML-DSA-44/65/87) behind future activation heights.
- Taproot must be removed (not post-quantum secure).
- Add extensive tests for consensus and merged mining behavior.

## Phase Plan

### Phase 0: Baseline and Repository Mapping
- Inventory current codebase (consensus, script, wallet, validation).
- DONE Identify Taproot usage points (script, policy, wallet, tests).
- Locate Falcon-512 implementation in old Tidecoin repo for reference.
- Defer AuxPoW/merged mining repo selection until after Tidecoin compatibility.
- DONE Document key deltas from Bitcoin 0.30 that affect consensus (difficulty quirks).
- DONE Document current vs Tidecoin deltas for chainparams, ports, policy, PoW, and related settings in `ai-docs/phase0-tidecoin-diff.md`.

### Phase 1: Falcon-512 Integration (Tidecoin Sync)
Objective: Make this node validate and sync with Tidecoin network using Falcon-512.
- DONE Wire yespower PoW hashing/validation and Tidecoin difficulty retarget quirks (first retarget rule + overflow guard).
- DONE Integrate Falcon-512 keys/signatures in consensus-critical paths (legacy compat + strict mode).
- DONE Update script and address/key handling to support Falcon-512 PQ pubkeys.
- DONE Add tests to validate Falcon-512 signature verification (unit + wallet/signing flows).
- DONE Ensure compatibility with Tidecoin network parameters (genesis, magic bytes,
  ports, prefixes, checkpoints).
Deliverable: node can sync with Tidecoin network using Falcon-512. (DONE)

### Phase 2: Remove Taproot
Objective: Eliminate taproot code paths and related policies.
- DONE Remove taproot from consensus, policy, wallet, RPC, PSBT, tests, and docs.
- DONE Remove segwit v1+ paths (keep only segwit v0).
- DONE Remove MuSig2 and x-only pubkey helpers.
Deliverable: taproot fully removed from consensus and policy paths.

Progress tracking and detailed checklist live in `ai-docs/taproot-removal.md`.

### Phase 3: HD Wallet Capabilities
Objective: Add PQHD wallet support aligned with Tidecoin needs (descriptor-only, no xpub).
- DONE Implement PQHD KDF + deterministic keygen (pqhd_v1).
- DONE Introduce PQHD seed storage and wallet policy defaults.
- DONE Integrate PQHD descriptors for new wallets (pqhd-only).
- DONE Remove BIP32/xpub/xprv descriptor support; keep WIF for imported privkeys.
- DONE Add PQHD gating + scheme policy (auxpow height gates, per-scheme descriptors).
- DONE Add tests for PQHD keygen, kdf, policy, and descriptor behavior.
- IN PROGRESS Remove remaining secp256k1/ECC and legacy keypaths (see `ai-docs/pqhd-removal-plan.md`).
Deliverable: PQHD descriptor wallet functionality with tests. (PARTIAL: secp teardown ongoing)

### Phase 4: Additional PQ Signatures (Falcon-1024, ML-DSA-44/65/87)
Objective: Add new PQ schemes gated by activation heights.
- DONE Integrate Falcon-1024 and ML-DSA-44/65/87 signatures.
- DONE Define scheme IDs + pubkey prefixes.
- DONE Add activation height logic and consensus/policy gating (auxpow).
- DONE Add tests for pre-activation and post-activation behavior.
Deliverable: new schemes available after activation heights. (DONE)

### Phase 5: Merged Mining (AuxPoW) with Litecoin
Objective: Introduce merged mining and validate with tests.
- Port AuxPoW/merged mining logic from Bellscoin.
- Update consensus and validation for AuxPoW blocks.
- Add extensive functional tests (main chain + auxiliary chain).
Deliverable: merged mining supported and tested.

### Phase 6: PQ-Native v1 Witness (OP_SHA512)
Objective: Introduce OP_SHA512 and v1 64-byte witness program for 256-bit PQ security.
- DONE Plan + sprint split (`ai-docs/op_sha512_plan.md`, `ai-docs/sprints/op_sha512-sprint.md`).
- DONE Introduce uint512 type.
- DONE Implement v1_512 sighash (tagged SHA-512), precomputed hashes.
- DONE Implement OP_SHA512 opcode (repurpose OP_NOP4) gated by auxpow.
- DONE Add v1 script-hash-only output type (P2WSH512).
- DONE Add PQ HRP (mainnet `q`, testnet `tq`, regtest `rq`) and enforce v1 decode rules.
- DONE Policy: reject v1 outputs pre-auxpow in mempool; consensus v1 pre-auxpow remains anyone-can-spend.
- IN PROGRESS Finish remaining tests and cross-PR checklist in `ai-docs/sprints/op_sha512-sprint.md`.
Deliverable: PQ-native v1 witness fully implemented and tested. (PARTIAL)

## Open Decisions
- AuxPoW/merged mining parameters and repo source.

## Risks and Mitigations
- Consensus divergence due to difficulty quirks: preserve Tidecoin-specific logic
  and add consensus tests.
- Signature scheme integration: isolate consensus-critical validation and add
  golden test vectors.
- Merged mining complexity: ensure deterministic AuxPoW parsing and validation.
- PQ-native v1 witness: require test vectors for sighash/opcode correctness.

## Wallet Export/Import Review Needed
We need a focused review of private key import/export surface and wallet RPCs:
- `importprivkey` status and PQ key handling.
- `dumpprivkey` availability/absence and PQ-friendly export format.
- Wallet tool dump/restore behavior for PQHD vs legacy BDB keys.

## Next Inputs Needed
- Paths to old Tidecoin and Bellscoin repositories.
  - Old Tidecoin: `/home/yaroslav/dev/tidecoin/oldtidecoin`
  - Bellscoin: `/home/bellscoin/bels/0.28/bellscoinV3`
