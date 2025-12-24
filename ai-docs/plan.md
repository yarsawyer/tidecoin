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
- Gate new signature schemes (Falcon-1024, Dilithium 3,5) behind future activation heights.
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
- Integrate Falcon-512 keys/signatures in consensus-critical paths.
- Update script and address/key handling to support Falcon-512.
- Add or port tests to validate Falcon-512 signature verification.
- Ensure compatibility with Tidecoin network parameters (genesis, magic bytes,
  ports, prefixes, checkpoints).
Deliverable: node can sync with Tidecoin network using Falcon-512.

### Phase 2: Remove Taproot
Objective: Eliminate taproot code paths and related policies.
- DONE Remove taproot from consensus, policy, wallet, RPC, PSBT, tests, and docs.
- DONE Remove segwit v1+ paths (keep only segwit v0).
- DONE Remove MuSig2 and x-only pubkey helpers.
Deliverable: taproot fully removed from consensus and policy paths.

Progress tracking and detailed checklist live in `ai-docs/taproot-removal.md`.

### Phase 3: HD Wallet Capabilities
Objective: Add HD wallet support aligned with Tidecoin needs.
- Decide on legacy BIP32/BIP44 vs descriptor wallets.
- Implement key derivation and wallet storage updates.
- Add functional tests for key derivation and address generation.
Deliverable: HD wallet functionality with tests.

### Phase 4: Additional PQ Signatures (Falcon-1024, Dilithium-3/5)
Objective: Add new PQ schemes gated by activation heights.
- Integrate Falcon-1024 and Dilithium-3/5 signatures.
- Define script/versioning or opcodes for new schemes.
- Add activation height logic and consensus gating.
- Add tests for pre-activation and post-activation behavior.
Deliverable: new schemes available after activation heights.

### Phase 5: Merged Mining (AuxPoW) with Litecoin
Objective: Introduce merged mining and validate with tests.
- Port AuxPoW/merged mining logic from Bellscoin.
- Update consensus and validation for AuxPoW blocks.
- Add extensive functional tests (main chain + auxiliary chain).
Deliverable: merged mining supported and tested.

## Open Decisions
- Activation heights for taproot removal and new signature schemes.
- HD wallet mode (legacy vs descriptors).
- Exact PQ library versions and integration approach.

## Risks and Mitigations
- Consensus divergence due to difficulty quirks: preserve Tidecoin-specific logic
  and add consensus tests.
- Signature scheme integration: isolate consensus-critical validation and add
  golden test vectors.
- Merged mining complexity: ensure deterministic AuxPoW parsing and validation.

## Next Inputs Needed
- Paths to old Tidecoin and Bellscoin repositories.
- Tidecoin network parameters file(s).
- PQ library repositories and version constraints.
