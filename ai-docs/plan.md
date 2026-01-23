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
- Bellscoin reference repo (AuxPoW + scrypt + retarget): `/home/yaroslav/dev/bellscoin/bels/0.28/bellscoinV3`
- Network parameters are sourced from the old Tidecoin repo.
- Signature libraries are integrated in-tree (PQClean-based).

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
- DONE Select AuxPoW/merged mining reference repo (Bellscoin).
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
- DONE Import scrypt + build wiring (with SSE2 toggle).
- DONE PoW switch: pre‑auxpow yespower, post‑auxpow scrypt.
- DONE Difficulty switch: pre‑auxpow legacy retarget, post‑auxpow DigiShield.
- DONE AuxPow consensus validation + chain‑ID checks (chainid=8).
- DONE AuxPow RPC tooling (`createauxblock`, `submitauxblock`, `getauxblock`).
- DONE Header presync window‑aware retarget check (fixes post‑auxpow headers sync).
- DONE Unit tests for auxpow serialization, PoW switch, and headers sync retarget.
- IN PROGRESS Functional tests for activation/retarget switch.
Deliverable: merged mining supported and tested. (PARTIAL: functional tests pending)

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

### Phase 7: UI/Branding Cleanup (Qt + URI + Units)
Objective: Remove lingering Bitcoin branding (icons, BTC units, bitcoin: URI, splash).
- DONE Audit current Qt resources and strings for Bitcoin/BTC remnants.
- DONE Update units display names (BTC → TDC / tides / photons / tidoshi).
- DONE Switch Qt URI scheme handling to `tidecoin:` (parse/format/paymentserver).
- DONE Map splash/icon alias to `tidecoin_splash` in Qt resources.
- TODO Replace Windows/macOS icons (`bitcoin.ico`/`bitcoin.icns`) and desktop entries.
- TODO Update Qt docs/tests and translations (`src/qt/README.md`, `src/qt/test/uritests.cpp`, `src/qt/locale/*.ts`).
Deliverable: Tidecoin-branded GUI and consistent address/URI display. (PARTIAL)

## Decisions Locked
- AuxPoW chainid: 8 (Tidecoin‑specific).
- Pre‑auxpow PoW: yespower; post‑auxpow PoW: scrypt (auxpow or non‑auxpow).
- PQ HRP: mainnet `q`, testnet `tq`, regtest `rq`.

## Open Decisions
- AuxPoW activation height (per network).

## Risks and Mitigations
- Consensus divergence due to difficulty quirks: preserve Tidecoin-specific logic
  and add consensus tests.
- Signature scheme integration: isolate consensus-critical validation and add
  golden test vectors.
- Merged mining complexity: ensure deterministic AuxPoW parsing and validation.
- PQ-native v1 witness: require test vectors for sighash/opcode correctness.

## Wallet Export/Import Review Needed
We need a focused review of private key import/export surface and wallet RPCs:
- Deprecate `importprivkey`; require `importdescriptors` as the only private‑key import path.
- Add `dumpprivkey <address|descriptor>` (per‑address child key export, **no** master seed export).
- Define PQ‑friendly export format and semantics:
  - Support two WIF encodings (configurable on dump, accepted on import):
    - Legacy WIF (oldtidecoin‑style): prefix + privkey bytes + compression flag + pubkey bytes.
    - Priv‑only WIF (current Tidecoin): prefix + privkey bytes (+ optional compression flag).
  - `dumpprivkey` should allow a `format=` selector (e.g., `legacy` vs `privonly`)
    and default to `privonly` unless a compatibility override is requested.
  - Descriptor import must accept both WIF payload layouts and auto‑detect based on payload length.
    - Legacy WIF detection: payload contains `privkey_bytes || pubkey_bytes`, where
      pubkey bytes start with the scheme prefix and length matches scheme pubkey size.
    - Restrict legacy WIF handling to Falcon‑512 only (reject legacy layout for other schemes).
    - `dumpprivkey format=legacy` allowed only for Falcon‑512; otherwise error.
  - Size/UX: WIF strings are large for PQ keys — audit RPC/Qt limits (HTTP max body size,
    Qt console line length), add tests, and document safe usage (CLI vs Qt).
  - Tests:
    - Legacy WIF (Falcon‑512) imports successfully and derives correct pubkey.
    - Legacy‑layout WIF for non‑Falcon schemes is rejected.
    - Priv‑only WIF import works for all schemes.
  - Input types for `dumpprivkey`: `address` or full `descriptor` (including ranged PQHD).
  - Error semantics:
    - Wallet locked → explicit unlock required.
    - Address not ours / no private key material → error (watch‑only).
    - Descriptor without private keys (public only) → error.
    - PQHD wallet missing seed for the descriptor path → error.
- Wallet tool dump/restore behavior for PQHD vs legacy BDB keys.

### Implementation PR Plan (Wallet import/export)
PR‑W1 — Descriptor‑only private key import (**DONE**)
- Scope:
  - `importprivkey` removed; private key imports go through `importdescriptors`.
- Acceptance:
  - No `importprivkey` RPC available.
  - `importdescriptors` with explicit key works end‑to‑end.

PR‑W2 — `dumpprivkey` per‑address export (**DONE**)
- Scope:
  - Implement `dumpprivkey <address|descriptor>` (child‑key export only).
  - Add `format=` selector (`privonly` default, `legacy` Falcon‑512 only).
- Touchpoints:
  - `src/wallet/rpc/addresses.cpp`
  - `src/wallet/rpc/wallet.cpp`
  - `src/key_io.cpp` (legacy WIF encoding helper)
- Acceptance:
  - `dumpprivkey` rejects watch‑only / missing seed / locked wallet.
  - `format=legacy` allowed only for Falcon‑512.

PR‑W3 — Legacy WIF auto‑detect + import (**DONE**)
- Scope:
  - Detect legacy payload layout (priv||pub) on import.
  - Validate scheme prefix/length; allow only Falcon‑512 legacy.
  - Ignore trailing compression flag on import (do not emit).
- Touchpoints:
  - `src/key_io.cpp`
  - `src/key_io.h`
  - `src/test/key_io_tests.cpp`
- Acceptance:
  - Legacy WIF import works for Falcon‑512; rejected for other schemes.
  - Priv‑only WIF import works for all schemes.
- Completed changes (files):
  - `src/key_io.h`
  - `src/key_io.cpp`
  - `src/wallet/rpc/addresses.cpp`
  - `src/wallet/rpc/wallet.cpp`
  - `src/test/key_io_tests.cpp`

PR‑W4 — Size/UX guardrails (**DONE**)
- Scope:
  - Audit RPC/Qt request limits; document safe usage for large WIFs.
  - Add unit test covering the largest PQ WIF round‑trip.
- Touchpoints:
  - `src/key_io.cpp`
  - `src/test/key_io_tests.cpp`
  - `doc/descriptors.md`
- Acceptance:
  - Documented limits; large WIFs succeed via CLI/RPC where supported.
- Completed changes (files):
  - `src/key_io.cpp`
  - `src/test/key_io_tests.cpp`
  - `doc/descriptors.md`

## Next Inputs Needed
- Confirm final auxpow activation height(s) for main/test/reg.
