# Tidecoin Migration Plan (Bitcoin 0.30 Base)

## Goal
Evolve this Bitcoin 0.30-based node to become a Tidecoin-compatible node with
post-quantum signature support and merged mining, while removing taproot and
preserving Tidecoin network compatibility.

## Inputs and References
- Primary repo: this `tidecoin` tree.
- Reference repos: old Tidecoin (Falcon-512) and Bellscoin (merged mining).
- Network parameters will be sourced from the old Tidecoin repo.
- Signature libraries will be upgraded; exact repos will be provided later.

## Guiding Constraints
- Maintain sync and consensus with existing Tidecoin network.
- Gate new signature schemes behind future activation heights.
- Taproot must be removed (not post-quantum secure).
- Add extensive tests for consensus and merged mining behavior.

## Phase Plan

### Phase 0: Baseline and Repository Mapping
- Inventory current codebase (consensus, script, wallet, validation).
- Identify Taproot usage points (script, policy, wallet, tests).
- Locate Falcon-512 implementation in old Tidecoin repo for reference.
- Locate AuxPoW/merged mining implementation in Bellscoin repo for reference.
- Document key deltas from Bitcoin 0.30 that affect consensus (difficulty quirks).

### Phase 1: Falcon-512 Integration (Tidecoin Sync)
Objective: Make this node validate and sync with Tidecoin network using Falcon-512.
- Integrate Falcon-512 keys/signatures in consensus-critical paths.
- Update script and address/key handling to support Falcon-512.
- Add or port tests to validate Falcon-512 signature verification.
- Ensure compatibility with Tidecoin network parameters (genesis, magic bytes,
  ports, prefixes, checkpoints).
Deliverable: node can sync with Tidecoin network using Falcon-512.

### Phase 2: Remove Taproot
Objective: Eliminate taproot code paths and related policies.
- Remove taproot script version handling and policy acceptance.
- Update wallet and descriptor handling as needed.
- Remove or adjust tests that assume taproot.
Deliverable: taproot disabled and removed from consensus and policy paths.

#### Taproot Removal Checklist (Detailed)
Scope: remove BIP340/341/342 taproot and tapscript support from consensus, policy,
wallet, RPC, PSBT, tests, and docs. Keep non-taproot Schnorr support only if
explicitly needed later; otherwise remove it together with taproot.

1) Consensus and deployments
- Remove taproot deployment constants and activation settings.
  - Files: `src/consensus/params.h`, `src/kernel/chainparams.cpp`
- Remove any taproot-related softfork reporting.
  - Files: `src/rpc/blockchain.cpp`
- Confirm no chainparams/activation logic still references DEPLOYMENT_TAPROOT.

2) Script and consensus validation
- Remove tapscript script version handling and taproot spending rules.
  - Files: `src/script/interpreter.cpp`, `src/script/interpreter.h`,
    `src/script/script_error.cpp`
- Remove taproot output type and script solver mappings.
  - Files: `src/script/solver.cpp`, `src/script/solver.h`
- Remove taproot sighash caching paths and taproot-specific signature checks.
  - Files: `src/script/sigcache.cpp`, `src/script/sign.cpp`
- Remove taproot tree builder and control block logic.
  - Files: `src/script/interpreter.h`, `src/script/signingprovider.*`

3) Addressing, output types, and key handling
- Remove P2TR output type handling and any Bech32m taproot path.
  - Files: `src/outputtype.cpp`, `src/key_io.cpp`
- Remove x-only pubkey taproot helper paths if unused after taproot removal.
  - Files: `src/key.h`

4) PSBT and transaction signing
- Remove PSBT taproot fields and parsing/serialization support.
  - Files: `src/psbt.h`, `src/psbt.cpp`
- Remove taproot-specific signing logic and flags.
  - Files: `src/script/sign.h`, `src/script/sign.cpp`

5) Wallet and UI
- Remove taproot-enabled wallet checks and descriptors.
  - Files: `src/interfaces/wallet.h`, `src/wallet/interfaces.cpp`,
    `src/qt/receivecoinsdialog.cpp`
- Remove tr() descriptor support if present.
  - Files: `src/rpc/blockchain.cpp`, `doc/descriptors.md`

6) RPC and CLI surface area
- Remove taproot fields from RPC results and help text.
  - Files: `src/rpc/rawtransaction.cpp`
- Remove taproot softfork from getblockchaininfo softfork listing.
  - Files: `src/rpc/blockchain.cpp`

7) Tests, test framework, and data
- Remove taproot functional tests.
  - Files: `test/functional/feature_taproot.py`, `test/functional/wallet_taproot.py`,
    `test/functional/rpc_psbt.py`, `test/functional/rpc_decodescript.py`,
    `test/functional/wallet_migration.py`, `test/functional/wallet_backwards_compatibility.py`,
    `test/functional/wallet_miniscript.py`, `test/functional/test_runner.py`
- Remove taproot helpers from test framework utilities.
  - Files: `test/functional/test_framework/address.py`,
    `test/functional/test_framework/script.py`,
    `test/functional/test_framework/wallet.py`
- Remove taproot unit tests and test vectors.
  - Files: `src/test/script_tests.cpp`, `src/test/script_standard_tests.cpp`,
    `src/test/miniscript_tests.cpp`, `src/test/data/script_tests.json`

8) Benchmarks
- Remove taproot-related benchmarks.
  - Files: `src/bench/sign_transaction.cpp`, `src/bench/connectblock.cpp`

9) secp256k1 schnorr module (optional, decide explicitly)
- If no schnorr use remains, remove schnorr module and tests.
  - Files: `src/secp256k1/src/modules/schnorrsig/*`, `src/secp256k1/src/tests.c`
- If kept, ensure no taproot-only call sites remain.

10) Documentation and release notes
- Remove or update taproot references in docs.
  - Files: `doc/descriptors.md`, `doc/bips.md`, `doc/release-notes/*`

11) Build and config verification
- Ensure no leftover include or linker references to removed taproot code.
- Run unit + functional tests relevant to script, wallet, and RPC after removal.

Progress tracking lives in `ai-docs/taproot-removal.md`.

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
