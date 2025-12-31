# PQHD Next Sprint Backlog (NSM integration)

This document turns `ai-docs/pqhd.md` into an implementable, PR-sized sprint backlog.

Hard rules for this sprint plan:
- Planning only here; code changes happen in follow-up PRs.
- Every task maps to spec requirements (`PQHD-REQ-xxxx`) and concrete repo touch-points (paths + symbols).
- High-risk areas are separated: `CPubKey` refactor ≠ wallet DB schema ≠ descriptor parsing ≠ PSBT plumbing.

Primary spec: `ai-docs/pqhd.md`

Progress tracking:
- Implementation status (by `PQHD-REQ-xxxx`) is tracked in `ai-docs/pqhd-integration-progress.md`.
- After landing a PR slice below, update `ai-docs/pqhd-integration-progress.md` and optionally tick the PR “Status” line in §4.

---

## 1) Spec Requirements Index

### PQHD-REQ-0001 — Scheme registry is canonical and stable
- Source: `pqhd.md` §2, §2.1
- Why: scheme prefix decides verifier and pubkey length everywhere (scripts, wallet keys, PSBT keys).

### PQHD-REQ-0002 — Auxpow-gated scheme activation for output generation
- Source: `pqhd.md` §12.3.5, §12.3.6
- Why: wallet must not create outputs the network won’t relay/accept; pre-auxpow outputs must remain Falcon-512-only.

### PQHD-REQ-0003 — Wallet policy decides scheme (not `pq::ActiveScheme()`)
- Source: `pqhd.md` §12.3
- Why: scheme selection is wallet-local and must support per-call overrides + change policy.

### PQHD-REQ-0004 — SeedID32 is the only seed identifier
- Source: `pqhd.md` §8.3
- Why: avoid truncated handles (fingerprints); remove ambiguity/collision concerns entirely.

### PQHD-REQ-0005 — Seed import de-duplication is by SeedID32 (idempotent)
- Source: `pqhd.md` §8.3, §12.5.2A
- Why: importing the same seed twice must be safe; prevent silent DB corruption.

### PQHD-REQ-0006 — Multi-root wallets: multiple PQHD seeds per wallet
- Source: `pqhd.md` §12.4
- Why: parity with Bitcoin wallet reality (multiple roots over time); supports rotation and imported seeds.

### PQHD-REQ-0007 — PQHD seed encryption and lock semantics match Bitcoin
- Source: `pqhd.md` §12.5.2A, §12.5.2C
- Why: locked wallets must not derive/top-up and must not sign; ensure predictable UX and security.

### PQHD-REQ-0008 — Wallet DB schema for PQHD seeds and policy
- Source: `pqhd.md` §12.5.1–§12.5.4
- Why: stable disk format is required before any wallet behavior is built on top.

### PQHD-REQ-0009 — PQHD path constants and semantics are fixed
- Source: `pqhd.md` §6.2–§6.3, §9.2
- Why: restore/discovery depends on frozen purpose/coin_type and hardened-only semantics.

### PQHD-REQ-0010 — NodeSecret/ChainCode derivation (hardened-only CKD)
- Source: `pqhd.md` §7.2–§7.3
- Why: core deterministic derivation primitive for PQHD.

### PQHD-REQ-0011 — Leaf key material derivation (HKDF-style)
- Source: `pqhd.md` §7.4
- Why: separates derivation from per-scheme keygen; avoids “fixed N random bytes” coupling.

### PQHD-REQ-0012 — Versioned `KeyGenFromSeed` wrappers per scheme
- Source: `pqhd.md` §7.5
- Why: restorability across PQClean/Tidecoin upgrades; pin behavior by `pqhd_version`.

### PQHD-REQ-0013 — Deterministic RNG scoping for keygen
- Source: `pqhd.md` §7.5, §17.3
- Why: avoid cross-thread leakage and accidental reuse of deterministic streams outside keygen.

### PQHD-REQ-0014 — `CPubKey` becomes scheme-aware and variable-length
- Source: `pqhd.md` §0.1, §16.2, §17.1
- Why: multi-scheme wallet/descriptor/PSBT requires a pubkey container that can represent all TidePubKey sizes.

### PQHD-REQ-0015 — Fixed-size `CPubKey::SIZE` assumptions are removed/contained
- Source: `pqhd.md` §0.1, §10.1, §16.2
- Why: descriptors/PSBT parsing currently hard-code `CPubKey::SIZE`; must not block multi-scheme.

### PQHD-REQ-0016 — Descriptor grammar: `pqhd(<SeedID32>)/...` key expression
- Source: `pqhd.md` §9.2
- Why: descriptor wallets are the target architecture; `pqhd()` is the key source abstraction.

### PQHD-REQ-0017 — Descriptor restrictions + canonical printing for `pqhd()`
- Source: `pqhd.md` §9.2.1–§9.2.3
- Why: hardened-only enforcement and stable string normalization/checksum.

### PQHD-REQ-0018 — Explicit pubkeys in descriptors remain usable for PQ
- Source: `pqhd.md` §9.1
- Why: watch-only and legacy imports must work with variable-sized TidePubKeys.

### PQHD-REQ-0019 — PSBT stays BIP174; PQHD uses proprietary fields
- Source: `pqhd.md` §10, §10.0–§10.2
- Why: preserve RPC/Qt flows; avoid BIP32 fingerprint semantics and xpubs for PQHD.

### PQHD-REQ-0020 — Define `tidecoin/PQHD_ORIGIN` proprietary record encoding
- Source: `pqhd.md` §10.2
- Why: signers/analysis need SeedID32+path without xpub/fingerprint.

### PQHD-REQ-0021 — Wallet + RPC/Qt write/read PQHD origin metadata in PSBT
- Source: `pqhd.md` §10.3
- Why: enable meaningful PSBT analysis and offline signing workflows.

### PQHD-REQ-0022 — Migration baseline: oldtidecoin wallets are legacy BDB non-HD
- Source: `pqhd.md` §12.1
- Why: migration only needs legacy key imports (no HD seed import required).

### PQHD-REQ-0023 — PQHD unit tests for determinism + parsing
- Source: `pqhd.md` §14, §16.4
- Why: avoid silent breakage; determinism is a contract.

### PQHD-REQ-0024 — PQHD functional tests for wallet behavior and gating
- Source: `pqhd.md` §12.3, §10.3, §16.4
- Why: enforce expected user-facing semantics across RPC flows.

### PQHD-REQ-0025 — Store PQHD origin in `CKeyMetadata` (SeedID32 + hardened path)
- Source: `pqhd.md` §12.5.4
- Why: PSBT origin export and wallet UX require a canonical per-key origin record without relying on BIP32/xpub semantics.

---

## 2) Gap List (Missing / Partially Implemented)

Note: entries marked “(resolved)” are kept as historical context because they drove the PR slicing order.

### GAP-01 (resolved) — `CPubKey` is Falcon-512-only; fixed-size assumptions everywhere
- REQs: PQHD-REQ-0014, PQHD-REQ-0015, PQHD-REQ-0016, PQHD-REQ-0019
- Status: resolved by PR-3 (`CPubKey` variable-length + scheme-aware)
- Evidence:
  - Spec: `pqhd.md` §0.1, §16.2
  - Repo: see `ai-docs/pqhd-integration-progress.md` “Implemented” for PR-3 touch-points/tests
- Impact (historical): multi-scheme wallets/PSBT/descriptor parsing were blocked beyond Falcon-512.

### GAP-02 — No PQHD seed identity rules in storage/RPC
- REQs: PQHD-REQ-0004, PQHD-REQ-0005, PQHD-REQ-0008
- Evidence:
  - Spec: `pqhd.md` §8.1 (“no collision rules”), §12.5
  - Repo: `src/wallet/walletdb.h` uses `CHDChain::seed_id` (`CKeyID` hash160), no SeedID32 records
- Impact: cannot store/import/dedup PQHD seeds; cannot reference a seed from descriptors/PSBT.

### GAP-03 (resolved) — No PQHD derivation primitives implemented (NodeSecret/ChainCode, HKDF)
- REQs: PQHD-REQ-0010, PQHD-REQ-0011, PQHD-REQ-0023
- Status: resolved by PR-1 (PQHD KDF primitives + vectors)
- Evidence:
  - Spec: `pqhd.md` §7.2–§7.4
  - Repo: see `ai-docs/pqhd-integration-progress.md` “Implemented” for PR-1 touch-points/tests
- Impact (historical): deterministic leaf material derivation was missing; PQHD keygen/restore was blocked.

### GAP-04 (resolved) — No versioned `KeyGenFromSeed` contract implemented
- REQs: PQHD-REQ-0012, PQHD-REQ-0013, PQHD-REQ-0023
- Status: resolved by PR-2 (versioned `KeyGenFromSeed` wrappers + determinism tests for all schemes)
- Evidence:
  - Spec: `pqhd.md` §7.5
  - Repo: see `ai-docs/pqhd-integration-progress.md` “Implemented” for PR-2 touch-points/tests
- Impact (historical): restorability across upgrades was not guaranteed; PQHD could not be safely deployed.

### GAP-05 — Descriptor support missing for `pqhd(<SeedID32>)/...` + explicit TidePubKey validation
- REQs: PQHD-REQ-0016, PQHD-REQ-0017, PQHD-REQ-0018
- Evidence:
  - Spec: `pqhd.md` §9.1–§9.2
  - Repo: `src/script/descriptor.cpp` has no `pqhd()` provider; and existing pubkey parsing historically assumes secp-like sizes without scheme-aware length validation.
- Impact: cannot represent PQHD key sources in descriptor wallets; explicit PQ pubkeys (raw hex TidePubKey) may be rejected or mis-validated without TidePubKey length checks.

### GAP-06 — PSBT PQHD origin metadata not implemented
- REQs: PQHD-REQ-0019, PQHD-REQ-0020, PQHD-REQ-0021
- Evidence:
  - Spec: `pqhd.md` §10.2–§10.3
  - Repo: PSBT proprietary mechanism exists (`src/psbt.h` `m_proprietary`), but no Tidecoin PQHD semantics
  - Repo: `src/rpc/rawtransaction.cpp` `decodepsbt` prints raw proprietary entries only
- Impact: PSBTs won’t contain PQHD origins; analysis/offline signing UX degrades.

### GAP-07 — Scheme policy is not wallet-driven; `pq::ActiveScheme()` is hard-coded
- REQs: PQHD-REQ-0002, PQHD-REQ-0003
- Evidence:
  - Spec: `pqhd.md` §12.3
  - Repo: `src/pq/pq_api.h` `pq::ActiveScheme()` returns `kFalcon512Info`
- Impact: cannot manage per-wallet scheme defaults and auxpow gating for address generation/change.

### GAP-08 — Migration tooling not defined in current repo
- REQs: PQHD-REQ-0022
- Evidence:
  - Spec: `pqhd.md` §12.1; oldtidecoin asserts `!IsHDEnabled()` and behaves as legacy BDB non-HD
  - Repo: no explicit import path for oldtidecoin wallet DBs
- Impact: users cannot migrate oldtidecoin wallets into PQHD wallets without a defined workflow/tool.

---

## 3) Sprint Backlog (PR-sized tasks, prioritized)

This sprint is ordered by dependency: determinism primitives → determinism keygen (all schemes) → key container refactor (unblocks everything else) → wallet persistence/policy → descriptors → PSBT → migration notes.

Task status legend:
- `[x]` done (landed + verified)
- `[ ]` not started
- `[~]` in progress (partially landed)

### [x] Task 1 — Implement PQHD derivation primitives + vectors (KDF-only, no wallet integration)
- Problem: PQHD needs hardened-only derivation and leaf material derivation before any wallet feature can exist.
- Requirements: PQHD-REQ-0004, PQHD-REQ-0009, PQHD-REQ-0010, PQHD-REQ-0011, PQHD-REQ-0023
- Touch-points:
  - `src/crypto/hmac_sha512.h` (`CHMAC_SHA512`)
  - `src/hash.h`, `src/hash.cpp` (existing HMAC helpers; reuse where appropriate)
  - New module (proposed): `src/wallet/pqhd_kdf.{h,cpp}` (or `src/pq/pqhd_kdf.{h,cpp}` if you prefer PQ grouping)
  - Tests: `src/test/pqhd_kdf_tests.cpp` (new)
- Implementation outline:
  - Implement `SeedID32(master_seed)` per `pqhd.md`.
  - Implement master node generation and CKD for NodeSecret/ChainCode (hardened-only).
  - Implement leaf material derivation with domain separation (scheme id + full hardened path).
  - Add deterministic KDF test vectors (KDF-level only; no PQClean outputs).
- Acceptance criteria:
  - Unit tests validate KDF outputs for fixed vectors (master, a leaf, and at least one different scheme/path).
  - API surface is stable and documented in headers.
- Tests required:
  - Unit: `pqhd_kdf_tests.cpp`.
- Rollout/safety:
  - No behavior changes; library-only.
- Size: M.

### [x] Task 2 — Implement `KeyGenFromSeed` v1 for all PQ signature schemes (pinned by `pqhd_version`)
- Problem: wallet restore must be stable across Tidecoin/PQClean upgrades and must cover all supported schemes (not just Falcon-512).
- Requirements: PQHD-REQ-0012, PQHD-REQ-0013, PQHD-REQ-0023
- Touch-points:
  - `src/pq/pq_api.h` (public `KeyGenFromSeed` entry point + versioning)
  - `src/pq/` (versioned implementation files, e.g. `src/pq/keygen_v1.cpp` + per-scheme helpers)
  - PQClean scheme code (called via wrapper only):
    - `src/pq/falcon-512/*`
    - `src/pq/falcon-1024/*`
    - `src/pq/ml-dsa-44/*`
    - `src/pq/ml-dsa-65/*`
    - `src/pq/ml-dsa-87/*`
  - Tests: `src/test/pqhd_keygen_tests.cpp` (new)
- Implementation outline:
  - Define `KeyGenFromSeed(pqhd_version, scheme_id, leaf_key_material) -> (sk, pk)` and lock the v1 behavior.
  - Implement v1 wrappers for:
    - Falcon-512 / Falcon-1024
    - ML-DSA-44 / ML-DSA-65 / ML-DSA-87
  - Scope a deterministic RNG stream inside the wrapper (thread-local/RAII) so determinism does not depend on PQClean’s internal randomness usage patterns.
  - Add determinism tests:
    - same (version, scheme, leaf_material) yields the same pk,
    - store only a hash-of-sk in tests to avoid leaking secrets in logs/artifacts.
- Acceptance criteria:
  - Determinism vectors exist per scheme for v1.
  - Wrong sizes/scheme mismatch return errors (negative tests).
- Tests required:
  - Unit: `pqhd_keygen_tests.cpp`.
- Rollout/safety:
  - No wallet behavior changes; used later by PQHD keypool/descriptor integration.
- Size: L.

### [x] Task 3 — Refactor `CPubKey` to be scheme-aware and variable-length (and remove fixed-size assumptions)
- Problem: multi-scheme wallet + descriptors + PSBT cannot work while `CPubKey` is Falcon-512-only and `CPubKey::SIZE` is assumed across subsystems.
- Requirements: PQHD-REQ-0014, PQHD-REQ-0015
- Touch-points (blast radius):
  - Core key container:
    - `src/pubkey.h`, `src/pubkey.cpp` (`CPubKey`, `GetLen()`, current `SIZE`, ordering/serialization)
  - Descriptor parsing:
    - `src/script/descriptor.cpp` (pubkey parsing and validation)
  - PSBT parsing:
    - `src/psbt.h`, `src/psbt.cpp` (key size checks; maps keyed by `CPubKey`)
  - Wallet DB descriptor key storage:
    - `src/wallet/walletdb.h` (`DBKeys::WALLETDESCRIPTORKEY`, `DBKeys::WALLETDESCRIPTORCKEY`)
  - Tests that assume fixed sizes:
    - `src/test/*` (descriptor/psbt/key_io tests as they surface)
- Implementation outline:
  - Inventory all `CPubKey::SIZE` uses and classify (consensus/script vs wallet-only vs tests).
  - Refactor `CPubKey` representation to store variable-length TidePubKey bytes while preserving:
    - stable ordering (map keys),
    - stable serialization (walletdb/psbt where applicable),
    - fast access to prefix and raw bytes.
  - Replace fixed-size checks with “parse + validate scheme-specific sizes” using `src/pq/pq_scheme.h`.
  - Keep legacy Falcon-512 encoding unchanged (prefix `0x07` + 897 bytes) to preserve chain compatibility.
- Acceptance criteria:
  - Codebase compiles with variable-length `CPubKey` and accepts the 5 current schemes as valid pubkey sizes.
  - No remaining hard dependency on `CPubKey::SIZE` in descriptor/PSBT parsing.
- Tests required:
  - Unit: `./build/bin/test_tidecoin -t pq_pubkey_container_tests`
  - Unit: `./build/bin/test_tidecoin -t psbt_pq_keypaths_tests`
  - Build: `cmake --build build -j12 --target test_bitcoin`
- Rollout/safety:
  - Isolate as its own PR; do not include wallet DB schema or descriptor feature work here.
- Size: L.

### [x] Task 4 — Add PQHD wallet DB seed/policy records + scheme gating policy (Falcon-512-only pre-auxpow)
- Problem: PQHD needs persistable encrypted seed material (SeedID32) and a wallet-local scheme policy; wallet must not create outputs for schemes that are not activated yet.
- Requirements: PQHD-REQ-0002, PQHD-REQ-0003, PQHD-REQ-0004, PQHD-REQ-0005, PQHD-REQ-0006, PQHD-REQ-0007, PQHD-REQ-0008, PQHD-REQ-0024, PQHD-REQ-0025
- Touch-points:
  - Wallet DB:
    - `src/wallet/walletdb.h`, `src/wallet/walletdb.cpp` (new DB keys + record structs)
    - `src/wallet/walletdb.h` (`CKeyMetadata` PQHD origin fields + serialization)
  - Wallet feature flags/versioning:
    - `src/wallet/walletutil.h`, `src/wallet/wallet.h`
  - Wallet policy + enforcement hooks:
    - `src/wallet/wallet.h`, `src/wallet/wallet.cpp` (policy storage + accessors)
    - `src/wallet/scriptpubkeyman.*` (where keypool/top-up and new destination selection will consult policy once PQHD is wired)
    - `src/pq/pq_api.h` (`pq::ActiveScheme()` call sites that must become wallet-driven)
  - Consensus activation height:
    - `src/kernel/chainparams.cpp`, `src/consensus/params.h` (`nAuxpowStartHeight`)
- Implementation outline:
  - Add encrypted seed records keyed by SeedID32 (no short aliases).
  - Add policy record fields:
    - default seed (SeedID32),
    - default receive scheme id,
    - default change scheme id,
    - optional per-scheme seed override mapping (multi-root support).
  - Enforce idempotent seed import (SeedID32 de-dup).
  - Extend `CKeyMetadata` to carry PQHD origin:
    - `SeedID32` (32 bytes) + full hardened path (`vector<uint32_t>`)
    - version-gated serialization upgrade (Bitcoin walletdb patterns)
  - Add an internal policy predicate:
    - pre-auxpow: only Falcon-512 is allowed for new outputs/change,
    - post-auxpow: other schemes allowed.
  - Keep seed lifecycle RPC/Qt UX deferred; this task is storage + policy semantics only.
- Acceptance criteria:
  - Wallet DB round-trips PQHD seed/policy records.
  - Wallet policy load clamps default schemes to Falcon-512 pre-auxpow (enforcement at output-generation sites remains a follow-up requirement).
  - Existing wallets are unaffected unless PQHD wallet flag is enabled.
- Tests required:
  - Unit: walletdb serialization tests for PQHD seed/policy.
  - (Optional follow-up) Unit: policy gating tests for a few heights and schemes.
- Rollout/safety:
  - Feature-flagged via wallet flag; default behavior remains Falcon-512.
- Size: M.

### [x] Task 5 — Add descriptor parsing + canonical printing for `pqhd(<SeedID32>)/...` and validate explicit TidePubKey hex keys (parsing-only)
- Problem: descriptor wallets are the target architecture; we need a PQHD key source (`pqhd()`) and we must ensure explicit PQ pubkeys (raw hex TidePubKey) are accepted and validated correctly.
- Requirements: PQHD-REQ-0016, PQHD-REQ-0017, PQHD-REQ-0018
- Touch-points:
  - `src/script/descriptor.cpp`:
    - `ParsePubkeyInner(...)`, `ParseKeyPath(...)`, `PubkeyProvider` subclasses
  - `src/script/descriptor.h` (descriptor interfaces for normalized/private strings)
- Tests: `src/test/descriptor_tests.cpp`
- Implementation outline:
  - Explicit pubkeys stay raw hex:
    - accept variable-length TidePubKey bytes (prefix + scheme pubkey),
    - validate scheme id and pubkey length via `src/pq/pq_scheme.h`,
    - remove any implicit 33/65-byte secp pubkey assumptions for these keys.
  - Add `pqhd(<SeedID32>)/...` key expression with strict restrictions:
    - SeedID32 only (exactly 32 bytes hex),
    - hardened-only path elements, `*h` only, no multipath,
    - scheme element present in the path at the required position.
  - Canonical printing rules:
    - always print `h` markers and print the SeedID32 in full.
- Acceptance criteria:
  - Descriptor round-trips parse → canonical string (stable).
  - Negative tests reject non-hardened steps, multipath, invalid SeedID length, and missing scheme element.
- Tests required:
  - Unit: `descriptor_tests` additions.
- Rollout/safety:
  - Parsing-only; no wallet derivation integration in this sprint.
- Size: M.

### [ ] Task 6 — Implement PSBT `tidecoin/PQHD_ORIGIN` proprietary records (inputs + outputs) + RPC/Qt parsed view
- Problem: Tidecoin needs PQHD origin metadata in PSBT without BIP32/xpubs; we also need `decodepsbt` / Qt to display it cleanly.
- Requirements: PQHD-REQ-0019, PQHD-REQ-0020, PQHD-REQ-0021
- Touch-points:
  - PSBT core:
    - `src/psbt.h`, `src/psbt.cpp` (proprietary record parse/serialize; typed helpers)
  - Wallet PSBT fill paths:
    - `src/wallet/wallet.cpp` (`CWallet::FillPSBT`)
    - `src/wallet/scriptpubkeyman.cpp` (`DescriptorScriptPubKeyMan::FillPSBT`)
    - `src/wallet/rpc/spend.cpp` (`walletprocesspsbt`)
  - RPC/Qt display:
    - `src/rpc/rawtransaction.cpp` (`decodepsbt`)
    - `src/qt/psbtoperationsdialog.*` (if it shows origin data)
  - Tests:
    - `src/test/psbt_tests.cpp` (or add one)
- Implementation outline:
  - Freeze encoding helper:
    - proprietary identifier: `tidecoin`
    - subtype: `0x01` (PQHD_ORIGIN)
    - keydata: TidePubKey bytes (variable length)
    - value: `SeedID32 || CompactSize(path_len) || path elements (u32 little-endian)`
  - Write rules:
    - Inputs: annotate any pubkey the wallet recognizes in the spend path.
    - Outputs: “Bitcoin way”:
      - annotate wallet-owned outputs where origin is known (including change, and also wallet-owned multisig outputs where applicable),
      - never annotate outputs that are *not* wallet-owned (do not leak internal origin metadata to recipients).
  - Display rules:
    - `decodepsbt` adds a parsed view for PQHD_ORIGIN while keeping the raw proprietary list unchanged.
- Acceptance criteria:
  - PSBT round-trips preserve proprietary entries.
  - `decodepsbt` produces a stable JSON representation of PQHD origins when present.
- Tests required:
  - Unit: PSBT encode/decode with PQHD origin record, with expected JSON.
- Rollout/safety:
  - No consensus impact; only PSBT metadata.
- Size: M.

### [ ] Task 7 — Document oldtidecoin legacy wallet migration mapping (no code yet)
- Problem: oldtidecoin wallets are legacy (BDB) and non-HD; migration is “import legacy entries”, not “import HD seeds”.
- Requirements: PQHD-REQ-0022
- Touch-points (reference analysis):
  - oldtidecoin: `/home/yaroslav/dev/tidecoin/oldtidecoin/tidecoin/src/wallet/wallet.cpp` (HD effectively disabled)
  - current repo: `src/wallet/walletdb.h` legacy key records (`WriteKey`, `CKeyMetadata`)
- Implementation outline:
  - Enumerate legacy records required for migration (private keys + metadata + labels as needed).
  - Define minimum viable workflow (likely: old wallet `dumpwallet` → new wallet `importwallet`/`importprivkey` equivalent).
  - Identify what can reuse existing RPCs vs new helper RPC (defer coding to later sprint).
- Acceptance criteria:
  - A concise migration note doc exists under `ai-docs/` and is linked from `pqhd.md`.
- Tests required: none (doc-only).
- Rollout/safety: n/a.
- Size: S.

### Deferred (explicitly out of this sprint)
- Seed lifecycle RPC/Qt surface (create/import/export/default selection UX): design/implement once KDF/keygen/CPubKey/DB scaffolding exists.
- Bounded-export watch-only workflows: implement after PQHD keypool + descriptor integration is working.
- Full PQHD keypool derivation/top-up and “descriptor-backed solvability”: depends on tasks above and is too large for this sprint.

---

## 4) PR Breakdown Plan (3–6 slices)

### PR-1: PQHD KDF primitives + vectors
- Status: [x] implemented (see `ai-docs/pqhd-integration-progress.md`)
- Tasks: Task 1
- Tests: new PQHD KDF unit tests
- Docs: update `ai-docs/pqhd-integration-progress.md` statuses

### PR-2: `KeyGenFromSeed` v1 (all schemes) + determinism tests
- Status: [x] implemented (see `ai-docs/pqhd-integration-progress.md`)
- Tasks: Task 2
- Tests: new PQHD keygen unit tests; run `test_tidecoin` subset locally
- Docs: note `pqhd_version` pinning in progress tracker

### PR-3: `CPubKey` variable-length refactor (scheme-aware)
- Status: [x] implemented (see `ai-docs/pqhd-integration-progress.md`)
- Tasks: Task 3
- Tests: `./build/bin/test_tidecoin -t pq_pubkey_container_tests` and `./build/bin/test_tidecoin -t psbt_pq_keypaths_tests` (plus a full build)
- Docs: progress tracker updates

### PR-4: Wallet DB PQHD seed/policy records + auxpow scheme gating semantics
- Status: [x] implemented (see `ai-docs/pqhd-integration-progress.md`)
- Tasks: Task 4
- Tests: walletdb unit tests (policy gating tests optional follow-up)
- Docs: progress tracker updates

### PR-5: Descriptor parsing: `pqhd(<SeedID32>)/...` + explicit TidePubKey (raw hex) validation + canonical printing
- Status: [x] implemented (see `ai-docs/pqhd-integration-progress.md`)
- Tasks: Task 5
- Tests: `./build/bin/test_tidecoin -t descriptor_tests`
- Docs: progress tracker updates

### PR-6: PSBT PQHD_ORIGIN (inputs + outputs) + parsed RPC display
- Status: [x] done
- Tasks: Task 6
- Tests: PSBT unit tests; `decodepsbt` unit tests if applicable
- Docs: progress tracker updates

Doc-only: Task 7 can land anytime.

---

## 5) Risks & Mitigations (Sprint scope)

- `CPubKey` blast radius: isolate in PR-3; keep changes mechanical; add targeted unit tests for variable-length keys.
- Determinism contract mistakes: lock v1 outputs with unit tests (PR-1/PR-2) and keep `pqhd_version` explicit.
- Policy/consensus mismatches: enforce “Falcon-512 only pre-auxpow” at wallet policy layer (PR-4) with gating tests.
- Descriptor parsing pitfalls: strict grammar + canonical printing tests (PR-5).
- PSBT interoperability confusion: keep BIP174 framing; use proprietary fields only; preserve unknown records unchanged (PR-6).
