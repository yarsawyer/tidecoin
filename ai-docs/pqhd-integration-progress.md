# PQHD Integration Progress

Authoritative spec: `ai-docs/pqhd.md`

This file tracks implementation status by requirement ID (`PQHD-REQ-xxxx`).

Legend:
- Implemented: landed in code and covered by tests (or explicitly verified behavior)
- In Progress: active work in-flight or partially present but incomplete
- Not Started: no implementation yet

---

## Decisions Needed

- PQHD seed lifecycle RPC/Qt surface (create/import/export/default selection) is still open in `ai-docs/pqhd.md` §15, but explicitly deferred (not needed for the next PQHD sprint that focuses on KDF/keygen/CPubKey/DB scaffolding).

---

## Implemented

- PQHD-REQ-0001 — Scheme registry is canonical and stable (`src/pq/pq_scheme.h`, `src/pq/pq_api.h`)
- PQHD-REQ-0004 — SeedID32 is the only seed identifier (`src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`, `src/test/pqhd_kdf_tests.cpp`)
- PQHD-REQ-0019 — PSBT is BIP174 and supports proprietary key/value records (`src/psbt.h`, `src/rpc/rawtransaction.cpp` raw proprietary display)
- PQHD-REQ-0009 — PQHD path constants and semantics are fixed (`src/pq/pqhd_params.h` for purpose/coin_type; hardened-only enforcement in `src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`; vectors in `src/test/pqhd_kdf_tests.cpp`)
- PQHD-REQ-0010 — NodeSecret/ChainCode derivation (hardened-only CKD) (`src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`, `src/test/pqhd_kdf_tests.cpp`)
- PQHD-REQ-0011 — Leaf key material derivation (HKDF-style) (`src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`, `src/test/pqhd_kdf_tests.cpp`)
  - Safety hardening: strict v1 leaf-path validation (shape + hardened-only + scheme must be recognized by build), cleanses secret intermediates, move-only RAII for 64-byte stream keys.
- PQHD-REQ-0012 — Versioned `KeyGenFromSeed` wrappers per scheme (`src/pq/pq_api.h`, `src/pq/pqhd_keygen.cpp`, `src/test/pqhd_keygen_tests.cpp`)
  - Covers Falcon-512/1024 + ML-DSA-44/65/87; deterministic keypair seed length is enforced and negative-tested.
- PQHD-REQ-0013 — Deterministic RNG scoping for keygen (`src/pq/pqhd_keygen.cpp` uses deterministic keypair entrypoints; no global RNG override)
- PQHD-REQ-0023 — PQHD unit tests for determinism + parsing (determinism: `src/test/pqhd_kdf_tests.cpp`, `src/test/pqhd_keygen_tests.cpp`)

---

## In Progress

- PQHD-REQ-0002 — Auxpow-gated scheme activation for output generation (documented; enforcement pending)
- PQHD-REQ-0003 — Wallet policy decides scheme (vs `pq::ActiveScheme()`) (documented; enforcement pending)
- PQHD-REQ-0007 — PQHD seed encryption and lock semantics match Bitcoin (wallet lock semantics exist; PQHD seed semantics pending)

---

## Not Started

### Seed Identity + Storage
- PQHD-REQ-0005 — Seed import de-duplication is by SeedID32 (idempotent)
- PQHD-REQ-0006 — Multi-root wallets: multiple PQHD seeds per wallet
- PQHD-REQ-0008 — Wallet DB schema for PQHD seeds and policy

### Derivation + Keygen
- (none)

### Key Container Refactor
- PQHD-REQ-0014 — `CPubKey` becomes scheme-aware and variable-length
- PQHD-REQ-0015 — Fixed-size `CPubKey::SIZE` assumptions are removed/contained

### Descriptors
- PQHD-REQ-0016 — Descriptor grammar: `pqhd(<SeedID32>)/...` key expression
- PQHD-REQ-0017 — Descriptor restrictions + canonical printing for `pqhd()`
- PQHD-REQ-0018 — Explicit pubkeys in descriptors remain usable for PQ

### PSBT + RPC/Qt Integration
- PQHD-REQ-0020 — Define `tidecoin/PQHD_ORIGIN` proprietary record encoding
- PQHD-REQ-0021 — Wallet + RPC/Qt write/read PQHD origin metadata in PSBT

### Migration + Tests
- PQHD-REQ-0022 — Migration baseline: oldtidecoin wallets are legacy BDB non-HD
- PQHD-REQ-0024 — PQHD functional tests for wallet behavior and gating

---

## PR Slice Status (from `ai-docs/sprints/pqhd-next-sprint.md`)

- PR-1 (PQHD KDF primitives + vectors): implemented (`src/pq/pqhd_kdf.*`, `src/pq/pqhd_params.h`, `src/test/pqhd_kdf_tests.cpp`)
- PR-2 (`KeyGenFromSeed` v1 for all schemes + determinism tests): implemented (`src/pq/pqhd_keygen.cpp`, `src/test/pqhd_keygen_tests.cpp`)
- PR-3 (`CPubKey` variable-length refactor): not started (no `CPubKey` work in PQHD PRs yet)
- PR-4 (wallet DB seed/policy records + auxpow gating semantics): next
