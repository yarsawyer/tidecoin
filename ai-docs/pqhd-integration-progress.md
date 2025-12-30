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
- PQHD-REQ-0019 — PSBT is BIP174 and supports proprietary key/value records (`src/psbt.h`, `src/rpc/rawtransaction.cpp` raw proprietary display)

---

## In Progress

- PQHD-REQ-0002 — Auxpow-gated scheme activation for output generation (documented; enforcement pending)
- PQHD-REQ-0003 — Wallet policy decides scheme (vs `pq::ActiveScheme()`) (documented; enforcement pending)
- PQHD-REQ-0007 — PQHD seed encryption and lock semantics match Bitcoin (wallet lock semantics exist; PQHD seed semantics pending)

---

## Not Started

### Seed Identity + Storage
- PQHD-REQ-0004 — SeedID32 is the only seed identifier
- PQHD-REQ-0005 — Seed import de-duplication is by SeedID32 (idempotent)
- PQHD-REQ-0006 — Multi-root wallets: multiple PQHD seeds per wallet
- PQHD-REQ-0008 — Wallet DB schema for PQHD seeds and policy

### Derivation + Keygen
- PQHD-REQ-0009 — PQHD path constants and semantics are fixed
- PQHD-REQ-0010 — NodeSecret/ChainCode derivation (hardened-only CKD)
- PQHD-REQ-0011 — Leaf key material derivation (HKDF-style)
- PQHD-REQ-0012 — Versioned `KeyGenFromSeed` wrappers per scheme
- PQHD-REQ-0013 — Deterministic RNG scoping for keygen

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
- PQHD-REQ-0023 — PQHD unit tests for determinism + parsing
- PQHD-REQ-0024 — PQHD functional tests for wallet behavior and gating
