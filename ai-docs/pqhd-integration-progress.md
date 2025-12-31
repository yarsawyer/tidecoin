# PQHD Integration Progress

Authoritative spec: `ai-docs/pqhd.md`

This file tracks implementation status by requirement ID (`PQHD-REQ-xxxx`).

Legend:
- Implemented: landed in code and covered by tests (or explicitly verified behavior)
- In Progress: active work in-flight or partially present but incomplete
- Not Started: no implementation yet

---

## How We Mark Progress

- This file is the **source of truth** for PQHD implementation status.
- To mark progress, **move** a `PQHD-REQ-xxxx` bullet between:
  - `Not Started` → `In Progress` → `Implemented`
- When moving a requirement to `Implemented`, add:
  - Touch-points (file paths + key symbols)
  - How to verify (unit/functional test targets, commands, or manual verification notes)
- Keep the **PR slice checkboxes** updated (below) so it’s obvious what we can start next.

---

## Decisions Needed

- None for the current PR chain.
- PQHD seed lifecycle RPC/Qt surface is explicitly deferred; the plan is to refactor/extend existing wallet RPC/Qt flows later (no new “seed management” RPC family now).

---

## Implemented

- PQHD-REQ-0001 — Scheme registry is canonical and stable (`src/pq/pq_scheme.h`, `src/pq/pq_api.h`)
- PQHD-REQ-0004 — SeedID32 is the only seed identifier (`src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`, `src/test/pqhd_kdf_tests.cpp`)
- PQHD-REQ-0008 — Wallet DB schema for PQHD seeds and policy
  - Touch-points:
    - `src/wallet/pqhd.h` (`PQHDSeed`, `PQHDCryptedSeed`, `PQHDPolicy`)
    - `src/wallet/walletdb.h` (`wallet::DBKeys::PQHD_*`, `WalletBatch::Write*PQHD*`)
    - `src/wallet/walletdb.cpp` (DB key strings, write helpers, `LoadPQHDWalletRecords()`)
    - `src/wallet/wallet.h`, `src/wallet/wallet.cpp` (load hooks + in-memory storage)
  - Verify: `./build/bin/test_tidecoin -t walletdb_tests`
- PQHD-REQ-0019 — PSBT is BIP174 and supports proprietary key/value records (`src/psbt.h`, `src/rpc/rawtransaction.cpp` raw proprietary display)
- PQHD-REQ-0020 — `tidecoin/PQHD_ORIGIN` proprietary record encoding + parsing
  - Touch-points:
    - `src/psbt.h` (`psbt::tidecoin::{PROPRIETARY_IDENTIFIER,SUBTYPE_PQHD_ORIGIN,PQHDOrigin}`)
    - `src/psbt.cpp` (`psbt::tidecoin::{MakeProprietaryKey,MakePQHDOriginValue,DecodePQHDOrigin,AddPQHDOrigin}`)
    - `src/rpc/rawtransaction.cpp` (`decodepsbt` parsed display: `pqhd_origins`)
    - `src/test/psbt_pqhd_origin_tests.cpp`
  - Verify:
    - `cmake --build build -j12 --target test_bitcoin`
    - `./build/bin/test_tidecoin -t psbt_pqhd_origin_tests`
- PQHD-REQ-0009 — PQHD path constants and semantics are fixed (`src/pq/pqhd_params.h` for purpose/coin_type; hardened-only enforcement in `src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`; vectors in `src/test/pqhd_kdf_tests.cpp`)
- PQHD-REQ-0010 — NodeSecret/ChainCode derivation (hardened-only CKD) (`src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`, `src/test/pqhd_kdf_tests.cpp`)
- PQHD-REQ-0011 — Leaf key material derivation (HKDF-style) (`src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`, `src/test/pqhd_kdf_tests.cpp`)
  - Safety hardening: strict v1 leaf-path validation (shape + hardened-only + scheme must be recognized by build), cleanses secret intermediates, move-only RAII for 64-byte stream keys.
- PQHD-REQ-0012 — Versioned `KeyGenFromSeed` wrappers per scheme (`src/pq/pq_api.h`, `src/pq/pqhd_keygen.cpp`, `src/test/pqhd_keygen_tests.cpp`)
  - Covers Falcon-512/1024 + ML-DSA-44/65/87; deterministic keypair seed length is enforced and negative-tested.
- PQHD-REQ-0013 — Deterministic RNG scoping for keygen (`src/pq/pqhd_keygen.cpp` uses deterministic keypair entrypoints; no global RNG override)
- PQHD-REQ-0014 — `CPubKey` becomes scheme-aware and variable-length
  - Touch-points:
    - `src/pubkey.h` (`CPubKey`, `GetLen()`, `COMPRESSED_SIZE`, `UNCOMPRESSED_SIZE`, `SIZE` as a maximum)
    - `src/pubkey.cpp` (`CPubKey` parsing/verification, compact message recovery path)
    - `src/key.cpp` (BIP32/CExtPubKey fixed 33-byte pubkey assumptions contained)
    - `src/script/solver.cpp` (`MatchPayToPubkey` uses `GetOp()` + `CPubKey::ValidSize()` for variable-length keys)
  - Verify: `./build/bin/test_tidecoin -t pq_pubkey_container_tests`
- PQHD-REQ-0015 — Fixed-size `CPubKey::SIZE` assumptions are removed/contained
  - Touch-points:
    - `src/psbt.h` (BIP32 keypath and partial-sig key-size checks accept variable-length PQ pubkeys)
    - `src/key.cpp` (`CExtPubKey::Encode()` copies 33 bytes, not `CPubKey::SIZE`)
  - Verify: `./build/bin/test_tidecoin -t psbt_pq_keypaths_tests`
- PQHD-REQ-0023 — PQHD unit tests for determinism + parsing (determinism: `src/test/pqhd_kdf_tests.cpp`, `src/test/pqhd_keygen_tests.cpp`)
- PQHD-REQ-0025 — PQHD origin fields in `CKeyMetadata` (SeedID32 + hardened path)
  - Touch-points: `src/wallet/walletdb.h` (`CKeyMetadata::VERSION_WITH_PQHD_ORIGIN`, `has_pqhd_origin`, `pqhd_seed_id`, `pqhd_path`)
  - Verify: `./build/bin/test_tidecoin -t walletdb_tests`
- PQHD-REQ-0016 — Descriptor grammar: `pqhd(<SeedID32>)/...` key expression
  - Touch-points:
    - `src/script/descriptor.cpp` (`PQHDPubkeyProvider`, `ParsePubkeyInner()` `pqhd(...)` parsing)
  - Verify: `./build/bin/test_tidecoin -t descriptor_tests`
- PQHD-REQ-0017 — Descriptor restrictions + canonical printing for `pqhd()`
  - Touch-points:
    - `src/script/descriptor.cpp` (`PQHDPubkeyProvider::ToString()`, hardened-only parsing, `*h` only)
    - `src/test/descriptor_tests.cpp` (`descriptor_pqhd_key_expression_parsing`)
  - Verify: `./build/bin/test_tidecoin -t descriptor_tests`

---

## In Progress

- PQHD-REQ-0002 — Auxpow-gated scheme activation for output generation (documented; enforcement pending)
- PQHD-REQ-0003 — Wallet policy decides scheme (vs `pq::ActiveScheme()`) (documented; enforcement pending)
- PQHD-REQ-0007 — PQHD seed encryption and lock semantics match Bitcoin (wallet lock semantics exist; PQHD seed semantics pending)
- PQHD-REQ-0021 — Wallet + RPC/Qt write/read PQHD origin metadata in PSBT
  - Partial: `decodepsbt` reads and formats `tidecoin/PQHD_ORIGIN` into `pqhd_origins`.
  - Missing: wallet emission during `walletprocesspsbt` / PSBT creation and analysis.

---

## Not Started

### Seed Identity + Storage
- PQHD-REQ-0005 — Seed import de-duplication is by SeedID32 (idempotent)
- PQHD-REQ-0006 — Multi-root wallets: multiple PQHD seeds per wallet

### Derivation + Keygen
- (none)

### Key Container Refactor
<!-- (implemented; see above) -->

### Descriptors
- PQHD-REQ-0018 — Explicit pubkeys in descriptors remain usable for PQ
  - Note: inherited upstream `descriptor_tests` vectors are secp256k1/WIF/BIP32-centric and are skipped in Tidecoin (PQ `CKey`). We still need a small PQ-native descriptor test suite for explicit pubkeys (raw hex `TidePubKey` bytes).

### PSBT + RPC/Qt Integration
- (implemented) PQHD-REQ-0020 — Define `tidecoin/PQHD_ORIGIN` proprietary record encoding
- PQHD-REQ-0021 — Wallet + RPC/Qt write/read PQHD origin metadata in PSBT

### Migration + Tests
- PQHD-REQ-0022 — Migration baseline: oldtidecoin wallets are legacy BDB non-HD
- PQHD-REQ-0024 — PQHD functional tests for wallet behavior and gating

---

## PR Slice Status (from `ai-docs/sprints/pqhd-next-sprint.md`)

- [x] PR-1 — PQHD KDF primitives + vectors
  - Touch-points: `src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`, `src/pq/pqhd_params.h`, `src/test/pqhd_kdf_tests.cpp`
  - Verify: `./build/bin/test_tidecoin -t pqhd_kdf_tests`
- [x] PR-2 — `KeyGenFromSeed` v1 (all schemes) + determinism tests
  - Touch-points: `src/pq/pq_api.h`, `src/pq/pqhd_keygen.cpp`, `src/test/pqhd_keygen_tests.cpp`
  - Verify: `./build/bin/test_tidecoin -t pqhd_keygen_tests`
- [x] PR-3 — `CPubKey` variable-length refactor (scheme-aware)
  - Touch-points: `src/pubkey.h`, `src/pubkey.cpp`, `src/key.cpp`, `src/psbt.h`, `src/script/solver.cpp`, `src/test/pq_pubkey_container_tests.cpp`, `src/test/psbt_pq_keypaths_tests.cpp`
  - Verify: `./build/bin/test_tidecoin -t pq_pubkey_container_tests` and `./build/bin/test_tidecoin -t psbt_pq_keypaths_tests`
- [x] PR-4 — Wallet DB PQHD seed/policy records + auxpow scheme gating semantics
  - Touch-points: `src/wallet/pqhd.h`, `src/wallet/walletdb.h`, `src/wallet/walletdb.cpp`, `src/wallet/wallet.h`, `src/wallet/wallet.cpp`, `src/wallet/test/walletdb_tests.cpp`
  - Verify: `./build/bin/test_tidecoin -t walletdb_tests`
- [x] PR-5 — Descriptors: `pqhd(<SeedID32>)/...` parsing + canonical printing + tests
  - Touch-points: `src/script/descriptor.cpp`, `src/test/descriptor_tests.cpp`
  - Verify: `./build/bin/test_tidecoin -t descriptor_tests`
- [x] PR-6 — PSBT `PQHD_ORIGIN` (inputs + outputs) + parsed RPC display
  - Touch-points: `src/psbt.h`, `src/psbt.cpp`, `src/rpc/rawtransaction.cpp`, `src/test/psbt_pqhd_origin_tests.cpp`
  - Verify: `./build/bin/test_tidecoin -t psbt_pqhd_origin_tests`
