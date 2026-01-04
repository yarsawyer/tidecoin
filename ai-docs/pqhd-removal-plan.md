# PQHD-Only Wallet Removal Plan (No BIP32 / No secp Keys)

This document captures the concrete removal plan for Tidecoin when we commit
to **PQHD-only wallets** and **legacy non-HD BDB import** only. There are no
legacy BIP32/HD wallets to preserve.

## Scope and Assumptions

- Legacy wallets are **BDB non-HD** only.
- We still need to **import existing private keys** from those wallets.
- **No BIP32/xpub/xprv** functionality is required or preserved.
- **No secp256k1/ECDSA/ECDH** key support is required for wallet operations.
- PQHD descriptors (`pqhd(...)`) and explicit PQ pubkeys are the only wallet
  key sources going forward.

## Status (as of 2026-01-03)

Completed (in-tree now):
- Removed xpub/xprv encode/decode from `src/key_io.cpp` / `src/key_io.h`.
- Removed `EXT_PUBLIC_KEY` / `EXT_SECRET_KEY` base58 prefixes from
  `src/kernel/chainparams.cpp` / `src/kernel/chainparams.h`.
- Removed `src/util/bip32.h` / `src/util/bip32.cpp` and include references.
- Removed `BIP32Hash` from `src/hash.h` / `src/hash.cpp`.
- Removed `src/script/keyorigin.h` and references.
- Descriptor parser no longer supports origin metadata or xpub/xprv providers;
  PQHD (`pqhd(...)`) and explicit PQ pubkeys only (`src/script/descriptor.cpp`).
- Removed key-origin plumbing from signing providers/signature data
  (`src/script/signingprovider.*`, `src/script/sign.*`).
- Restored `HidingSigningProvider` hide-origin support to match call sites.
- Fixed KeyOriginInfo fingerprint handling for `std::array` in
  `src/wallet/scriptpubkeyman.cpp`.
- Removed `CExtKey`-based `SetupDescriptorScriptPubKeyMan` overloads in
  `src/wallet/wallet.cpp`.
- Removed `bip32_tests.cpp` from `src/test/CMakeLists.txt`.
- Updated `src/test/descriptor_tests.cpp` to drop xpub cache assumptions and
  assert xpub/xprv rejection; updated `src/test/pq_pubkey_container_tests.cpp`
  to avoid secp size constants.
- Removed `src/secp256k1/` subtree and ECC context wiring (node no longer
  initializes secp256k1).

Incomplete / pending:
- CPubKey variable-length PQ refactor (PR-5) is not implemented.
- Script solver updates for variable-length PQ pubkeys (PR-5) not done.
- Descriptor parsing for explicit PQ pubkey hex (raw TidePubKey bytes) not done.
- Remaining test/bench/fuzz cleanup for secp/BIP32 assumptions is partial.

## Phase 0 — Lock Down Behavior (No Deletions Yet)

**Goal:** ensure nothing creates or accepts BIP32/xpub constructs.

Touchpoints:
- `src/script/descriptor.cpp`: reject xpub providers; allow only `pqhd(...)` and
  explicit PQ pubkeys.
- `src/wallet/walletutil.cpp`: ensure new wallets create PQHD descriptors only.
- `src/wallet/scriptpubkeyman.cpp`: stop creating xpub-based descriptors.
- `src/psbt.cpp`, `src/psbt.h`: ignore or reject BIP32/xpub PSBT records.
- `src/rpc/rawtransaction.cpp`: remove BIP32 derivation output from decode paths.

Acceptance:
- New wallet `listdescriptors` shows only PQHD-backed descriptors.
- `importdescriptors` with xpub fails with a clear error.

## Phase 1 — Remove BIP32/xpub Public Surface

**Goal:** remove all user-facing BIP32/xpub support.

Touchpoints:
- `src/key_io.cpp`: remove xpub/xprv encode/decode.
- `src/kernel/chainparams.cpp`: remove `EXT_PUBLIC_KEY` / `EXT_SECRET_KEY`
  base58 prefixes.
- `src/util/bip32.h`: remove keypath helpers.
- `src/hash.h`: remove `BIP32Hash`.
- `src/script/keyorigin.h`: remove BIP32 fingerprint/keypath types.
- `src/rpc/client.cpp`: remove BIP32 derivation hints from RPC help.

Acceptance:
- No xpub/xprv parsing remains.
- RPC outputs do not expose BIP32 keypaths or fingerprints.

## Phase 2 — Remove BIP32 Types + HD Metadata

**Goal:** delete core BIP32 types and HD chain metadata.

Touchpoints:
- `src/key.h`, `src/key.cpp`: remove `CExtKey`, `CExtPubKey`, `CKey::Derive`,
  `CExtKey::SetSeed`.
- `src/pubkey.h`, `src/pubkey.cpp`: remove `CPubKey::Derive`, `CExtPubKey`,
  `BIP32_EXTKEY_SIZE`.
- `src/wallet/walletdb.h`, `src/wallet/walletdb.cpp`: remove `CHDChain`,
  `CKeyMetadata::hd_seed_id`, `hdKeypath`.
- `src/wallet/wallet.h`, `src/wallet/wallet.cpp`: remove HD/xpub APIs and flags
  (e.g., `GetActiveHDPubKeys`, `WALLET_FLAG_LAST_HARDENED_XPUB_CACHED`).
- `src/script/descriptor.cpp`, `src/script/descriptor.h`: remove
  `BIP32PubkeyProvider` and xpub caches.

Acceptance:
- Build has zero BIP32 symbols.
- Wallet metadata stores only PQHD origin data and explicit PQ keys.

## Phase 3 — Remove secp256k1/ECDH/ECC Context

**Goal:** remove all secp256k1/ECDSA/ECDH usage and linkage.

Touchpoints:
- `src/key.h`, `src/key.cpp`: remove ECDH, ECC_Context, secp includes.
- `src/pubkey.cpp`: remove `secp256k1_selftest`.
- `src/init.cpp`, `src/bitcoind.cpp`, tools/bench: remove ECC context creation.
- `src/CMakeLists.txt`: drop secp256k1 subtree from build graph.
- `src/secp256k1/CMakeLists.txt`: remove from build.

Acceptance:
- No `secp256k1_*` symbols linked.
- Node runs without ECC context setup.

## Phase 4 — Script / Descriptor Compatibility Cleanup

**Goal:** ensure scripts and descriptors are PQ-first and variable-length.

Touchpoints:
- `src/pubkey.h`, `src/pubkey.cpp`: refactor CPubKey to variable-length,
  scheme-aware PQ pubkey container.
- `src/script/solver.cpp`: update P2PK/multisig matching for variable-length PQ
  pubkeys.
- `src/script/descriptor.cpp`: explicit PQ pubkey hex is accepted as a key
  expression; `pqhd(...)` remains primary.

Acceptance:
- PQ pubkeys are accepted; legacy secp formats are rejected.
- P2PKH/P2WPKH for PQ pubkeys remain valid.

## Phase 5 — Tests / Bench / Fuzz Cleanup

**Goal:** remove all BIP32/secp test artifacts.

Touchpoints:
- `src/test/*`: remove BIP32/xpub tests and any secp-only assumptions.
- `src/test/fuzz/*`: remove secp-related fuzz targets.
- `src/bench/*`: remove ECDSA/secp benches.

Acceptance:
- `test_tidecoin` builds and runs without secp/BIP32 artifacts.

## Legacy BDB Import (Required)

Because we only have non-HD BDB wallets:

- Import existing private keys as explicit PQ keys.
- Ignore any residual `keypool`/HD chain records if present.
- Do not create or depend on any BIP32 structures.

Touchpoints:
- `src/wallet/walletdb.cpp`: read legacy key records.
- `src/wallet/wallet.cpp`: import into PQHD wallet as explicit keys.

Acceptance:
- Old BDB wallet opens and UTXOs are spendable.
- No BIP32/HD functionality is required for legacy import.

## PR Slice Map (Removal Sequence)

### Removal PR‑1 — Lock down behavior (Phase 0)
- Scope: reject xpub/BIP32 descriptors and PSBT records; PQHD-only descriptors for new wallets.
- Touchpoints: `src/script/descriptor.cpp`, `src/wallet/walletutil.cpp`,
  `src/wallet/scriptpubkeyman.cpp`, `src/psbt.cpp`, `src/psbt.h`,
  `src/rpc/rawtransaction.cpp`
- Tests: descriptor parser tests (xpub reject), PSBT decode tests (BIP32 fields
  ignored/rejected).

### Removal PR‑2 — Remove BIP32/xpub public surface (Phase 1)
- Scope: eliminate xpub/xprv parsing, prefixes, keypath helpers, BIP32 hash util.
- Touchpoints: `src/key_io.cpp`, `src/kernel/chainparams.cpp`,
  `src/util/bip32.h`, `src/hash.h`, `src/script/keyorigin.h`,
  `src/rpc/client.cpp`
- Tests: RPC help/encode tests updated; build passes with no BIP32 symbols.

### Removal PR‑3 — Remove BIP32 types + HD metadata (Phase 2)
- Scope: delete `CExtKey/CExtPubKey`, `CKey::Derive`, HD metadata and xpub
  descriptor provider.
- Touchpoints: `src/key.h`, `src/key.cpp`, `src/pubkey.h`, `src/pubkey.cpp`,
  `src/wallet/walletdb.h`, `src/wallet/walletdb.cpp`, `src/wallet/wallet.h`,
  `src/wallet/wallet.cpp`, `src/script/descriptor.cpp`,
  `src/script/descriptor.h`
- Tests: walletdb serialization tests; descriptor tests (pqhd only); migration
  import from legacy BDB keys.

### Removal PR‑4 — Remove secp256k1/ECDH/ECC context (Phase 3)
- Scope: drop ECC context setup and secp linkage.
- Touchpoints: `src/key.h`, `src/key.cpp`, `src/pubkey.cpp`, `src/init.cpp`,
  `src/bitcoind.cpp`, `src/CMakeLists.txt`,
  `src/secp256k1/CMakeLists.txt`
- Tests: build + basic node startup; remove secp-specific tests/bench that break
  the build.

### Removal PR‑5 — PQ pubkey compatibility + test cleanup (Phase 4/5)
- Scope: CPubKey variable-length PQ refactor; script/descriptor matching;
  cleanup tests/bench/fuzz.
- Touchpoints: `src/pubkey.h`, `src/pubkey.cpp`, `src/script/solver.cpp`,
  `src/script/descriptor.cpp`, `src/test/*`, `src/bench/*`,
  `src/test/fuzz/*`
- Tests: `test_tidecoin`, key/descriptor tests, script tests.

## Task Checklists (Implementation)

### PR‑1 Checklist — Lock Down Behavior
- [x] Reject xpub/xprv key expressions in `src/script/descriptor.cpp` (generic
      parse error today; add a clearer error later if needed).
- [x] Update descriptor tests to cover xpub rejection and pqhd acceptance.
- [x] Ensure new wallet creation only generates pqhd descriptors in
      `src/wallet/walletutil.cpp` and `src/wallet/scriptpubkeyman.cpp`.
- [x] Define PSBT handling for BIP32/xpub records in `src/psbt.h` and wallet
      FillPSBT: hard-reject BIP32 derivation paths and xpubs.
- [x] Update `decodepsbt` output in `src/rpc/rawtransaction.cpp` to omit
      BIP32 fields and reject `bip32derivs=true` in descriptorprocesspsbt.
- [x] Add/adjust tests for PSBT behavior (expect BIP32 derivations to be rejected).

### PR‑2 Checklist — Remove BIP32/xpub Public Surface
- [x] Remove xpub/xprv encoding/decoding in `src/key_io.cpp`.
- [x] Remove `EXT_PUBLIC_KEY` / `EXT_SECRET_KEY` prefixes in
      `src/kernel/chainparams.cpp`.
- [x] Remove `src/util/bip32.h` and all include references.
- [x] Remove `BIP32Hash` from `src/hash.h` and fix any call sites.
- [x] Remove `src/script/keyorigin.h` (BIP32 fingerprints/keypaths) and update
      any dependent code paths.
- [x] Update RPC help text in `src/rpc/client.cpp` to remove BIP32 references.

### PR‑3 Checklist — Remove BIP32 Types + HD Metadata
- [x] Delete `CExtKey` / `CExtPubKey` and related APIs in
      `src/key.h` / `src/key.cpp`.
- [x] Remove `CPubKey::Derive`, `CExtPubKey`, `BIP32_EXTKEY_SIZE` from
      `src/pubkey.h` / `src/pubkey.cpp`.
- [x] Remove `CHDChain` and HD metadata from
      `src/wallet/walletdb.h` / `src/wallet/walletdb.cpp` (ignore legacy
      `hdchain` records; keep legacy parsing of old key metadata only).
- [x] Remove wallet HD/xpub APIs and flags in
      `src/wallet/wallet.h` / `src/wallet/wallet.cpp` (drop `IsHDEnabled`
      and all GUI/interfaces wiring).
- [x] Remove `BIP32PubkeyProvider` and xpub caches from
      `src/script/descriptor.cpp` / `src/script/descriptor.h`.
- [x] Update walletdb tests to validate only PQHD origin metadata.
- [x] Confirm legacy BDB import still loads explicit PQ keys
      (`src/wallet/test/walletload_tests.cpp`).

### PR‑4 Checklist — Remove secp256k1/ECDH/ECC Context
- [x] Remove secp256k1 includes and ECDH/ECC types in `src/key.h` / `src/key.cpp`.
- [x] Remove `secp256k1_selftest` usage in `src/pubkey.cpp`.
- [x] Remove ECC context initialization in `src/init.cpp`, `src/bitcoind.cpp`,
      and any tool entrypoints.
- [x] Drop secp256k1 build targets in `src/CMakeLists.txt` and
      `src/secp256k1/CMakeLists.txt` (subtree removed).
- [x] Remove any remaining secp-only tests/bench that break the build.

### PR‑5 Checklist — PQ Pubkey Compatibility + Test Cleanup
- [ ] Refactor `CPubKey` to variable-length, scheme-aware PQ container in
      `src/pubkey.h` / `src/pubkey.cpp`.
- [ ] Update script matching for P2PK/multisig in `src/script/solver.cpp`.
- [ ] Ensure descriptor parsing accepts explicit PQ pubkeys as raw hex in
      `src/script/descriptor.cpp`.
- [ ] Remove all remaining secp/BIP32 tests, benches, and fuzzers
      (`src/test/*`, `src/bench/*`, `src/test/fuzz/*`) (partial: `bip32_tests`
      removed from build; fuzz + remaining xpub helpers still present).
- [ ] Add/update tests for PQ pubkey container and descriptor parsing.
