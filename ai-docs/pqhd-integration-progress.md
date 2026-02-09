# PQHD Integration Progress

Authoritative spec: `ai-docs/pqhd.md`
Related cleanup/removal plan: `ai-docs/pqhd-removal-plan.md`

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
- PQHD‑only removal work is tracked in `ai-docs/pqhd-removal-plan.md` and is reflected here under “Cleanup alignment”.

---

## Implemented

- PQHD-REQ-0001 — Scheme registry is canonical and stable (`src/pq/pq_scheme.h`, `src/pq/pq_api.h`)
- PQHD-REQ-0003 — Wallet policy decides scheme (no global default scheme)
  - Touch-points:
    - `src/key.h` (`CKey::MakeNewKey(SchemeId, ...)`, `GenerateRandomKey(SchemeId, ...)`)
    - `src/key.cpp` (keygen uses `pq::SchemeFromId`, no implicit default)
    - `src/pq/pq_api.h` (removed `pq::ActiveScheme()`)
    - Tests/benches updated to pass explicit `pq::SchemeId::FALCON_512`
  - Verify:
    - `cmake --build build -j12` (ensures no scheme-less keygen remains)
- PQHD-REQ-0004 — SeedID32 is the only seed identifier (`src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`, `src/test/pqhd_kdf_tests.cpp`)
- PQHD-REQ-0008 — Wallet DB schema for PQHD seeds and policy
  - Touch-points:
    - `src/wallet/pqhd.h` (`PQHDSeed`, `PQHDCryptedSeed`, `PQHDPolicy`)
    - `src/wallet/walletdb.h` (`wallet::DBKeys::PQHD_*`, `WalletBatch::Write*PQHD*`)
    - `src/wallet/walletdb.cpp` (DB key strings, write helpers, `LoadPQHDWalletRecords()`, `walletdescriptorpubkeycache` for PQHD descriptor cache)
    - `src/wallet/wallet.h`, `src/wallet/wallet.cpp` (load hooks + in-memory storage)
  - Verify:
    - `./build/bin/test_tidecoin -t walletdb_tests`
    - `./build/bin/test_tidecoin -t wallet_tests/CreateWallet` (ensures PQHD descriptor cache persists and reloads)
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
- PQHD-REQ-0026 — PQHD‑only PSBT surface (xpub hard‑reject + no BIP32 derivation output)
  - Touch-points:
    - `src/psbt.h` (hard‑reject `PSBT_GLOBAL_XPUB`)
    - `src/rpc/rawtransaction.cpp` (`decodepsbt` omits `global_xpubs`/`bip32_derivs`)
    - `src/rpc/rawtransaction.cpp` (`descriptorprocesspsbt` has no `bip32derivs`)
    - `src/wallet/rpc/spend.cpp` (`walletprocesspsbt` and `walletcreatefundedpsbt` no longer expose `bip32derivs`)
    - `src/wallet/wallet.cpp`, `src/wallet/scriptpubkeyman.cpp` (`FillPSBT` signatures no longer take `bip32derivs`)
    - `src/rpc/client.cpp` (CLI conversion table updated for removed PSBT args/index shifts)
  - Verify:
    - `./build/bin/test_tidecoin -t psbt_pqhd_origin_tests`
    - `python3 test/functional/test_runner.py rpc_psbt.py wallet_bumpfee.py wallet_pqhd_seed_lifecycle.py --jobs=1 --combinedlogslen=200`
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
  - Touch-points:
    - `src/wallet/walletdb.h` (`CKeyMetadata::VERSION_WITH_PQHD_ORIGIN`, `has_pqhd_origin`, `pqhd_seed_id`, `pqhd_path`)
    - `src/wallet/scriptpubkeyman.cpp` (`DescriptorScriptPubKeyMan::GetMetadata` now populates PQHD seed/path from descriptor + derived child index)
    - `src/wallet/rpc/addresses.cpp` (`getaddressinfo` now surfaces `pqhd_seedid` and `pqhd_path` with `include_pqhd_origin` control, default enabled)
  - Verify:
    - `./build/bin/test_tidecoin -t walletdb_tests`
    - `python3 test/functional/test_runner.py wallet_change_address.py --jobs=1 --combinedlogslen=200`
- PQHD-REQ-0016 — Descriptor grammar: `pqhd(<SeedID32>)/...` key expression
  - Touch-points:
    - `src/script/descriptor.cpp` (`PQHDPubkeyProvider`, `ParsePubkeyInner()` `pqhd(...)` parsing)
  - Verify: `./build/bin/test_tidecoin -t descriptor_tests`
- PQHD-REQ-0017 — Descriptor restrictions + canonical printing for `pqhd()`
  - Touch-points:
    - `src/script/descriptor.cpp` (`PQHDPubkeyProvider::ToString()`, hardened-only parsing, `*h` only)
    - `src/test/descriptor_tests.cpp` (`descriptor_pqhd_key_expression_parsing`)
  - Verify: `./build/bin/test_tidecoin -t descriptor_tests`
- PQHD-REQ-0018 — Explicit PQ pubkeys in descriptors use raw prefixed hex only (no xpub/xprv)
  - Touch-points:
    - `src/test/descriptor_tests.cpp` (`descriptor_explicit_pq_pubkey_matrix`)
      - positive matrix: `pk`, `pkh`, `wpkh`, `sh(wpkh)`, `combo`, `wsh(pk)`, `wsh512(pk)`, `multi`, `sortedmulti`, `wsh(multi)` over all supported PQ schemes.
      - mixed-scheme multisig parse path (`GetPQHDSchemePrefix()` must be unset when ambiguous).
      - negative vectors for secp compressed pubkey and xpub/BIP32 descriptor expression.
    - `test/functional/rpc_getdescriptorinfo.py`
      - RPC-surface rejects secp key and xpub expression.
      - RPC-surface accepts explicit PQ raw-hex wrappers including `wsh512(...)`.
  - Verify:
    - `./build/bin/test_tidecoin --run_test=descriptor_tests --report_level=detailed`
    - `python3 test/functional/test_runner.py rpc_getdescriptorinfo.py --jobs=1 --combinedlogslen=200`
  - Behavioral guarantee:
    - Tidecoin descriptor parsing remains PQ-only for explicit key material.
    - Unsupported secp/xpub vectors are rejected at both parser and RPC surfaces.
- PQHD-REQ-0007 — PQHD seed encryption and lock semantics match Bitcoin
  - Touch-points:
    - `src/pq/pqhd_kdf.h` (`pqhd::SecureSeed32` RAII-wiped seed wrapper)
    - `src/script/signingprovider.h`, `src/script/signingprovider.cpp` (`GetPQHDSeed` returns `std::optional<pqhd::SecureSeed32>`; no caller-owned plain output buffers)
    - `src/wallet/scriptpubkeyman.h`, `src/wallet/scriptpubkeyman.cpp` (`WalletStorage::GetPQHDSeed` adopts secure return type)
    - `src/wallet/wallet.h`, `src/wallet/wallet.cpp` (`CWallet::GetPQHDSeed` secure return; locked-wallet deny path; decrypted plaintext is cleansed before release)
    - `src/wallet/pqhd.h` (`PQHDSeed::seed` migrated to secure allocator container)
    - `src/wallet/wallet.cpp` (`PQHDSeedState::seed` secure allocator; explicit cleanse-before-clear in encrypt/remove paths)
    - `src/wallet/rpc/wallet.cpp` (`importpqhdseed` cleanses parsed seed bytes and stack seed buffer)
    - `src/wallet/scriptpubkeyman.cpp` (`TopUpWithDB` derivation path uses `PQHDWalletSigningProvider` and fails when seed cannot be decrypted)
    - `src/wallet/rpc/addresses.cpp` (`getnewaddress`/`getrawchangeaddress` surface keypool-exhaustion derivation failures)
    - `test/functional/wallet_pqhd_lock_semantics.py` (runtime lock/unlock derivation behavior)
  - Verify:
    - `cmake --build build -j 12`
    - `./build/bin/test_tidecoin -t walletdb_tests`
    - `./build/bin/test_tidecoin -t scriptpubkeyman_tests`
    - `./build/bin/test_tidecoin -t psbt_wallet_tests`
    - `python3 test/functional/test_runner.py wallet_pqhd_lock_semantics.py --jobs=1 --combinedlogslen=200`
    - `python3 test/functional/test_runner.py wallet_pqhd_seed_lifecycle.py rpc_psbt.py --jobs=1 --combinedlogslen=200`
  - Behavioral guarantee:
    - Locked encrypted PQHD wallets can still hand out pre-generated keypool entries.
    - Once keypool is exhausted, locked wallets cannot derive new PQHD keys.
    - Unlocking restores derivation and address generation.
    - PQHD seed retrieval is secure-by-construction for wallet/signing-provider callers, and temporary plaintext seed buffers are explicitly cleansed on critical paths.
- PQHD-REQ-0002 — Auxpow-gated scheme activation for output generation
  - Touch-points:
    - `src/pq/pq_scheme.h` (`pq::IsSchemeAllowedAtHeight(...)`)
    - `src/wallet/wallet.cpp` (`CWallet::LoadPQHDPolicy` clamp + policy defaults)
    - `src/wallet/walletutil.cpp` (`GeneratePQHDWalletDescriptor` activation gate)
    - `src/wallet/scriptpubkeyman.cpp` (`DescriptorScriptPubKeyMan::GetNewDestination` scheme gate)
    - `src/wallet/rpc/wallet.cpp` (`setpqhdpolicy`)
    - `src/qt/addresstablemodel.cpp`, `src/qt/optionsdialog.{h,cpp}`, `src/qt/forms/optionsdialog.ui` (Qt override/defaults)
  - Verify:
    - `./build/bin/test_tidecoin -t pq_pubkey_container_tests`
    - `./build/bin/test_tidecoin -t walletdb_tests`
    - `./build/bin/test_tidecoin -t scriptpubkeyman_tests`
    - `python3 test/functional/test_runner.py wallet_pqhd_policy.py --jobs=1 --combinedlogslen=200`
  - Note:
    - Tidecoin regtest is post-auxpow from height 0; coverage is intentionally post-auxpow only.
- PQHD-REQ-0021 — Wallet + RPC/Qt write/read PQHD origin metadata in PSBT
  - Touch-points:
    - `src/wallet/scriptpubkeyman.cpp` (`DescriptorScriptPubKeyMan::FillPSBT` emits `tidecoin/PQHD_ORIGIN` for unambiguous single-key wallet-owned inputs/outputs, gated by `include_pqhd_origins`)
    - `src/wallet/wallet.cpp`, `src/wallet/wallet.h` (`CWallet::FillPSBT` plumbs `include_pqhd_origins`)
    - `src/wallet/rpc/spend.cpp` (`walletprocesspsbt` adds `include_pqhd_origins` RPC flag, default enabled)
    - `src/rpc/client.cpp` (CLI arg conversion mapping for `walletprocesspsbt` and `getaddressinfo` options)
    - `src/wallet/test/psbt_wallet_tests.cpp` (`psbt_fill_emits_pqhd_origin_records`)
    - `src/rpc/rawtransaction.cpp` (`decodepsbt` parsed display of `pqhd_origins`, already present)
    - `test/functional/rpc_psbt.py` (wallet-update flow remains passing with PQHD-origin decode paths)
    - `test/functional/wallet_pqhd_seed_lifecycle.py` (explicit enabled/disabled origin-emission assertions)
  - Verify:
    - `TIDECOIN_RUN_WALLET_TESTS=1 ./build/bin/test_tidecoin --run_test=psbt_wallet_tests --report_level=detailed`
    - `python3 test/functional/test_runner.py wallet_pqhd_seed_lifecycle.py wallet_pqhd_lock_semantics.py wallet_change_address.py rpc_psbt.py --jobs=1 --combinedlogslen=200`
  - Behavioral guarantee:
    - wallet PSBT fill emits proprietary PQHD origin metadata for wallet-owned, single-key scripts on both input and output maps by default.
    - operators can disable this metadata emission per-call in `walletprocesspsbt` for privacy-sensitive workflows.
- PQHD-REQ-0024 — PQHD functional tests for wallet behavior and gating
  - Touch-points:
    - `test/functional/wallet_pqhd_policy.py` (scheme-policy update and override gating)
    - `test/functional/wallet_pqhd_lock_semantics.py` (locked-derivation semantics)
    - `test/functional/wallet_pqhd_seed_lifecycle.py` (multi-root seed lifecycle)
    - `test/functional/test_runner.py` (test registration)
  - Verify:
    - `python3 test/functional/test_runner.py wallet_pqhd_policy.py wallet_pqhd_lock_semantics.py wallet_pqhd_seed_lifecycle.py --jobs=1 --combinedlogslen=200`
  - Behavioral guarantee:
    - Core PQHD policy, lock behavior, and seed lifecycle are covered by direct functional assertions.
- PQHD-REQ-0005 — Seed import de-duplication is by SeedID32 (idempotent)
  - Touch-points:
    - `src/wallet/wallet.h` (`ImportPQHDSeedResult`, `ImportPQHDSeed`)
    - `src/wallet/wallet.cpp` (`ComputePQHDSeedID`, `CWallet::ImportPQHDSeed`)
    - `src/wallet/rpc/wallet.cpp` (`importpqhdseed`)
    - `test/functional/wallet_pqhd_seed_lifecycle.py` (re-import returns `inserted=false`)
  - Verify:
    - `python3 test/functional/test_runner.py wallet_pqhd_seed_lifecycle.py --jobs=1 --combinedlogslen=200`
  - Behavioral guarantee:
    - Re-import of the same 32-byte master seed is accepted as a no-op keyed by SeedID32.
- PQHD-REQ-0006 — Multi-root wallets: multiple PQHD seeds per wallet
  - Touch-points:
    - `src/wallet/wallet.h` (`ListPQHDSeeds`, `SetPQHDSeedDefaults`, `RemovePQHDSeed`)
    - `src/wallet/wallet.cpp` (core lifecycle + descriptor-reference safety on removal)
    - `src/wallet/rpc/wallet.cpp` (`listpqhdseeds`, `setpqhdseed`, `removepqhdseed`)
    - `test/functional/wallet_pqhd_seed_lifecycle.py` (import/list/select/remove lifecycle)
  - Verify:
    - `python3 test/functional/test_runner.py wallet_pqhd_seed_lifecycle.py --jobs=1 --combinedlogslen=200`
  - Behavioral guarantee:
    - Wallet supports multiple PQHD roots, exposes lifecycle APIs, and blocks unsafe removal of defaults/descriptor-referenced seeds.
- PQHD-REQ-0022 — Migration baseline: oldtidecoin wallets are legacy BDB non-HD
  - Touch-points:
    - `src/wallet/wallet.cpp` (`DBErrors::LEGACY_WALLET` reject-on-load path, `MigrateLegacyToDescriptor(...)`)
    - `src/wallet/walletdb.cpp` (`LEGACY_WALLET` detection, `bdb_ro` migration-only DB path)
    - `src/wallet/migrate.cpp`, `src/wallet/migrate.h` (BerkeleyRO parser and migration DB backend)
    - `src/wallet/rpc/wallet.cpp` (`listwalletdir` legacy warning, `migratewallet` RPC)
  - Verify (manual real-wallet migration run):
    - Legacy BDB wallet source: `/home/yaroslav/dev/tidecoin/wallet_old/wallet.dat`
    - Isolated node boot:
      - `./build/bin/tidecoind -datadir=/tmp/tide_mig_test -walletdir=/tmp/tide_mig_test/wallets -nosettings -listen=0 -dnsseed=0 -discover=0 -server=1 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcuser=tide -rpcpassword=tidepass -rpcport=19443 -port=19444 -daemonwait`
    - Legacy detection:
      - `./build/bin/tidecoin-cli -datadir=/tmp/tide_mig_test -rpcuser=tide -rpcpassword=tidepass -rpcport=19443 listwalletdir`
      - returns warning: `This wallet is a legacy wallet and will need to be migrated with migratewallet before it can be loaded`
    - Migration:
      - `./build/bin/tidecoin-cli -datadir=/tmp/tide_mig_test -rpcuser=tide -rpcpassword=tidepass -rpcport=19443 migratewallet wallet_old`
      - returned:
        - `wallet_name: wallet_old`
        - `backup_path: /tmp/tide_mig_test/wallets/wallet_old_1770668262.legacy.bak`
    - Post-migration state:
      - `getwalletinfo` shows descriptor wallet (`format: sqlite`, `descriptors: true`)
      - `listpqhdseeds` shows initialized default PQHD seed.
  - Behavioral guarantee:
    - Legacy oldtidecoin BDB wallets are intentionally not loaded directly.
    - Migration RPC converts legacy wallet state to descriptor/PQHD wallet state and creates a legacy backup.

---

## In Progress

- (none)

---

## Not Started

### Seed Identity + Storage
- (none)

### Derivation + Keygen
- (none)

### Key Container Refactor
<!-- (implemented; see above) -->

### Descriptors
- (none)

### PSBT + RPC/Qt Integration
- (none)

### Migration + Tests
- (none)

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
- [x] PR-4 — Wallet DB PQHD seed/policy records
  - Touch-points: `src/wallet/pqhd.h`, `src/wallet/walletdb.h`, `src/wallet/walletdb.cpp`, `src/wallet/wallet.h`, `src/wallet/wallet.cpp`, `src/wallet/test/walletdb_tests.cpp`
  - Verify: `./build/bin/test_tidecoin -t walletdb_tests`
- [x] PR-5 — Descriptors: `pqhd(<SeedID32>)/...` parsing + canonical printing + tests
  - Touch-points: `src/script/descriptor.cpp`, `src/test/descriptor_tests.cpp`
  - Verify: `./build/bin/test_tidecoin -t descriptor_tests`
- [x] PR-6 — PSBT `PQHD_ORIGIN` (inputs + outputs) + parsed RPC display
  - Touch-points: `src/psbt.h`, `src/psbt.cpp`, `src/rpc/rawtransaction.cpp`, `src/test/psbt_pqhd_origin_tests.cpp`
  - Verify: `./build/bin/test_tidecoin -t psbt_pqhd_origin_tests`

---

## Cleanup Alignment (PQHD‑Only Removal Plan)

The following cleanup items are already complete and are tracked in
`ai-docs/pqhd-removal-plan.md`:

- BIP32/xpub public surface removed (no xpub/xprv parsing or prefixes).
- `src/util/bip32.*`, `BIP32Hash`, and `script/keyorigin.h` removed.
- `CExtKey`/`CExtPubKey` removed; wallet HD/xpub APIs removed.
- secp256k1 subtree removed; ECC context initialization removed.
- RPC help text updated to drop xpub/xprv references.

These cleanup steps are now part of the baseline and should be assumed in
all future PQHD work.
