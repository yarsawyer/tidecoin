# PSBT Hardening Fix Report

## Scope
This document tracks hardening work around Tidecoin wallet PSBT signing behavior after the discovered multisig/miniscript signer-discovery failures.

Focus area:
- `src/wallet/scriptpubkeyman.cpp` (`DescriptorScriptPubKeyMan::FillPSBT`)
- `src/wallet/wallet.cpp` (`CWallet::FillPSBT`)
- functional coverage for multisig/miniscript PSBT signing paths

## Executive Summary
- A real wallet-core correctness issue was identified: a signer wallet could fail to produce signatures for valid PSBT inputs it actually had keys for.
- Root cause was not consensus/script verification; it was key discovery in wallet-side PSBT signing fallback.
- Implemented fix:
  1. extract candidate pubkeys from generic pushed script elements (not only `Solver` PUBKEY/MULTISIG paths),
  2. add key-id fallback lookup (`CKeyID`) when descriptor pubkey-index map lookup misses.
- Result:
  - failing decaying miniscript multisig PSBT functional test passes,
  - descriptor/PQHD `dumpprivkey(address)` parity issue was fixed in core.

## Problem Statement
In Tidecoin (PQ-only path), BIP32 derivation toggles are removed from wallet PSBT APIs:
- `walletprocesspsbt` no longer accepts a `bip32derivs` argument.
- `walletcreatefundedpsbt` no longer accepts a `bip32derivs` argument.
- `CWallet::FillPSBT` / `DescriptorScriptPubKeyMan::FillPSBT` no longer carry a `bip32derivs` parameter.

That removes upstream Bitcoin’s usual fallback key discovery inputs (`hd_keypaths`, taproot bip32 paths) from wallet signer flow.
The remaining fallback in Tidecoin was insufficient for some miniscript constructions.

Observed failure mode:
- test: `wallet_miniscript_decaying_multisig_descriptor_psbt.py`
- symptom: final signer iteration did not flip PSBT to `complete=true` even though script material and ownership were expected.

## Root Cause Analysis
### Root cause A: fallback key extraction too narrow
Previous fallback key collection depended on `Solver(...)` script classification (`PUBKEY`, `MULTISIG`) and did not robustly cover miniscript keys embedded in general pushed byte elements.

Impact:
- candidate signing keys were never discovered for some witness/redeem script shapes.

### Root cause B: pubkey->descriptor index lookup miss
`GetSigningProvider(const CPubKey&)` requires an exact hit in descriptor manager `m_map_pubkeys`.

If map lookup misses for a pubkey:
- provider lookup returns `nullptr`,
- even when the wallet still has matching private key material in descriptor key store by `CKeyID`.

Impact:
- signer lookup could fail due to cache/index coverage mismatch despite local key ownership.

## Implemented Fixes
### 1) Generic pushdata pubkey extraction
In `DescriptorScriptPubKeyMan::FillPSBT` fallback path:
- parse opcodes in `script`, `input.redeem_script`, and `input.witness_script`,
- treat pushed byte vectors that parse as valid pubkeys as signing candidates,
- de-duplicate by `CKeyID`.

Security properties:
- no signature acceptance change,
- no consensus behavior change,
- only candidate discovery for wallet-local signing expanded.

### 2) Key-id fallback injection
When `GetSigningProvider(pubkey)` misses:
- perform direct `GetKey(pubkey.GetID())` lookup in descriptor key store,
- if found, inject pubkey/key into temporary signing provider used for that PSBT input signing attempt.

Security properties:
- only keys already present in wallet store are used,
- no external key material import,
- locked/encrypted wallet constraints remain enforced by existing key access flow.

### 3) Wallet PSBT emission of `tidecoin/PQHD_ORIGIN`
In `DescriptorScriptPubKeyMan::FillPSBT`:
- for each wallet-owned input script and output script, when the solving/signing provider is unambiguous (single pubkey),
- resolve PQHD metadata via `GetMetadata(dest)` (`pqhd_seed_id` + hardened path),
- emit proprietary PSBT records via `psbt::tidecoin::AddPQHDOrigin(...)` to:
  - `PSBTInput::m_proprietary` (`PSBT_IN_PROPRIETARY`)
  - `PSBTOutput::m_proprietary` (`PSBT_OUT_PROPRIETARY`)

Validation coverage:
- unit: `psbt_fill_emits_pqhd_origin_records` (`src/wallet/test/psbt_wallet_tests.cpp`)
- functional: `rpc_psbt.py` still passes with decode/analyze paths intact.

### 4) Privacy control: optional PQHD origin emission
To support privacy-sensitive PSBT workflows, emission is now explicitly controllable:
- `walletprocesspsbt` adds `include_pqhd_origins` (default `true`).
- Core path plumbs this flag through:
  - `CWallet::FillPSBT(..., include_pqhd_origins)`
  - `DescriptorScriptPubKeyMan::FillPSBT(..., include_pqhd_origins)`
  - `ExternalSignerScriptPubKeyMan::FillPSBT(..., include_pqhd_origins)`
- When disabled:
  - PSBT signing/updating behavior is unchanged,
  - `tidecoin/PQHD_ORIGIN` proprietary records are not attached.

Validation coverage:
- unit: `psbt_fill_emits_pqhd_origin_records` now checks both enabled and disabled modes.
- functional: `wallet_pqhd_seed_lifecycle.py` now checks decodepsbt `pqhd_origins` presence/absence under both flag values.

Security/correctness notes:
- emission is metadata-only; no script or signature semantics change.
- emission is intentionally scoped to unambiguous single-key paths to avoid attaching incorrect key-origin tuples for complex/multi-key descriptors.

## Why This Does Not Break Security Guarantees
### Consensus safety
- unchanged: script interpreter, mempool acceptance rules, block validation rules.
- scope is wallet local signing orchestration only.

### Key ownership boundaries
- fallback signs only with key IDs already owned by the current wallet.
- no cross-wallet key leakage path introduced.

### Signature verification integrity
- final signature validity remains enforced by `SignPSBTInput` and script verify flags.
- fallback discovery does not mark invalid signatures as valid.

### DoS profile
- script pushdata scan adds bounded local CPU work in wallet RPC signing flow.
- does not increase p2p attack surface or consensus validation costs.

## Differences vs Bitcoin Upstream
Bitcoin descriptor PSBT fallback uses PSBT metadata paths (`hd_keypaths`, taproot paths) and does not require this exact fallback strategy.

Tidecoin differences driving this hardening:
- PQ-only descriptor model,
- no BIP32-derivation option in wallet PSBT APIs,
- different key-plumbing expectations in descriptor manager indexing.

Net effect:
- Tidecoin now reaches functional parity for affected multisig/miniscript signing behavior via script/keyid fallback route.

## Adjacent Hardening Completed (PQHD Metadata Surface)
To restore strict wallet functional coverage (without reintroducing BIP32/xpub semantics), an adjacent wallet metadata hardening was implemented:

- `DescriptorScriptPubKeyMan::GetMetadata` now emits PQHD origin metadata for descriptor-owned destinations:
  - resolves descriptor index from `m_map_script_pub_keys`,
  - reads descriptor base path via `GetPQHDKeyPathInfo()`,
  - appends hardened child index for ranged descriptors,
  - fills `CKeyMetadata::{has_pqhd_origin,pqhd_seed_id,pqhd_path}`.
- `getaddressinfo` now exports:
  - `pqhd_seedid` (SeedID32),
  - `pqhd_path` (`m/...h/...` path).

Why this matters for PSBT hardening context:
- It does not change signing correctness directly, but it closes observability gaps that previously forced weaker behavioral-only assertions.
- It enables strict derivation-index functional checks in PQHD wallets while keeping Tidecoin’s PQHD-only model (no `hdkeypath` / BIP32 metadata dependency).

## Resolved Adjacent Issue (`dumpprivkey` Path)
During debugging, per-signer `dumpprivkey` strategy was attempted and exposed an address-target descriptor provider mismatch.

Status:
- fixed in core (`src/wallet/rpc/addresses.cpp`) by adding:
  - descriptor SPKM private-provider fallback for address-target lookups,
  - legacy SPKM key lookup path when solving providers intentionally omit private key access.
- covered by regression in `test/functional/wallet_importdescriptors.py` (address-target vs descriptor-target parity on imported descriptor key).

### Intent vs implementation
Design intent (documented):
- `dumpprivkey` accepts both `address` and `descriptor` targets.
- expected failures are lock state, watch-only, not-owned key material, or missing seed/material.

Implementation reality:
- address-target branch uses `GetSolvingProvider(script)` and then `GetKey(...)` from that provider.
- for descriptor SPKM, solving provider path uses `include_private=false`, so private key lookup can fail even when wallet owns the key.
- descriptor-target branch uses index-based provider with `include_private=true`, so it is more reliable.

Conclusion:
- this mismatch was an implementation oversight in `dumpprivkey` address-path handling, not an intentional policy limitation.

### Why this did not block PSBT hardening
- PSBT signing now uses `DescriptorScriptPubKeyMan::FillPSBT` fallback logic (script pubkey extraction + key-id fallback), independent of `dumpprivkey` RPC behavior.
- PSBT correctness was fixed first; `dumpprivkey(address)` parity was then fixed as an adjacent RPC-surface hardening.

Status:
- fixed for positive owned-descriptor path.
- additional negative-matrix assertions are still recommended.

## Seed Memory Hardening (2026-02-09)
### Objective
Eliminate non-RAII plaintext seed handling in the wallet/signing-provider seed retrieval path, and ensure explicit cleanse-before-clear behavior on critical seed lifecycle operations.

### Core changes
1. Secure retrieval contract:
   - `SigningProvider::GetPQHDSeed` now returns `std::optional<pqhd::SecureSeed32>` instead of writing into caller-owned `std::array`.
   - Propagated through:
     - `src/script/signingprovider.h`
     - `src/script/signingprovider.cpp`
     - `src/wallet/scriptpubkeyman.h`
     - `src/wallet/scriptpubkeyman.cpp`
     - `src/wallet/wallet.h`
     - `src/wallet/wallet.cpp`
2. RAII seed wrapper:
   - Added `pqhd::SecureSeed32` (non-copyable, move-only, destructor wipe) in:
     - `src/pq/pqhd_kdf.h`
3. Storage/container hardening:
   - `PQHDSeed::seed` switched to secure allocator container:
     - `src/wallet/pqhd.h`
   - In-memory `PQHDSeedState::seed` switched to secure allocator container:
     - `src/wallet/wallet.h`
4. Explicit cleanse points:
   - Encrypt path wipes plaintext in-memory seed before clear:
     - `src/wallet/wallet.cpp` (`EncryptWallet` PQHD-seed encryption loop)
   - Seed removal wipes plaintext seed bytes before erase:
     - `src/wallet/wallet.cpp` (`RemovePQHDSeed`)
   - RPC import wipes temporary parsed seed bytes and stack seed buffer:
     - `src/wallet/rpc/wallet.cpp` (`importpqhdseed`)
   - Decrypted plaintext in `CWallet::GetPQHDSeed` is cleansed before return:
     - `src/wallet/wallet.cpp`

### Security impact
- No consensus changes.
- No script validation or mempool-policy changes.
- No widening of key-access scope.
- Reduces plaintext seed lifetime and accidental retention in caller-managed buffers.

### Verification
- Build:
  - `cmake --build build -j 12`
- Unit:
  - `./build/bin/test_tidecoin -t walletdb_tests`
  - `./build/bin/test_tidecoin -t scriptpubkeyman_tests`
  - `./build/bin/test_tidecoin -t psbt_wallet_tests`
- Functional:
  - `python3 test/functional/test_runner.py wallet_pqhd_seed_lifecycle.py wallet_pqhd_lock_semantics.py rpc_psbt.py wallet_signer.py --jobs=1 --combinedlogslen=200`
  - Result: `wallet_pqhd_seed_lifecycle.py`, `wallet_pqhd_lock_semantics.py`, `rpc_psbt.py` passed; `wallet_signer.py` skipped by framework (external-signer/xpub path unsupported in PQ-only builds).

### Follow-up remediation
1. done: aligned `dumpprivkey(address)` with descriptor ownership path by resolving a private-capable provider on matching descriptor SPKM.
2. done: added functional parity coverage:
   - `dumpprivkey(address)` returns key for owned descriptor/PQHD address.
   - parity check between `dumpprivkey(address)` and `dumpprivkey(descriptor, {"index": 0})`.
3. done: added explicit negative-matrix coverage for descriptor-address export path:
   - locked encrypted wallet returns unlock-needed error,
   - watch-only descriptor address returns private-key-unavailable,
   - not-owned address returns address-not-found-in-wallet.

## Hardening Test Plan
### Completed verification
- `wallet_miniscript_decaying_multisig_descriptor_psbt.py` passes with core fix applied.
- `wallet_change_address.py` strict derivation-index coverage now passes using `pqhd_path` metadata:
  - `python3 test/functional/test_runner.py wallet_change_address.py --jobs=1 --combinedlogslen=200`

### Current coverage inventory (`dumpprivkey`)
- No dedicated unit test for `dumpprivkey` RPC behavior found under `src/test`.
- Current references are indirect/functional helper usage in:
  - `test/functional/test_framework/test_node.py`
  - `test/functional/test_framework/wallet_util.py`
- Conclusion: the `dumpprivkey(address)` vs `dumpprivkey(descriptor,index)` parity bug can regress without being caught by current test suite.

### Required additional tests (to add)
1. **Unit: descriptor PSBT fallback pushdata extraction**
   - Construct miniscript/redeem/witness scripts with keys in pushdata.
   - Assert candidate pubkeys are discovered and used for signing.

2. **Unit: key-id fallback lookup**
   - Simulate missing `m_map_pubkeys` mapping while key exists in descriptor key store.
   - Assert signing succeeds via `GetKey(CKeyID)` fallback.

3. **Unit: locked wallet behavior**
   - Ensure fallback does not bypass lock state.
   - Assert expected `PRIVATE_KEY_NOT_AVAILABLE` semantics.

4. **Functional: multisig partial-sign progression**
   - Ensure deterministic progression from incomplete to complete at threshold in PQ multisig/miniscript wallet tests.

5. **Functional: negative ownership test**
   - Provide PSBT with valid script but key not present in signer wallet.
   - Assert no signature is added.

6. **Fuzz/robustness: large-script pushdata parsing**
   - Exercise fallback parser against large but valid scripts.
   - Ensure no crashes/pathological behavior.

7. **Functional: `dumpprivkey(address)` on owned descriptor/PQHD address**
   - Create descriptor/PQHD wallet, derive address, call `dumpprivkey(address)`.
   - Assert key export succeeds when wallet is unlocked and owns the key.
   - status: implemented in `wallet_importdescriptors.py`.

8. **Functional: `dumpprivkey` parity + negative matrix**
   - Assert parity between:
     - `dumpprivkey(address)` and
     - `dumpprivkey(descriptor, index)` for the same derived child key.
   - Assert locked wallet, watch-only, and not-owned address still fail with expected errors.
   - status: implemented in `wallet_importdescriptors.py`.

## Residual Risk Assessment
- **Risk level:** low after fix.
- **Primary residual risk:** future descriptor cache/index changes could regress pubkey map coverage.
- **Mitigation:** lock in fallback behavior with dedicated tests (items 1, 2, 7, 8 above).

## Rollout Recommendation
1. Keep current core PSBT hardening fix (do not revert).
2. Keep current `dumpprivkey(address)` parity fix (do not revert).
3. Implement and land remaining hardening tests (items 1-6).
4. Keep `wallet_miniscript_decaying_multisig_descriptor_psbt.py` and `wallet_importdescriptors.py` in wallet-test CI gate.
5. Re-run wallet functional subset after each descriptor/SPKM refactor.
