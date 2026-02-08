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
- Result: failing decaying miniscript multisig PSBT functional test now passes.

## Problem Statement
In Tidecoin (PQ-only path), `bip32derivs` is intentionally unsupported in wallet PSBT fill:
- `CWallet::FillPSBT` returns `PSBTError::UNSUPPORTED` when `bip32derivs=true`.

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
- intentional `bip32derivs` unsupported path in wallet PSBT fill,
- different key-plumbing expectations in descriptor manager indexing.

Net effect:
- Tidecoin now reaches functional parity for affected multisig/miniscript signing behavior via script/keyid fallback route.

## Known Adjacent Issue (`dumpprivkey` Path)
During debugging, per-signer `dumpprivkey` strategy was attempted and initially found unreliable for this flow.

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
- therefore PSBT correctness is fixed even while `dumpprivkey(address)` remains inconsistent for some descriptor/PQHD cases.

Status:
- not required for PSBT signing correctness after this hardening.
- recommended as follow-up item.

### Follow-up remediation
1. done: aligned `dumpprivkey(address)` with descriptor ownership path by resolving a private-capable provider on matching descriptor SPKM.
2. done: added functional parity coverage:
   - `dumpprivkey(address)` returns key for owned descriptor/PQHD address.
   - parity check between `dumpprivkey(address)` and `dumpprivkey(descriptor, {"index": 0})`.
3. pending hardening additions:
   - explicit locked-wallet and watch-only negative matrix for descriptor-address path.

## Hardening Test Plan
### Completed verification
- `wallet_miniscript_decaying_multisig_descriptor_psbt.py` passes with core fix applied.

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
   - status: parity implemented; negative matrix pending.

## Residual Risk Assessment
- **Risk level:** low after fix.
- **Primary residual risk:** future descriptor cache/index changes could regress pubkey map coverage.
- **Mitigation:** lock in fallback behavior with dedicated tests (items 1, 2, 7, 8 above).

## Rollout Recommendation
1. Keep current core fix (do not revert).
2. Implement and land PSBT hardening tests (items 1-6).
3. done for positive path: implemented `dumpprivkey` address-path fix and landed parity regression coverage.
4. Require `wallet_miniscript_decaying_multisig_descriptor_psbt.py` and new `dumpprivkey` functional checks in wallet-test CI gate.
5. Re-run wallet functional subset after each descriptor/SPKM refactor.
