# PQ Dummy Signature + Wallet Sizing Plan

Goal: remove remaining ECDSA/DER-sized assumptions from **dummy signatures** and **wallet sizing fallbacks**, and make them PQ-correct across **all supported PQ schemes**.

This work affects production code paths (PSBT, wallet capability probing, fee/size estimation), not just tests.

## Progress (as of 2026-02-02)

Completed:
- Added PQ sizing helpers in `src/pq/pq_txsize.h` and used them in wallet/test paths.
- Implemented PQ-aware dummy signature creator in `src/script/sign.cpp` (DER/ECDSA dummy sizing removed).
- Replaced wallet fallback sizing with PQ-aware input vsize (no ECDSA-size fallback).
- Updated unit tests that depended on legacy sizes:
  - `src/wallet/test/coinselector_tests.cpp`: PQ sizing for inputs, scaled max weights, and speed-ups (reuse wallets, avoid PQ keygen hot paths). `coin_grinder_tests` now passes.

Pending:
- Add `pq_txsize_tests.cpp` coverage for all schemes (Falcon/ML-DSA) and P2WPKH/P2SH-P2WPKH vsize.
- Finish miniscript sizing fixes (separate project).
- Run full unit suite after remaining fixes to confirm no regressions.

## Test Controls

- `coinselector_tests` are disabled by default to keep the suite fast.
- Run them explicitly by setting:
  - `TIDECOIN_RUN_COINSELECTOR_TESTS=1 ./build/bin/test_tidecoin --run_test=coinselector_tests`

## Background

Current state:
- `DUMMY_SIGNATURE_CREATOR` in `src/script/sign.cpp` fabricates a DER/ECDSA-shaped signature (71/72 bytes including the sighash byte).
- Tidecoin script validation treats signatures as **PQ signature bytes + 1 sighash byte**:
  - Interpreter pops the last byte as `nHashType` for PQ signatures (`CheckPostQuantumSignature`).
- Pubkeys are serialized as **1-byte scheme prefix + raw pubkey bytes** (`CKey::GetPubKey()`).

Where dummy signatures are used in production:
- `src/psbt.cpp`: `SignPSBTInput()` uses `DUMMY_SIGNATURE_CREATOR` when `txdata == nullptr` (a “probe” to see if a witness signature is produced / input is satisfiable).
- `src/wallet/scriptpubkeyman.cpp`: `LegacyDataSPKM::CanProvide()` uses `DUMMY_SIGNATURE_CREATOR` to probe whether a script can be satisfied.

Where size constants are used in production:
- `src/wallet/spend.cpp`: if `CalculateMaximumSignedInputSize(change_prototype_txout, ...) == -1`, the wallet falls back to `DUMMY_NESTED_P2WPKH_INPUT_SIZE`.

Policy constraints (Tidecoin-specific):
- All keys are PQ and MUST have a valid scheme prefix.
- Missing/unknown prefix is an error for real key usage (no “ECDSA-length fallback”).

## Design principles

1) **Single source of truth for PQ sizes**
- Centralize scheme pubkey/signature sizing in one place based on `pq::SchemeInfo` (pubkey_bytes, sig_bytes_max, sig_bytes_fixed).

2) **Dummy signatures are for structure, not cryptography**
- Dummy signature creators do not validate; they generate a non-empty byte vector of the correct *size* and include the trailing sighash byte.

3) **Never under-estimate**
- For fee estimation fallbacks, prefer conservative (max) sizes if scheme cannot be determined.

4) **Strictness where it matters**
- Wallet policy/encoding should error on unknown scheme prefixes.
- Dummy signature generation should try to infer scheme from the pubkey; if unavailable, it may fall back to a conservative max to avoid breaking PSBT probing, but should not silently “pretend ECDSA”.

## Proposed PR breakdown

### PR-S0: PQ Size Primitives (no behavior changes)
Purpose: add reusable helpers for PQ script sizing without touching wallet/psbt behavior.

Changes:
- Add new header: `src/pq/pq_txsize.h` (or `src/pq/pq_size.h`)
  - `std::optional<pq::SchemeId> SchemeIdFromPubKey(const CPubKey&)` (prefix parsing)
  - `size_t PubKeyLenWithPrefix(pq::SchemeId)`
  - `size_t SigLenMaxInScript(pq::SchemeId)` = `sig_bytes_max + 1` (sighash byte)
  - `size_t SigLenFixedInScript(pq::SchemeId)` (if needed)
  - Template vsize helpers:
    - `int VSizeP2WPKHInput(size_t sig_len_in_script, size_t pubkey_len_with_prefix)`
    - `int VSizeP2SH_P2WPKHInput(size_t sig_len_in_script, size_t pubkey_len_with_prefix)`
    - Helpers handle CompactSize lengths correctly (e.g. pubkeys > 252 bytes).
- Add unit tests: `src/test/pq_txsize_tests.cpp`
  - Verify sizes for all schemes (Falcon-512/1024, ML-DSA 44/65/87).
  - Verify P2WPKH/P2SH-P2WPKH vsize computations match script-level formulae.

Acceptance:
- Builds cleanly.
- New tests pass without changing existing test expectations.

Status: **Partially complete** (helpers in place; tests pending).

---

### PR-S1: PQ-Aware Dummy Signature Creators (script/psbt/wallet probing)
Purpose: replace DER/ECDSA-shaped dummy signatures with PQ-shaped dummy signatures.

Changes:
- `src/script/sign.cpp`:
  - Replace `DummySignatureCreator` implementation with a PQ-aware variant that:
    - Attempts `provider.GetPubKey(keyid, pubkey)`
    - Parses scheme prefix from pubkey[0]
    - Allocates `sig_bytes_max + 1` (or fixed, depending on whether we want MAX vs typical)
    - Sets last byte to `SIGHASH_ALL` (or `SIGHASH_ALL` for BASE/WITNESS_V0; disallow `SIGHASH_DEFAULT` for v1_512).
  - Keep exported symbols:
    - `DUMMY_SIGNATURE_CREATOR` -> “PQ sized (typical or max)”
    - `DUMMY_MAXIMUM_SIGNATURE_CREATOR` -> “PQ sized max”
  - If pubkey/scheme cannot be inferred:
    - Return a conservative max-sized PQ signature (max across supported schemes) OR return false depending on call site needs.
    - Prefer conservative max to avoid breaking PSBT probing and CanProvide.

- Ensure call sites stay correct:
  - `src/psbt.cpp`: PSBT probe path (`txdata==nullptr`) should still work and set `sigdata.witness` when required.
  - `src/wallet/scriptpubkeyman.cpp`: `LegacyDataSPKM::CanProvide()` should continue to behave (probe should populate `sigdata.signatures` when keys exist).

Tests:
- Update/extend `src/wallet/test/wallet_tests.cpp::dummy_input_size_test` to stop relying on ECDSA-size signatures (it should become PQ-based or move to PR-S2).
- Run and ensure passing:
  - `wallet_tests`, `psbt_wallet_tests`, `script_sign` fuzz smoke (if available), `test_tidecoin`.

Acceptance:
- No more DER/ECDSA-length dummy signatures.
- PSBT probe path still works for segwit inputs.

Risks:
- If some providers cannot return pubkeys by keyid during probing, signatures may not be produced. Mitigate via conservative fallback sizing rather than hard failure.

Status: **Complete**.

---

### PR-S2: Wallet fee/size fallback: replace `DUMMY_NESTED_P2WPKH_INPUT_SIZE`
Purpose: make the fallback change-spend size PQ-correct and scheme-aware.

Changes:
- Replace constant `DUMMY_NESTED_P2WPKH_INPUT_SIZE` usage in `src/wallet/spend.cpp`:
  - Add helper in wallet code to determine the correct scheme for change (PQHD policy):
    - Determine active change scheme prefix for the wallet (default change scheme).
    - Compute nested P2WPKH input vsize via `pq_txsize` helpers.
  - Use scheme-aware value when `CalculateMaximumSignedInputSize(...) == -1`.

- Decide strategy for unknown scheme:
  - If wallet has PQHD policy -> always known.
  - If no policy (legacy wallets/tooling) -> conservative max across supported schemes.

Tests:
- Update `src/wallet/test/wallet_tests.cpp` dummy sizing expectations accordingly.
- Check tests sensitive to coin selection / cost-of-change:
  - `src/wallet/test/coinselector_tests.cpp`
  - `src/wallet/test/coinselection_tests.cpp`
  - `src/wallet/test/spend_tests.cpp`
  - `src/wallet/test/feebumper_tests.cpp`

Acceptance:
- No under-estimation in fallback sizing for PQ keys.
- Coin selection tests updated to reflect new fallback sizes means fee/cost-of-change logic is still consistent.

Status: **Complete** (wallet fallback PQ-sized; coinselector tests updated).

---

### PR-S3: Strict prefix rules + docs
Purpose: enforce “prefix required” consistently and document invariants.

Changes:
- Audit any remaining places that “fall back” to legacy ECDSA sizes if scheme prefix missing (descriptor/miniscript sizing, wallet descriptors).
- Add explicit errors where required by Tidecoin policy:
  - Missing/unknown PQ prefix should be a hard error for real key encoding/provider metadata.

Documentation:
- Add a short doc section (either here or in `ai-docs/pqhd.md`) describing:
  - “Signature in script = PQ bytes + sighash byte”
  - How dummy sizing works and why conservative max may be used in probing-only contexts.

Acceptance:
- No silent “ECDSA-size fallback” for PQ keys in production paths.

Status: **Pending**.

## Dependencies / related work

This plan does NOT fully fix miniscript sizing assumptions (hardcoded 33-byte pubkeys / 72-byte sigs). That is a separate but related project:
- Miniscript PQ sizing correctness must be fixed so `Descriptor::MaxSatisfactionWeight()` becomes accurate.
- Until then, wallet may still under-estimate when descriptor sizing paths are used. PR-S2 reduces the risk in fallback paths but does not eliminate it.

## Test matrix (per PR)

Always run:
- `cmake --build build -j 12`
- `./build/bin/test_tidecoin --run_test=wallet_tests --report_level=detailed`
- `./build/bin/test_tidecoin --run_test=coinselector_tests --report_level=detailed`
- `./build/bin/test_tidecoin --run_test=psbt_wallet_tests --report_level=detailed`
- `./build/bin/test_tidecoin --run_test=spend_tests --report_level=detailed`

After PR-S2 and PR-S3:
- Full: `./build/bin/test_tidecoin --report_level=detailed`
