PQ Multisig Test Plan (PR Breakdown)
====================================

Goal
----
Add deterministic, repeatable tests that validate PQ multisig behavior across:
- P2WSH and P2SH-wrapped P2WSH
- Single-scheme and mixed-scheme multisig
- Consensus limits and policy/standardness limits

Notes
-----
- "Pubkey hash" outputs are single-sig (P2WPKH/P2SH-P2WPKH), not multisig.
- Multisig tests focus on full pubkeys in witnessScript + script hash outputs.
- Additional tests will cover the “committed pubkey hash” P2WSH template
  (SHA256(TidePubKey) commitments in witnessScript; pubkeys provided in witness).
- All tests must be deterministic: use pq::KeyGenFromSeed with fixed seeds.

PR Checklist
------------

### PR-T1 — Test scaffolding + deterministic key fixtures
- [x] Add test helpers to generate PQ keypairs per scheme from fixed seeds.
- [x] Add helpers to build mixed-scheme pubkey vectors and CHECKMULTISIG scripts.
- [x] Add shared constants for m-of-n scenarios (1-of-1, 2-of-3, 3-of-5, 15-of-15, 20-of-20).
- [x] Add helper to compute witness stacks for CHECKMULTISIG (dummy + sigs + witnessScript).

Touchpoints:
- New or existing unit test helper file (e.g. `src/test/pq_multisig_tests.cpp` or `src/test/multisig_tests.cpp`)
- PQ keygen helpers: `src/pq/pq_api.h` / `src/pq/pqhd_keygen.cpp`

Acceptance:
- Test helpers compile and can derive valid PQ keypairs deterministically.

### PR-T2 — Unit/policy tests (single-scheme P2WSH + P2SH-P2WSH)
- [x] Add unit tests for each scheme: P2WSH m-of-n (1,2,3,15,20) pass.
- [x] Add unit tests for each scheme: P2SH-P2WSH m-of-n (1,2,3,15,20) pass.
- [x] Add negative tests:
      - 21-of-21 rejected (MAX_PUBKEYS_PER_MULTISIG)
      - witnessScript > MAX_SCRIPT_SIZE rejected (consensus)
      - stack item > MAX_SCRIPT_ELEMENT_SIZE rejected (consensus)
      - stack item > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE rejected (policy)

Touchpoints:
- `src/test/pq_multisig_tests.cpp` (new) or `src/test/multisig_tests.cpp` (extend)
- `src/policy/policy.cpp` (IsWitnessStandard) for policy assertions
- `src/script/interpreter.cpp` for consensus error codes

Acceptance:
- `./build/bin/test_tidecoin -t pq_multisig_tests` passes (or relevant test target).

### PR-T3 — Unit/policy tests (mixed-scheme multisig)
- [x] Add mixed-scheme test cases:
      - 2-of-3 (Falcon-512, ML-DSA-44, ML-DSA-87)
      - 3-of-5 (2x Falcon-512 + 2x ML-DSA-65 + 1x Falcon-1024)
      - 20-of-20 mixed (include all schemes)
- [x] Add negative test: wrong-scheme signature for a pubkey fails verification.

Touchpoints:
- `src/test/pq_multisig_tests.cpp` (same test module as PR-T2)

Acceptance:
- Mixed-scheme tests pass for P2WSH and P2SH-P2WSH.

### PR-T4 — Functional/regtest tests (single-scheme)
- [ ] Add functional test `test/functional/pq_multisig.py`.
- [ ] For each scheme, build P2WSH multisig, fund, sign, and mine.
- [ ] For each scheme, build P2SH-P2WSH multisig, fund, sign, and mine.

Gating:
- Ensure auxpow scheme gating is satisfied (set nAuxpowStartHeight low in regtest or mine past it).

Acceptance:
- Functional test passes on regtest.

### PR-T5 — Functional/regtest tests (mixed-scheme)
- [ ] Extend `pq_multisig.py` with mixed-scheme scenarios.
- [ ] Verify mixed-scheme P2WSH + P2SH-P2WSH spends confirm.

Acceptance:
- Mixed-scheme functional scenarios pass.

### PR-T6 — Unit/policy tests (committed pubkey hash template)
- [x] Add helpers to build the “committed pubkey hash” witnessScript:
      - `OP_DUP OP_SHA256 <h_i> OP_EQUALVERIFY OP_CHECKSIG OP_TOALTSTACK` (per slot)
      - Sum results with `OP_FROMALTSTACK OP_ADD ... <m> OP_NUMEQUAL`
- [x] Add unit tests (P2WSH and P2SH-P2WSH) for each scheme:
      - m-of-n scenarios: 1-of-1, 2-of-3, 3-of-5, 15-of-15, 20-of-20.
- [x] Add mixed-scheme committed-hash tests (2-of-3, 3-of-5, 20-of-20).
- [x] Add negative tests:
      - pubkey hash mismatch fails (wrong pubkey for committed hash).
      - invalid signature blob fails (per-slot).

Touchpoints:
- `src/test/pq_multisig_tests.cpp` (extend with new template + cases)
- `src/script/script.h` (opcodes only; no new consensus changes)

Acceptance:
- `./build/bin/test_tidecoin -t pq_multisig_tests` passes with committed-hash cases.

### PR-T7 — Functional/regtest tests (committed pubkey hash template)
- [ ] Extend `test/functional/pq_multisig.py` with committed-hash template spends.
- [ ] Cover single-scheme + mixed-scheme scenarios for P2WSH and P2SH-P2WSH.

Acceptance:
- Functional committed-hash scenarios pass on regtest.

### PR-T8 — Unit tests (negative coverage + PQ_STRICT)
- [x] Add PQ_STRICT coverage:
      - Run core multisig paths with `SCRIPT_VERIFY_PQ_STRICT` enabled.
- [x] Add CHECKMULTISIG negative cases:
      - m-1 signatures (threshold failure).
      - signatures out of pubkey order.
      - signature from non-participant key.
      - wrong sighash types (NONE/SINGLE).
      - m>n, n=0 edge cases.
      - m=0 behavior documented (consensus accepts 0-of-0).
- [x] Add bare multisig policy test (consensus valid, policy reject; reason "scriptpubkey" or "bare-multisig" depending on pubkey standardness).
- [x] Add committed-hash template negative cases:
      - threshold failure (m-1 signatures).
      - wrong order (pubkey/sig pairs swapped).

Touchpoints:
- `src/test/pq_multisig_tests.cpp`

Acceptance:
- `./build/bin/test_tidecoin -t pq_multisig_tests` passes with strict/negative cases.

### PR-T9 — Unit policy/weight tests (large PQ multisig)
- [x] Add standardness check for large PQ multisig transactions:
      - 20-of-20 ML-DSA-87 P2WSH fits under `MAX_STANDARD_TX_WEIGHT`.
      - `IsStandardTx()` returns true for this case.
- [x] Add explicit size/vsize assertions to guard future policy changes.

Touchpoints:
- `src/test/pq_multisig_tests.cpp`
- `src/policy/policy.cpp` (IsStandardTx) via existing helpers.

Acceptance:
- `./build/bin/test_tidecoin -t pq_multisig_tests` passes with weight checks.

Tracking
--------
Mark each PR complete by checking its checklist above. Keep this file updated as the single source of truth for PQ multisig testing progress.
