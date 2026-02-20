# Tidecoin PQ Script Test Coverage Plan

## Objective

Migrate Tidecoin script/tx test coverage to a hard post-quantum-only model:

- No secp256k1/ECDSA backward compatibility in tests.
- No legacy fixture dependency (`script_tests.json`) in Tidecoin.
- Full consensus-relevant coverage for Tidecoin script behavior.
- Broad corpus/vector coverage comparable in breadth to Bitcoin where semantics apply.

Execution checklist: `doc/pq-script-test-coverage-checklist.md`
Coverage gap matrix: `doc/pq-script-coverage-gap-matrix.md`

## PR Status

- [x] PR-01: Repository Policy and Tracking
- [x] PR-02: Hard Cutover for `script_tests` Fixtures
- [x] PR-03: Remove ECDSA Branch and Comments from `script_build`
- [x] PR-04: Expand `script_tests_pq.json` to Broad Coverage
- [x] PR-05: Replace Minimal PQ Fallback in `transaction_tests`
- [x] PR-06: Add PQ Functional Dumper for Script-Assets Corpus
- [x] PR-07: Generate and Commit `script_assets_test.json`
- [ ] PR-08: CI and Drift Gates

## Policy (Non-Negotiable)

- Hard cutover only: no compatibility layer for legacy keys/signatures.
- Keep consensus semantics, not legacy cryptographic encoding behavior.
- Remove ECDSA-only vectors/comments to eliminate review noise.
- Keep PQ test assets self-contained in this repository (no external qa-assets dependency for required coverage).

## Scope

In scope:

- `src/test/script_tests.cpp`
- `src/test/transaction_tests.cpp`
- `src/test/script_assets_tests.cpp`
- `src/test/fuzz/script_assets_test_minimizer.cpp`
- `src/test/CMakeLists.txt`
- `src/test/data/*` (script/tx fixtures)
- `test/functional/*` (new PQ dumptests producer)

Out of scope:

- Any runtime consensus migration logic for legacy signatures.
- Any secp/ECDSA reintroduction.

## Coverage Matrix (Keep vs Remove)

Keep (PQ-native vectors required):

- P2PK/P2PKH success/failure
- P2SH wrapping semantics
- Multisig semantics (ordering, arity, missing sigs, bad sigs)
- Sighash mode behavior (`ALL/NONE/SINGLE/ANYONECANPAY`) as applicable
- NULLDUMMY, SIGPUSHONLY, CLEANSTACK, MINIMALDATA, MINIMALIF, NULLFAIL (where active)
- CLTV/CSV behavior
- Witness behavior (mismatch/malleation/wrong value/non-empty scriptSig/etc.)
- General script engine behavior (pushdata, find/delete, valid ops, stack behavior)
- Tidecoin-specific behavior (`PQ_STRICT`, `OP_SHA512`, witness v1_512 policy/sighash tests)
- Script-assets corpus coverage across flag combinations
- Broad tx-valid/tx-invalid style vector coverage, PQ-native

Remove (not applicable after cutover):

- DER/BIP66 signature encoding vectors
- LOW_S vectors
- STRICTENC/secp pubkey-format vectors
- ECDSA-specific comments and branches
- Legacy fixture dependency on `script_tests.json`

## Work Plan

### Workstream 1: Remove Legacy Fixture and Branching

Tasks:

- Remove legacy `script_tests.json` usage from test build inputs.
- Remove legacy selection logic in `script_tests.cpp`; use PQ vectors only.
- Remove legacy fixture file from Tidecoin test data.

Acceptance criteria:

- No include/reference to `script_tests.json` in Tidecoin unit tests/CMake.
- PQ fixture is the only script JSON fixture consumed by `script_tests`.

### Workstream 2: Expand `script_tests_pq.json` Coverage

Tasks:

- Replace current minimal PQ auto-vectors with broad PQ-native set covering all matrix KEEP categories.
- Keep comments category-focused and non-legacy.
- Ensure `script_build` and `script_json_test` remain aligned on expected fixtures.
- Regeneration command: `TIDE_SCRIPT_TESTS_GEN_OUTPUT=src/test/data/script_tests_pq.json build/bin/test_tidecoin --run_test=script_tests/script_build --catch_system_errors=no --color_output=no`

Acceptance criteria:

- PQ vector count is substantially expanded (target: broad category parity with applicable Bitcoin `script_build` semantics).
- Every KEEP category has explicit positive and negative cases.

### Workstream 3: Remove ECDSA Noise from Unit Test Source

Tasks:

- Remove ECDSA-only `TestBuilder` cases and comments from `script_tests.cpp`.
- Replace any remaining legacy terminology in comments/messages.

Acceptance criteria:

- No BIP66/DERSIG/LOW_S/STRICTENC legacy-specific commentary or cases remain in Tidecoin script tests.
- Test output/messages are PQ- and consensus-semantics-focused.

### Workstream 4: Build PQ Dumptests Producer for Script Assets Corpus

Tasks:

- Add a Tidecoin functional generator (`--dumptests`) that emits script-assets entries in the same schema used by `script_assets_test`.
- Ensure generated cases cover Tidecoin-relevant script/flag spaces.

Acceptance criteria:

- A reproducible command exists to produce raw corpus entries into `TEST_DUMP_DIR`.
- Output schema is consumable by `script_assets_test_minimizer`.

### Workstream 5: Corpus Minimization and Fixture Pipeline

Tasks:

- Run `script_assets_test_minimizer` merge flow on generated raw corpus.
- Produce canonical `script_assets_test.json`.
- Commit canonical corpus in-tree and load it from repository test data.
- Document end-to-end regeneration commands in repository docs.

Acceptance criteria:

- Fresh corpus can be generated and minimized from scratch with documented commands.
- `script_assets_test` runs against the committed in-tree corpus by default.

### Workstream 6: Broaden PQ `tx_valid` / `tx_invalid` Coverage

Tasks:

- Replace current minimal PQ sanity fallback in `transaction_tests.cpp` with broad PQ-native vectors.
- Preserve consensus-focused validation behavior checks (flags, supersets/subsets where applicable).

Acceptance criteria:

- PQ tx fixtures contain broad positive/negative coverage.
- Tests no longer rely on legacy ECDSA fixture semantics.

### Workstream 7: CI and Reproducibility Gates

Tasks:

- Add/adjust CI path to exercise:
  - expanded PQ script vectors,
  - PQ tx vectors,
  - script-assets corpus-backed tests.
- Add regeneration documentation and deterministic checks (case count + hash recommended).

Acceptance criteria:

- CI fails on fixture drift or missing corpus in required profiles.
- Developers can regenerate all PQ fixtures using documented steps.

## Strategic Decision (Locked)

For `script_assets_test.json` (PR-07), Tidecoin will use:

- In-repo committed corpus artifact.
- Required execution in CI (no optional skip path for required profiles).
- Deterministic drift gate (case count + hash metadata) enforced in CI.

Rationale:

- Hard-cutover PQ policy requires deterministic always-on coverage.
- Avoids external network/asset dependency and silent skip regressions.

## Execution Order

1. Workstream 1
2. Workstream 3
3. Workstream 2
4. Workstream 4
5. Workstream 5
6. Workstream 6
7. Workstream 7

## Definition of Done

- Tidecoin test tree has no secp/ECDSA compatibility fixture path.
- PQ fixtures and corpus provide broad, consensus-relevant coverage.
- Regeneration workflow is documented and reproducible.
- CI enforces the new PQ-only coverage model.
