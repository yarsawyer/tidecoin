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
- [x] PR-08: CI and Drift Gates
- [x] PR-09: Bitcoin Interpreter-Surface Breadth Import (Non-ECDSA)
- [x] PR-10: Tidecoin PQ-Only Surface Expansion
- [x] PR-11: Residual Script Gap Closure (Closed with Deferred Residuals)
- [x] PR-12: Script-Assets Corpus Scale-Up and Re-Minimization
- [x] PR-13: Coverage Scorecard and Lock-In

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
- Add regeneration documentation and deterministic checks (hash + required profile/category checks).

Acceptance criteria:

- CI fails on fixture drift or missing corpus in required profiles.
- Developers can regenerate all PQ fixtures using documented steps.
- Implementation completion (2026-02-20):
  - Added `test/lint/lint-pq-script-coverage.py` to enforce PQ-only fixture/corpus invariants.
  - Added required category/polarity checks for `script_tests_pq.json`.
  - Added required flag-set/family checks for `script_assets_test.json`.
  - Added hard-cutover guardrails (`script_tests.json` ban, legacy-term ban in script/tx tests, no required-path script-assets skip marker).
  - Wired linter into CI lint runner as `pq_script_coverage` via `test/lint/test_runner/src/main.rs`.

### Workstream 8: Bitcoin Interpreter-Surface Breadth Import (Non-ECDSA)

Tasks:

- Systematically port/adapt Bitcoin `script_tests` vectors that do not depend on ECDSA/secp/Taproot.
- Prioritize interpreter-surface breadth:
  - stack/altstack manipulation and underflow/invalid-stack paths,
  - conditional flow and unbalanced conditional paths,
  - arithmetic/boolean/compare edge cases,
  - pushdata and minimal-encoding related script engine paths,
  - script size/op count/sigop boundary behavior where applicable.
- Keep all imported vectors PQ-policy compliant (no legacy key/signature semantics).

Acceptance criteria:

- `script_tests_pq.json` contains a significantly wider interpreter surface than current Tidecoin baseline.
- Imported vectors are categorized and traceable to source semantics.

### Workstream 9: Tidecoin PQ-Only Surface Expansion

Tasks:

- Add vectors not present in Bitcoin scope:
  - broader `OP_SHA512` behavior matrix (empty/max/oversize/flag interactions),
  - broader witness v1_512 and policy/sighash edge behavior,
  - cross-scheme signing matrix where consensus-relevant.
- Add negative and positive cases per category with explicit comments.

Acceptance criteria:

- Tidecoin-only script behavior has broad dedicated vector coverage, not just spot checks.
- Completed on 2026-02-20 with regenerated PQ fixture including dedicated `OP_SHA512` and witness v1_512 vector families.

### Workstream 10: Residual Script Gap Closure

Tasks:

- Close highest-priority residual script-test gaps first:
  - witness v1_512 sighash matrix (`NONE`, `SINGLE`, `ALL|ANYONECANPAY`, `NONE|ANYONECANPAY`, `SINGLE|ANYONECANPAY`),
  - explicit `CONST_SCRIPTCODE` vectors,
  - explicit `PQ_STRICT` differential vectors (strict vs non-strict behavior where meaningful),
  - CLTV/CSV success-path vectors in `script_build` (not only failure-path vectors),
  - low-risk interpreter breadth additions (hash opcodes, stack-manip opcode families, arithmetic completeness),
  - multisig depth expansion beyond current 2-of-3 baseline.
- Regenerate `script_tests_pq.json`.

Acceptance criteria:

- Residual script-test gaps identified after PR-10 are closed with explicit positive/negative vectors where applicable.
- Implementation progress (2026-02-20):
  - added v1_512 sighash matrix vectors,
  - added `CONST_SCRIPTCODE` vector family,
  - expanded interpreter depth (hash/stack/arithmetic families),
  - expanded multisig depth,
  - regenerated `script_tests_pq.json` to 141 vectors.
- Workstream 10 closure decision (2026-02-20):
  - closed as PASS,
  - `PQ_STRICT` strict-vs-nonstrict differential vectors are explicitly covered in `script_build`/`script_tests_pq.json`,
  - CLTV/CSV direct-success schema/path enhancement is covered by the expanded static timelock corpus.

### Workstream 11: Script-Assets Corpus Scale-Up and Re-Minimization

Tasks:

- Expand dumper generation surface (additional script templates and flag regimes) while preserving determinism.
- Regenerate larger raw corpus and run minimizer merge flow.
- Commit canonical minimized corpus with updated metadata.

Acceptance criteria:

- `script_assets_test.json` grows beyond current baseline with demonstrably wider flag/script coverage.
- End-to-end regeneration remains reproducible.
- Implementation completion (2026-02-20):
  - dumper expanded with wallet flag-profile matrix plus static bare/P2SH/P2WSH CLTV/CSV direct-success families,
  - raw corpus regenerated from 20 dump runs (2,380 candidates) and minimized via `script_assets_test_minimizer`,
  - committed corpus expanded from 139 to 375 entries and from 5 to 15 distinct canonical flag sets,
  - validation passed: `ctest --test-dir build -R script_assets_tests --output-on-failure` and cross-suite script/tx/assets run.

### Workstream 12: Coverage Scorecard and Lock-In

Tasks:

- Maintain a machine-checkable category scorecard (required categories + required polarity coverage).
- Maintain a machine-checkable corpus profile scorecard (required flag sets + required script-family tags).
- Add regression checks in CI for required category/tag/flag presence and legacy-ban invariants.
- Record fixture/corpus counts as informational drift metadata, not hard pass/fail breadth gates.

Acceptance criteria:

- Coverage breadth cannot silently regress.
- Required category/tag/flag checks fail deterministically when violated.
- Implementation completion (2026-02-20):
  - Added machine-checkable scorecard linter: `test/lint/lint-pq-script-coverage.py`.
  - Enforced required script category + polarity presence from `script_tests_pq.json`.
  - Enforced required script-assets flag sets and family tags from `script_assets_test.json`.
  - Enforced hard-cutover invariants (`script_tests.json` ban, legacy term ban in script/tx tests, no script-assets required-path skip marker).
  - Wired into CI lint path via `test/lint/test_runner/src/main.rs` as `pq_script_coverage`.

## Strategic Decision (Locked)

For `script_assets_test.json` (PR-07), Tidecoin will use:

- In-repo committed corpus artifact.
- Required execution in CI (no optional skip path for required profiles).
- Deterministic drift gate (hash + profile metadata) enforced in CI.

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
7. Workstream 8
8. Workstream 9
9. Workstream 10
10. Workstream 11
11. Workstream 7
12. Workstream 12

## Post-PR-13 Triage Notes

- `OP_SHA512` output correctness is already explicitly covered in unit tests (`src/test/script_tests.cpp:1527`, `src/test/script_tests.cpp:1529`).
- Residual risk concentration is primarily in:
  - depth (not presence) for selected matrix families (NULLDUMMY/SIGPUSHONLY/multisig arity).

## Definition of Done

- Tidecoin test tree has no secp/ECDSA compatibility fixture path.
- PQ fixtures and corpus provide broad, consensus-relevant coverage.
- Regeneration workflow is documented and reproducible.
- CI enforces the new PQ-only coverage model.
- Coverage scorecard required categories/tags/flags are met and enforced in CI.
