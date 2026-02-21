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
- [x] PR-14: Interpreter Negative-Surface Matrix Expansion
- [x] PR-15: Multisig and Policy Cartesian Expansion
- [x] PR-16: Timelock and Witness Matrix Expansion
- [x] PR-17: Cell-Based Scorecard Gate v2

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

### Workstream 13: Interpreter Negative-Surface Matrix Expansion

Tasks:

- Add explicit matrix-cell vectors in `script_build` + fixture using stable cell IDs in comments.
- Required cells:
  - `INT-BADOP-BARE`, `INT-BADOP-P2SH`, `INT-BADOP-P2WSH`
  - `INT-DISABLED-BARE`, `INT-DISABLED-P2SH`, `INT-DISABLED-P2WSH`
  - `INT-VERIFY-FAIL-BARE`, `INT-VERIFY-FAIL-P2SH`, `INT-VERIFY-FAIL-P2WSH`
  - `INT-STACK-UFLOW-2DROP`, `INT-STACK-UFLOW-2DUP`, `INT-STACK-UFLOW-2OVER`, `INT-STACK-UFLOW-2ROT`, `INT-STACK-UFLOW-2SWAP`, `INT-STACK-UFLOW-3DUP`, `INT-STACK-UFLOW-PICK`, `INT-STACK-UFLOW-ROLL`, `INT-ALT-UFLOW-FROMALTSTACK`
  - `INT-COND-UNBAL-IF-NO-ENDIF`, `INT-COND-UNBAL-ELSE-WO-IF`, `INT-COND-UNBAL-ENDIF-WO-IF`
- Keep all vectors PQ-policy compliant and wrapper-balanced across bare/P2SH/P2WSH where applicable.

Acceptance criteria:

- Every required cell ID appears in `src/test/data/script_tests_pq.json` and in `script_build` comments.
- Expected error class matches cell intent (`BAD_OPCODE`, `DISABLED_OPCODE`, `VERIFY`, `INVALID_STACK_OPERATION`, `INVALID_ALTSTACK_OPERATION`, `UNBALANCED_CONDITIONAL`).
- Implementation completion (2026-02-21):
  - Added 21 PR-14 matrix-cell vectors (`INT-*`) to `script_build` in `src/test/script_tests.cpp`.
  - Regenerated `src/test/data/script_tests_pq.json` (`141` -> `162` vectors).
  - Validation passed:
    - `build/bin/test_tidecoin --run_test=script_tests/script_build --catch_system_errors=no --color_output=no`
    - `build/bin/test_tidecoin --run_test=script_tests/script_json_test --catch_system_errors=no --color_output=no`
    - `ctest --test-dir build -R script_tests --output-on-failure`

### Workstream 14: Multisig and Policy Cartesian Expansion

Tasks:

- Expand multisig arity/order/missing-signature matrix with stable cell IDs.
- Required cells:
  - `MSIG-ARITY-1OF1-OK`, `MSIG-ARITY-1OF2-OK`, `MSIG-ARITY-1OF3-OK`, `MSIG-ARITY-2OF2-OK`, `MSIG-ARITY-2OF3-OK`, `MSIG-ARITY-3OF5-OK`
  - `MSIG-ORDER-WRONG`, `MSIG-MISSING-SIG`, `MSIG-WRONG-SIG`, `MSIG-WRONG-KEY`, `MSIG-EXTRA-SIG`
  - `MSIG-NULLDUMMY-ENFORCED`, `MSIG-NULLDUMMY-NOT-ENFORCED`
  - `MSIG-NULLFAIL-ENFORCED`, `MSIG-NULLFAIL-NOT-ENFORCED`
  - `MSIG-CLEANSTACK-ENFORCED`, `MSIG-CLEANSTACK-NOT-ENFORCED`
  - `MSIG-SIGPUSHONLY-ENFORCED`, `MSIG-SIGPUSHONLY-NOT-ENFORCED`
- Ensure wrappers are represented: bare, P2SH, and witness path where applicable.

Acceptance criteria:

- All required cell IDs exist with positive and negative polarity where defined.
- No ECDSA/secp/Taproot vectors are introduced while increasing multisig depth.
- Implementation completion (2026-02-21):
  - Added PR-15 matrix-cell vectors in `src/test/script_tests.cpp`:
    - arity: `MSIG-ARITY-1OF1-OK`, `MSIG-ARITY-1OF2-OK`, `MSIG-ARITY-1OF3-OK`, `MSIG-ARITY-2OF2-OK`, `MSIG-ARITY-2OF3-OK`, `MSIG-ARITY-3OF5-OK`
    - ordering and failure: `MSIG-ORDER-WRONG`, `MSIG-MISSING-SIG`, `MSIG-WRONG-SIG`, `MSIG-WRONG-KEY`, `MSIG-EXTRA-SIG`
    - policy: `MSIG-NULLDUMMY-*`, `MSIG-NULLFAIL-*`, `MSIG-CLEANSTACK-*`, `MSIG-SIGPUSHONLY-*`
  - Regenerated `src/test/data/script_tests_pq.json` (still `162` vectors after PR-14 + PR-15 consolidation).
  - Wrapper representation present across bare, `P2SH`, and witness (`MSIG-ARITY-2OF2-OK` via `P2WSH`).
  - Validation passed:
    - `build/bin/test_tidecoin --run_test=script_tests/script_build --catch_system_errors=no --color_output=no`
    - `build/bin/test_tidecoin --run_test=script_tests/script_json_test --catch_system_errors=no --color_output=no`
    - `ctest --test-dir build -R script_tests --output-on-failure`

### Workstream 15: Timelock and Witness Matrix Expansion

Tasks:

- Expand CLTV/CSV and witness matrix depth with stable cell IDs.
- Required timelock cells:
  - `TIME-CLTV-EMPTY-STACK`, `TIME-CLTV-NEGATIVE`, `TIME-CLTV-UNSAT`, `TIME-CLTV-SAT-BARE`, `TIME-CLTV-SAT-P2SH`, `TIME-CLTV-SAT-P2WSH`
  - `TIME-CSV-EMPTY-STACK`, `TIME-CSV-NEGATIVE`, `TIME-CSV-UNSAT`, `TIME-CSV-SAT-BARE`, `TIME-CSV-SAT-P2SH`, `TIME-CSV-SAT-P2WSH`
  - `TIME-CLTVCSV-COMBINED-SAT`, `TIME-CLTVCSV-COMBINED-UNSAT`
- Required witness-policy cells:
  - `WIT-V0-MISMATCH`, `WIT-V0-MALLEATED`, `WIT-V0-UNEXPECTED`, `WIT-V0-WRONG-VALUE`, `WIT-V0-WRONG-LEN`
  - `WIT-V1512-SIGHASH-ALL`, `WIT-V1512-SIGHASH-NONE`, `WIT-V1512-SIGHASH-SINGLE`, `WIT-V1512-SIGHASH-ALL-ACP`, `WIT-V1512-SIGHASH-NONE-ACP`, `WIT-V1512-SIGHASH-SINGLE-ACP`
  - `WIT-V1512-ZERO-SIGHASH-REJECT`, `WIT-V1512-WRONG-KEY`, `WIT-V1512-MISMATCH`, `WIT-V1512-MALLEATED`, `WIT-V1512-UNEXPECTED`, `WIT-V1512-WRONG-VALUE`, `WIT-V1512-WRONG-LEN`, `WIT-V1512-DISCOURAGED`
- Add matching script-assets entries for direct tx-field timelock-satisfied paths where schema-dependent.

Acceptance criteria:

- Timelock satisfied and unsatisfied behaviors are covered across bare/P2SH/P2WSH.
- v1_512 matrix has all six sighash modes plus required negative cells.
- Implementation completion (2026-02-21):
  - Added all required `TIME-*` and `WIT-*` cell IDs in `src/test/script_tests.cpp`.
  - Added timelock SAT wrapper cells for bare/P2SH/P2WSH using guarded-path vectors compatible with the fixed JSON tx schema.
  - Added missing v1_512 witness negatives: `WIT-V1512-MISMATCH`, `WIT-V1512-MALLEATED`, `WIT-V1512-UNEXPECTED`.
  - Regenerated `src/test/data/script_tests_pq.json` (`168` -> `177` vectors).
  - Validation passed:
    - `build/bin/test_tidecoin --run_test=script_tests/script_build --catch_system_errors=no --color_output=false`
    - `build/bin/test_tidecoin --run_test=script_tests/script_json_test --catch_system_errors=no --color_output=false`
    - `python3 test/lint/lint-pq-script-coverage.py`
    - `ctest --test-dir build -R "script_tests|script_assets_tests|transaction_tests|miniscript_tests|wallet_transaction_tests" --output-on-failure`

### Workstream 16: Cell-Based Scorecard Gate v2

Tasks:

- Add machine-readable required-cell manifests:
  - `test/lint/pq_script_required_cells.json`
  - `test/lint/pq_script_assets_required_cells.json`
- Extend `test/lint/lint-pq-script-coverage.py` to enforce required cell IDs and polarity per family.
- Wire checks into lint runner/CI as required gate.
- Keep fixture/corpus counts informational only; pass/fail must be semantic cell presence.

Acceptance criteria:

- CI fails deterministically when a required cell ID is removed or polarity is broken.
- CI passes when vectors are regenerated without semantic coverage regression.
- Implementation completion (2026-02-21):
  - Added machine-readable required-cell manifests:
    - `test/lint/pq_script_required_cells.json`
    - `test/lint/pq_script_assets_required_cells.json`
  - Extended `test/lint/lint-pq-script-coverage.py` to enforce:
    - required script cell IDs (`73`) with per-cell polarity checks,
    - required script family polarity checks (`17` families),
    - required script-assets cell IDs (`14`) and required flag sets (`15`),
    - existing hard-cutover invariants and canonical flag-order checks.
  - Documented the manifest-backed gate in `test/lint/README.md` (explicit path; not root `README.md`).
  - Lint runner integration remains active via `pq_script_coverage` in `test/lint/test_runner/src/main.rs`.
  - Validation passed:
    - `python3 test/lint/lint-pq-script-coverage.py`
    - `(cd test/lint/test_runner && RUST_BACKTRACE=1 cargo run -- --lint=pq_script_coverage)`
    - Negative test: injected a temporary nonexistent required cell ID (`INT-DOES-NOT-EXIST`) and verified deterministic lint failure.

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
13. Workstream 13
14. Workstream 14
15. Workstream 15
16. Workstream 16

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
