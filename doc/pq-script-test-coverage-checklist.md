# Tidecoin PQ Script Coverage Migration Checklist

This checklist decomposes the PQ-only migration into small PRs with exact file edits.

Locked decision:

- `script_assets_test.json` is committed in-repo and required in CI (no external qa-assets dependency for required coverage).

Reference matrix:

- `doc/pq-script-coverage-gap-matrix.md`

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

## PR-01: Repository Policy and Tracking

Goal:

- Freeze scope and make execution auditable.

Files to edit:

- `doc/pq-script-test-coverage-plan.md`
- `doc/pq-script-test-coverage-checklist.md` (this file)

Edits:

- Add links between plan and checklist.
- Add explicit statement: no ECDSA/secp fixture paths in tests.

Validation:

- `rg -n "ECDSA|secp|legacy fixture" doc/pq-script-test-coverage-plan.md doc/pq-script-test-coverage-checklist.md`

Exit criteria:

- Team has one plan doc and one executable checklist doc in-tree.

## PR-02: Hard Cutover for `script_tests` Fixtures

Goal:

- Remove legacy `script_tests.json` fixture path entirely.

Files to edit:

- `src/test/CMakeLists.txt`
- `src/test/script_tests.cpp`
- `src/test/data/script_tests.json` (delete)

Edits:

- In `src/test/CMakeLists.txt`, remove `data/script_tests.json` from `target_json_data_sources(test_bitcoin ...)`.
- In `src/test/script_tests.cpp`:
- Remove `#include <test/data/script_tests.json.h>`.
- Remove `pq_mode` branch selection for script fixture; keep only PQ fixture.
- Remove comments that describe upstream ECDSA vectors as active path.
- Delete `src/test/data/script_tests.json`.

Validation:

- `rg -n "script_tests\\.json" src/test | cat`
- `cmake -B build && cmake --build build -j$(nproc)`
- `ctest --test-dir build -R script_tests --output-on-failure`

Exit criteria:

- No reference to `script_tests.json` remains under `src/test`.

## PR-03: Remove ECDSA Branch and Comments from `script_build`

Goal:

- Remove all ECDSA-only `TestBuilder` cases and comments from script unit tests.

Files to edit:

- `src/test/script_tests.cpp`

Edits:

- Delete the non-PQ `const KeyData keys;` auto-vector block in `BOOST_AUTO_TEST_CASE(script_build)`.
- Keep/expand only PQ-native case construction in `script_build`.
- Remove ECDSA-specific wording from comments and failure messages (`DERSIG`, `LOW_S`, `STRICTENC`, `BIP66`, "legacy deterministic fixtures").

Validation:

- `rg -n "BIP66|DERSIG|LOW_S|STRICTENC|ECDSA|legacy deterministic" src/test/script_tests.cpp`
- `ctest --test-dir build -R script_tests --output-on-failure`

Exit criteria:

- `script_build` contains only PQ-native vector generation.

## PR-04: Expand `script_tests_pq.json` to Broad Coverage

Goal:

- Replace current 8-case PQ vectors with broad, category-complete vectors.

Files to edit:

- `src/test/script_tests.cpp`
- `src/test/data/script_tests_pq.json`
- `doc/pq-script-test-coverage-plan.md`

Edits:

- Expand PQ `TestBuilder` set to cover applicable categories:
- P2PK/P2PKH positive and negative.
- P2SH wrapper semantics.
- Multisig edge cases.
- Sig-hash mode behavior where applicable.
- NULLDUMMY/SIGPUSHONLY/CLEANSTACK.
- Witness mismatch/malleation/value/program-length cases.
- Keep comments category-oriented and non-legacy.
- Regenerate `src/test/data/script_tests_pq.json` from expanded builder output.
- Regeneration command: `TIDE_SCRIPT_TESTS_GEN_OUTPUT=src/test/data/script_tests_pq.json build/bin/test_tidecoin --run_test=script_tests/script_build --catch_system_errors=no --color_output=no`

Validation:

- `ctest --test-dir build -R script_tests --output-on-failure`
- `rg -n "PQ " src/test/data/script_tests_pq.json | head`
- `python3 - <<'PY'\nimport json;d=json.load(open('src/test/data/script_tests_pq.json'));print(len(d))\nPY`

Exit criteria:

- `script_tests_pq.json` coverage is broad and not minimal.

## PR-05: Replace Minimal PQ Fallback in `transaction_tests`

Goal:

- Replace current tiny PQ sanity checks with broad PQ tx vectors.

Files to edit:

- `src/test/transaction_tests.cpp`
- `src/test/CMakeLists.txt`
- `src/test/data/tx_valid.json` and `src/test/data/tx_invalid.json` (or new PQ-specific equivalents)

Edits:

- Remove `if (CKey::SIZE != 32) { ... return; }` minimal fallback in `tx_valid` and `tx_invalid`.
- Use PQ-native vector fixtures with the existing validation harness (`CheckTxScripts`).
- If introducing new names (`tx_valid_pq.json`, `tx_invalid_pq.json`), update includes and CMake sources accordingly.
- Remove ECDSA-specific explanatory comments.

Validation:

- `ctest --test-dir build -R transaction_tests --output-on-failure`
- `rg -n "ECDSA-specific|CKey::SIZE != 32" src/test/transaction_tests.cpp`

Exit criteria:

- `tx_valid`/`tx_invalid` are broad PQ vector driven tests, not minimal fallback.

## PR-06: Add PQ Functional Dumper for Script-Assets Corpus

Goal:

- Add reproducible raw corpus generator (`--dumptests`) in Tidecoin functional tests.

Files to edit:

- `test/functional/feature_pq_script_assets.py` (new)
- `test/functional/test_runner.py` (if adding to default or extended suite)
- `src/test/fuzz/script_assets_test_minimizer.cpp` (comment update only, optional)

Edits:

- Implement functional generator that emits script-assets JSON object lines compatible with `script_assets_tests.cpp`:
- fields: `tx`, `prevouts`, `index`, `flags`, `comment`, optional `final`, optional `success`, optional `failure`.
- Implement `--dumptests` and `TEST_DUMP_DIR` file writing compatible with minimizer merge flow.
- Update minimizer comments to point to Tidecoin generator script.

Validation:

- `TEST_DUMP_DIR=/tmp/tide_script_dump test/functional/feature_pq_script_assets.py --dumptests`
- `find /tmp/tide_script_dump -type f | head`
- Spot-check dumped JSON objects parse.

Exit criteria:

- Raw corpus generation is reproducible and schema-compatible.

## PR-07: Generate and Commit `script_assets_test.json`

Goal:

- Produce broad minimized corpus and make tests use it in CI-required flows.

Files to edit:

- `src/test/fuzz/script_assets_test_minimizer.cpp` (if needed)
- `src/test/script_assets_tests.cpp` (skip policy if changed)
- `doc/` regeneration docs
- `src/test/data/script_assets_test.json` (new committed corpus)
- optional metadata file for integrity checks (recommended)

Edits:

- Generate raw corpus using PR-06 dumper.
- Example raw generation:
- `rm -rf /tmp/tide_script_dump /tmp/tide_script_dump_min && mkdir -p /tmp/tide_script_dump /tmp/tide_script_dump_min`
- `for N in $(seq 1 20); do TEST_DUMP_DIR=/tmp/tide_script_dump test/functional/feature_pq_script_assets.py --dumptests; done`
- Minimize:
- `CC=clang CXX=clang++ cmake -B build-fuzz-libfuzzer -DBUILD_FOR_FUZZING=ON -DBUILD_GUI=OFF -DBUILD_TESTS=OFF -DENABLE_WALLET=ON -DSANITIZERS=fuzzer`
- `cmake --build build-fuzz-libfuzzer -j$(nproc) --target fuzz`
- `FUZZ=script_assets_test_minimizer build-fuzz-libfuzzer/bin/fuzz -merge=1 -use_value_profile=1 /tmp/tide_script_dump_min /tmp/tide_script_dump`
- Build JSON:
- `python3 -c "import glob,json;fs=sorted(glob.glob('/tmp/tide_script_dump_min/*'));es=[json.loads(open(p).read().rstrip(',\\n')) for p in fs];json.dump(es,open('src/test/data/script_assets_test.json','w'),indent=2,sort_keys=True);open('src/test/data/script_assets_test.json','a').write('\\n')"`
- Use canonical in-tree storage path (`src/test/data/script_assets_test.json`) and adjust loader/docs accordingly.
- Remove optional-skip behavior for required CI profiles.

Validation:

- Run `script_assets_test` with corpus path configured.
- Ensure non-empty, stable parse, and pass across reruns.

Exit criteria:

- Broad corpus is committed in-tree and consumed by required test path.

## PR-08: CI and Drift Gates

Goal:

- Ensure PQ-only fixture/corpus invariants do not regress.

Files to edit:

- CI config files (`.github/workflows/*` and/or project CI scripts)
- `doc/` regeneration docs
- optional metadata checker script in `contrib/devtools/` or `test/lint/`

Edits:

- Add CI jobs/steps for:
- `script_tests`
- `transaction_tests`
- `script_assets_test` with corpus present
- Add drift checks:
- case-count/hash checks for committed generated fixtures/corpus
- fail CI if legacy fixture references are reintroduced.
- fail CI if `script_assets_test` corpus is missing or skipped in required profiles.

Validation:

- CI green on intended branches.
- Intentional fixture drift causes deterministic CI failure.

Exit criteria:

- PQ-only test model is continuously enforced.
- Implementation completion (2026-02-20):
  - Added `test/lint/lint-pq-script-coverage.py` for machine-checkable PQ drift gates.
  - Wired lint into `test/lint/test_runner/src/main.rs` as `pq_script_coverage`.
  - Enforced fixture/corpus scorecard checks and hard-cutover invariants in required lint path.

## PR-09: Bitcoin Interpreter-Surface Breadth Import (Non-ECDSA)

Goal:

- Expand Tidecoin `script_tests_pq` breadth toward Bitcoin interpreter surface, excluding all ECDSA/secp/Taproot-only vectors.

Files to edit:

- `src/test/script_tests.cpp`
- `src/test/data/script_tests_pq.json`
- `doc/pq-script-coverage-gap-matrix.md`

Edits:

- Port/adapt non-crypto interpreter vectors from Bitcoin categories:
- stack/altstack manipulation and invalid-stack paths
- conditional flow / unbalanced conditionals
- arithmetic/boolean/comparison edges
- pushdata/minimal-encoding script engine paths
- boundary behavior where consensus-applicable
- Preserve hard-cutover policy (no legacy key/signature formats).
- Regenerate `script_tests_pq.json` using:
- `TIDE_SCRIPT_TESTS_GEN_OUTPUT=src/test/data/script_tests_pq.json build/bin/test_tidecoin --run_test=script_tests/script_build --catch_system_errors=no --color_output=no`

Validation:

- `build/bin/test_tidecoin --run_test=script_tests/script_json_test --catch_system_errors=no --color_output=no`
- `ctest --test-dir build -R script_tests --output-on-failure`
- `python3 - <<'PY'\nimport json;print(len(json.load(open('src/test/data/script_tests_pq.json'))))\nPY`

Exit criteria:

- `script_tests_pq.json` surface is substantially wider than baseline with required interpreter categories covered.

## PR-10: Tidecoin PQ-Only Surface Expansion

Goal:

- Add broad test coverage for Tidecoin-specific script semantics that Bitcoin does not cover.

Files to edit:

- `src/test/script_tests.cpp`
- `src/test/data/script_tests_pq.json`
- `doc/pq-script-coverage-gap-matrix.md`

Edits:

- Expand PQ-only vectors for:
- `OP_SHA512` behavior matrix (flag interactions and boundary elements)
- witness v1_512 policy/sighash edge behavior
- PQ-specific signing/sighash edge patterns where consensus-relevant
- Ensure each PQ-only category has positive and negative vectors.
- Regenerate `script_tests_pq.json`.

Validation:

- `TIDE_SCRIPT_TESTS_GEN_OUTPUT=src/test/data/script_tests_pq.json build/bin/test_tidecoin --run_test=script_tests/script_build --catch_system_errors=no --color_output=no`
- `build/bin/test_tidecoin --run_test=script_tests/script_json_test --catch_system_errors=no --color_output=no`
- `ctest --test-dir build -R script_tests --output-on-failure`
- `ctest --test-dir build -R transaction_tests --output-on-failure`
- `rg -n "OP_SHA512|v1_512|PQ " src/test/script_tests.cpp src/test/data/script_tests_pq.json`

Exit criteria:

- PQ-only categories are broad and explicit, not spot checks.
- Completed 2026-02-20: 5 `OP_SHA512` vectors and 7 witness v1_512 vectors regenerated into `script_tests_pq.json`.

## PR-11: Residual Script Gap Closure

Goal:

- Close residual script coverage gaps identified after PR-10.

Files to edit:

- `src/test/script_tests.cpp`
- `src/test/data/script_tests_pq.json`
- `doc/pq-script-coverage-gap-matrix.md`

Edits:

- Add missing/thin script vectors:
- witness v1_512 sighash variants (`NONE`, `SINGLE`, `ALL|ANYONECANPAY`, `NONE|ANYONECANPAY`, `SINGLE|ANYONECANPAY`)
- explicit `CONST_SCRIPTCODE` vectors
- explicit `PQ_STRICT` differential vectors
- CLTV/CSV success-path vectors in `script_build`
- targeted interpreter depth additions (hash opcode family, stack-manip families, arithmetic completeness, multisig depth)
- Regenerate `script_tests_pq.json`.

Validation:

- `TIDE_SCRIPT_TESTS_GEN_OUTPUT=src/test/data/script_tests_pq.json build/bin/test_tidecoin --run_test=script_tests/script_build --catch_system_errors=no --color_output=no`
- `build/bin/test_tidecoin --run_test=script_tests/script_json_test --catch_system_errors=no --color_output=no`
- `ctest --test-dir build -R script_tests --output-on-failure`

Exit criteria:

- Residual script gaps from post-PR-10 triage are closed with explicit vectors.
- Implementation pass completed on 2026-02-20:
- Added v1_512 sighash matrix vectors, `CONST_SCRIPTCODE` vectors, interpreter depth vectors (hash/stack/arithmetic), and multisig depth vectors; regenerated fixture now has 141 entries.
- Closure decision: PASS.
- `PQ_STRICT` strict-fail/non-strict-pass differential is now explicitly covered in `script_build` and `script_tests_pq.json`.
- CLTV/CSV direct-success schema/path enhancement beyond guarded-branch fixture success was addressed by expanded static bare/P2SH/P2WSH timelock corpus families.

## PR-12: Script-Assets Corpus Scale-Up and Re-Minimization

Goal:

- Increase corpus breadth and regenerate canonical minimized script-assets corpus.

Files to edit:

- `test/functional/feature_pq_script_assets.py`
- `src/test/fuzz/script_assets_test_minimizer.cpp` (if needed)
- `src/test/data/script_assets_test.json`
- `doc/pq-script-coverage-gap-matrix.md`

Edits:

- Expand dumper templates and flag combinations.
- Generate larger raw corpus and run minimizer merge.
- Replace committed corpus with new canonical minimized output.

Validation:

- `TEST_DUMP_DIR=/tmp/tide_script_dump python3 test/functional/feature_pq_script_assets.py --dumptests`
- `ctest --test-dir build -R script_assets_tests --output-on-failure`
- `python3 - <<'PY'\nimport json;print(len(json.load(open('src/test/data/script_assets_test.json'))))\nPY`

Exit criteria:

- Corpus breadth is materially expanded with required flag/script-family coverage.
- Implementation completion (2026-02-20):
- Expanded generator with flag-profile matrix across wallet spends plus static direct-success CLTV/CSV families in bare/P2SH/P2WSH forms.
- Regenerated and minimized corpus from 20 dump runs (`2,380` raw entries) to `375` committed entries.
- Flag profile breadth expanded from `5` to `15` distinct canonical flag sets.
- Validation passed:
- `ctest --test-dir build -R script_assets_tests --output-on-failure`
- `ctest --test-dir build -R "script_tests|transaction_tests|script_assets_tests" --output-on-failure`

## PR-13: Coverage Scorecard and Lock-In

Goal:

- Make breadth measurable and non-regressing.

Files to edit:

- `doc/pq-script-coverage-gap-matrix.md`
- CI config files (`.github/workflows/*` and/or project CI scripts)
- optional checker script under `test/lint/` or `contrib/devtools/`

Edits:

- Add category scorecard with required category list and required positive/negative coverage.
- Add corpus profile scorecard with required flag sets and required script-family tags.
- Keep vector/corpus counts as informational drift metadata only (not hard breadth pass/fail gates).
- Add CI checks for category/tag presence and legacy-ban invariants.

Validation:

- CI green with expected fixtures.
- Intentional required-category/tag/flag regressions fail deterministically.

Exit criteria:

- Coverage breadth is locked by deterministic CI gates.
- Implementation completion (2026-02-20):
- Added deterministic scorecard checker: `test/lint/lint-pq-script-coverage.py`.
- Added lint runner integration: `pq_script_coverage` in `test/lint/test_runner/src/main.rs` (CI lint job executes this via test runner).
- Scorecard gates now enforce:
- required script category presence + required positive/negative polarity,
- required script-assets flag-set presence and comment-family tags,
- hard-cutover invariants (`script_tests.json` absence, script/tx legacy-term ban, no required-path script-assets skip marker).
- Validation:
- `python3 test/lint/lint-pq-script-coverage.py`
- `(cd test/lint/test_runner && RUST_BACKTRACE=1 cargo run -- --lint=pq_script_coverage)`

## Cross-PR Acceptance Queries

Use these queries after each PR to verify invariants:

- `rg -n "script_tests\\.json" src/test`
- `rg -n "BIP66|DERSIG|LOW_S|STRICTENC|ECDSA|secp" src/test/script_tests.cpp src/test/transaction_tests.cpp`
- `rg -n "CKey::SIZE != 32" src/test/script_tests.cpp src/test/transaction_tests.cpp`
- `ctest --test-dir build -R "script_tests|transaction_tests|script_assets_tests" --output-on-failure`
- `rg -n "skipping script_assets_test" src/test/CMakeLists.txt src/test/script_assets_tests.cpp`
