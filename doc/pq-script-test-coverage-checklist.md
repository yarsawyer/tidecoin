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
- [ ] PR-08: CI and Drift Gates

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

## Cross-PR Acceptance Queries

Use these queries after each PR to verify invariants:

- `rg -n "script_tests\\.json" src/test`
- `rg -n "BIP66|DERSIG|LOW_S|STRICTENC|ECDSA|secp" src/test/script_tests.cpp src/test/transaction_tests.cpp`
- `rg -n "CKey::SIZE != 32" src/test/script_tests.cpp src/test/transaction_tests.cpp`
- `ctest --test-dir build -R "script_tests|transaction_tests|script_assets_tests" --output-on-failure`
- `rg -n "skipping script_assets_test" src/test/CMakeLists.txt src/test/script_assets_tests.cpp`
