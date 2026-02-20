# Tidecoin PQ Script Coverage Gap Matrix (vs Bitcoin)

## Snapshot (2026-02-20)

- `script_build` vectors:
  - Tidecoin: 141 (`src/test/script_tests.cpp`)
  - Bitcoin: 134 (`/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp`)
- Script JSON fixture size:
  - Tidecoin: 141 (`src/test/data/script_tests_pq.json`)
  - Bitcoin: 1264 (`/home/yaroslav/dev/bitcoin/bitcoin/src/test/data/script_tests.json`)
- Interpreter-surface additions in PQ fixture:
  - 37 dedicated vectors (`PQ interpreter *` comments) covering stack/altstack, flow control, arithmetic/comparison/hash/stack-manip families, and boundary behavior.
- Tidecoin-only additions in PQ fixture:
  - 24 dedicated vectors (5 `OP_SHA512` + 12 witness v1_512 + 4 `CONST_SCRIPTCODE` + 3 `PQ_STRICT`).
- Script assets corpus size:
  - Tidecoin: 375 (`src/test/data/script_assets_test.json`)
  - Flag-set breadth: 15 distinct canonical consensus flag profiles (legacy/witness + NULLDUMMY + CLTV/CSV combinations)

## How Tidecoin Script Tests Run

1. `script_build` (`src/test/script_tests.cpp:401`) builds in-memory vectors with `TestBuilder`, runs each via `DoTest`, and can regenerate JSON via `TIDE_SCRIPT_TESTS_GEN_OUTPUT`.
2. `script_json_test` (`src/test/script_tests.cpp:1041`) replays `script_tests_pq.json` through the same `DoTest` harness.
3. `script_assets_test` (`src/test/script_assets_tests.cpp:145`) loads `script_assets_test.json` objects and validates each success/failure across `ALL_CONSENSUS_FLAGS` subset/superset rules (`src/test/script_assets_tests.cpp:96`).

## Coverage Matrix

| Category | Bitcoin coverage reference | Tidecoin coverage reference | Tidecoin applicability | Status |
|---|---|---|---|---|
| P2PK + P2PKH pass/fail | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:430` | `src/test/script_tests.cpp:411`, `src/test/script_tests.cpp:417` | Keep | Covered |
| P2SH wrapper semantics | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:451` | `src/test/script_tests.cpp:433` | Keep | Covered |
| Multisig semantics | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:468` | `src/test/script_tests.cpp:458`, `src/test/script_tests.cpp:471` | Keep | Covered |
| Sighash mode behavior (`ALL/NONE/SINGLE/ANYONECANPAY`) | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:446` | `src/test/script_tests.cpp:423` | Keep | Covered |
| NULLDUMMY | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:641` | `src/test/script_tests.cpp:457` | Keep | Covered |
| SIGPUSHONLY | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:653` | `src/test/script_tests.cpp:463` | Keep | Covered |
| CLEANSTACK | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:674` | `src/test/script_tests.cpp:469` | Keep | Covered |
| Witness v0 core + mismatch/malleation/unexpected | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:690` | `src/test/script_tests.cpp:696`, `src/test/script_tests.cpp:766`, `src/test/script_tests.cpp:778` | Keep | Covered |
| Witness wrong value / wrong length / future-version discourage | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:739` | `src/test/script_tests.cpp:735`, `src/test/script_tests.cpp:757`, `src/test/script_tests.cpp:748` | Keep | Covered |
| MINIMALDATA | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/data/script_tests.json:2527` | `src/test/script_tests.cpp:616`, `src/test/script_tests.cpp:1139` | Keep | Covered (fixture + unit coverage) |
| CLTV behavior | Bitcoin fixture + unit coverage | `src/test/script_tests.cpp:750`, `src/test/data/script_assets_test.json:2644` | Keep | Covered |
| CSV behavior | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/data/script_tests.json:2524` | `src/test/script_tests.cpp:761`, `src/test/data/script_assets_test.json:2661` | Keep | Covered |
| MINIMALIF behavior | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/data/script_tests.json:2532` | `src/test/script_tests.cpp:649` | Keep (where active) | Covered |
| NULLFAIL behavior | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/data/script_tests.json:2671` | `src/test/script_tests.cpp:673` | Keep (where active) | Covered |
| Stack/altstack manipulation + underflow | Bitcoin interpreter fixture surface | `src/test/script_tests.cpp:502` | Keep | Covered |
| Conditional flow + unbalanced conditional | Bitcoin interpreter fixture surface | `src/test/script_tests.cpp:516` | Keep | Covered |
| Arithmetic/boolean/comparison edges | Bitcoin interpreter fixture surface | `src/test/script_tests.cpp:530` | Keep | Covered |
| Opcode/script-size boundary behavior | Bitcoin interpreter fixture surface | `src/test/script_tests.cpp:573`, `src/test/script_tests.cpp:580` | Keep | Covered |
| Tidecoin-specific `OP_SHA512` | N/A | `src/test/script_tests.cpp:939`, `src/test/script_tests.cpp:1676` | Keep | Covered |
| Tidecoin-specific witness v1_512 / sighash512 policy | N/A | `src/test/script_tests.cpp:959`, `src/test/script_tests.cpp:1752` | Keep | Covered |
| `CONST_SCRIPTCODE` behavior | N/A | `src/test/script_tests.cpp:819` | Keep | Covered |
| `PQ_STRICT` behavior | N/A | `src/test/script_tests.cpp:848` | Keep | Covered |
| ECDSA encoding (`DERSIG/LOW_S/STRICTENC/BIP66`) | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:514` | Removed from Tidecoin | Remove | Not applicable by policy |
| secp witness pubkey type checks | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:775` | Removed from Tidecoin | Remove | Not applicable by policy |
| Taproot script vectors | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/data/script_tests.json:2624` | Removed from Tidecoin | Remove | Not applicable by policy |

## Script Assets Metadata (Current State)

Each `script_assets_test.json` entry carries:

- `tx`: serialized spending transaction
- `prevouts`: serialized prevout outputs for all inputs
- `index`: input index under test
- `flags`: script-verify flags target
- `success` and/or `failure`: `{scriptSig, witness}` expected to pass/fail
- `comment`: generation context (currently mostly spend type + sighash mode)

Current corpus profile (`src/test/data/script_assets_test.json`):

- 375 total entries
- 15 distinct canonical flag sets
- Wallet-driven spend matrix across legacy/p2sh-witness/witness templates with 6 flag profiles per sighash mode
- Deterministic static timelock families expanded to bare/P2SH/P2WSH direct-success CLTV/CSV and CLTV+CSV paths

## Priority Additions (for broad applicable parity)

1. Residual depth follow-ups after PR-11/PR-13 closure:
   - recommended follow-up: deepen NULLDUMMY/SIGPUSHONLY matrix breadth.
2. PR-12 corpus scale-up and minimization is complete (375 entries, 15 canonical flag sets); keep this profile under drift checks.
3. Add a drift gate in PR-08 for required category/tag/flag assertions (with count metadata informational only) so coverage cannot regress.
4. PR-13 scorecard gate is active via `test/lint/lint-pq-script-coverage.py` and CI lint runner wiring.

## Coverage Scorecard Gate

- Enforced checker: `test/lint/lint-pq-script-coverage.py`
- CI integration path: `test/lint/test_runner/src/main.rs` linter `pq_script_coverage`
- Gate dimensions:
  - required script category presence and polarity from `src/test/data/script_tests_pq.json`,
  - required script-assets flag-set and family-tag presence from `src/test/data/script_assets_test.json`,
  - hard-cutover invariants (legacy fixture/term bans and required-path checks).

## Residual Gap Triage (Post PR-13)

### Strong Coverage

- P2SH / witness v0 positive+negative paths.
- Interpreter-surface import set (stack, flow, arithmetic baseline, boundaries).
- MINIMALDATA vector family.
- NULLFAIL vector family.
- `OP_SHA512` enable/disable/discourage/error matrix.

### Adequate But Thin

| Area | Current breadth | Gap |
|---|---|---|
| witness v1_512 | 12 vectors | Sighash matrix now covered; additional negative combinations may still be added |
| CLTV/CSV | 8 `script_build` vectors + expanded script-assets direct-success families | Core behavior is covered in both fixture and corpus paths; deeper combinatorics remain optional |
| Multisig | 7 vectors | Improved (1-of-2 + order failure), but arity/order depth can grow further |
| NULLDUMMY | 2 vectors | Minimal positive/negative pair only |
| SIGPUSHONLY | narrow matrix | Core behavior covered, deeper flag/cartesian matrix absent |

### Missing or Underspecified

No consensus-critical signature differential gaps are currently open; remaining follow-ups are breadth/depth refinements.

### Clarification

- `OP_SHA512` output correctness is already explicitly asserted in unit tests (`src/test/script_tests.cpp:1527`, `src/test/script_tests.cpp:1529`), including exact digest match.
