# Tidecoin PQ Script Coverage Gap Matrix (vs Bitcoin)

## Snapshot (2026-02-21)

- `script_build` vectors:
  - Tidecoin: 162 (`src/test/script_tests.cpp`)
  - Bitcoin: 134 (`/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp`)
- Script JSON fixture size:
  - Tidecoin: 162 (`src/test/data/script_tests_pq.json`)
  - Bitcoin: 1264 (`/home/yaroslav/dev/bitcoin/bitcoin/src/test/data/script_tests.json`)
  - Executable rows (excluding Bitcoin single-line doc rows): Tidecoin 162 vs Bitcoin 1212
- Interpreter-surface additions in PQ fixture:
  - 37 dedicated vectors (`PQ interpreter *` comments) covering stack/altstack, flow control, arithmetic/comparison/hash/stack-manip families, and boundary behavior.
- PR-14 negative-surface additions in PQ fixture:
  - 21 dedicated vectors (`PQ INT-*` comments) covering bad/disabled opcode wrappers, verify-fail wrappers, stack/altstack underflow, and conditional imbalance variants.
- Tidecoin-only additions in PQ fixture:
  - 24 dedicated vectors (5 `OP_SHA512` + 12 witness v1_512 + 4 `CONST_SCRIPTCODE` + 3 `PQ_STRICT`).
- Script assets corpus size:
  - Tidecoin: 375 (`src/test/data/script_assets_test.json`)
  - Flag-set breadth: 15 distinct canonical consensus flag profiles (legacy/witness + NULLDUMMY + CLTV/CSV combinations)

## Quantitative Depth Delta (Fixture-Only)

Method:

- Basis is fixture rows in `script_tests_pq.json` vs `script_tests.json`.
- Bitcoin comparison excludes 52 single-line format/documentation rows.
- Counts below are row-hit counts: a row is counted once per category/token if it contains that term.
- This section is fixture-only; additional Tidecoin depth also exists in `script_assets_test.json` (375) and tx fixtures (50 total).

Applicable category row-hit counts (where Tidecoin policy keeps semantics):

| Category | Tidecoin | Bitcoin | Delta |
|---|---:|---:|---:|
| P2SH | 60 | 913 | -853 |
| WITNESS | 42 | 134 | -92 |
| CLTV | 4 | 5 | -1 |
| CSV | 4 | 11 | -7 |
| MINIMALDATA | 7 | 115 | -108 |
| MINIMALIF | 3 | 46 | -43 |
| NULLFAIL | 5 | 10 | -5 |
| NULLDUMMY | 2 | 6 | -4 |
| SIGPUSHONLY | 5 | 8 | -3 |
| CLEANSTACK | 5 | 19 | -14 |
| CHECKMULTISIG | 11 | 131 | -120 |
| STACK_OP_FAMILY | 19 | 76 | -57 |
| ARITH_OP_FAMILY | 14 | 143 | -129 |
| HASH_OP_FAMILY | 33 | 115 | -82 |
| BAD_OPCODE | 3 | 89 | -86 |
| DISABLED_OPCODE | 3 | 24 | -21 |
| INVALID_STACK_OPERATION | 12 | 91 | -79 |
| UNBALANCED_CONDITIONAL | 4 | 29 | -25 |

Full opcode/token row-hit counts:

| Token | Tidecoin | Bitcoin | Delta |
|---|---:|---:|---:|
| CHECKSIG | 20 | 68 | -48 |
| CHECKMULTISIG | 11 | 99 | -88 |
| CHECKLOCKTIMEVERIFY | 4 | 5 | -1 |
| CHECKSEQUENCEVERIFY | 4 | 11 | -7 |
| CODESEPARATOR | 2 | 1 | +1 |
| IF | 8 | 248 | -240 |
| NOTIF | 1 | 23 | -22 |
| ELSE | 4 | 206 | -202 |
| ENDIF | 8 | 262 | -254 |
| VERIFY | 3 | 30 | -27 |
| 2DROP | 3 | 9 | -6 |
| 2DUP | 2 | 7 | -5 |
| 2OVER | 2 | 5 | -3 |
| 2ROT | 2 | 11 | -9 |
| 2SWAP | 2 | 5 | -3 |
| 3DUP | 2 | 6 | -4 |
| PICK | 2 | 15 | -13 |
| ROLL | 2 | 14 | -12 |
| TOALTSTACK | 1 | 8 | -7 |
| FROMALTSTACK | 3 | 5 | -2 |
| ADD | 2 | 35 | -33 |
| SUB | 1 | 9 | -8 |
| MIN | 1 | 10 | -9 |
| MAX | 1 | 10 | -9 |
| GREATERTHAN | 1 | 11 | -10 |
| LESSTHAN | 1 | 11 | -10 |
| WITHIN | 2 | 15 | -13 |
| ABS | 1 | 7 | -6 |
| NEGATE | 1 | 7 | -6 |
| 1ADD | 1 | 11 | -10 |
| 1SUB | 1 | 7 | -6 |
| BOOLAND | 1 | 15 | -14 |
| BOOLOR | 0 | 15 | -15 |
| HASH160 | 29 | 88 | -59 |
| HASH256 | 1 | 7 | -6 |
| SHA256 | 1 | 8 | -7 |
| SHA1 | 1 | 8 | -7 |
| RIPEMD160 | 1 | 7 | -6 |
| SHA512 | 5 | 0 | +5 |
| BAD_OPCODE | 3 | 89 | -86 |
| DISABLED_OPCODE | 3 | 24 | -21 |
| INVALID_STACK_OPERATION | 12 | 91 | -79 |
| UNBALANCED_CONDITIONAL | 4 | 29 | -25 |

Policy-excluded (intentionally not backfilled in Tidecoin):

| Legacy/Taproot surface | Tidecoin | Bitcoin | Delta |
|---|---:|---:|---:|
| DERSIG | 0 | 56 | -56 |
| LOW_S | 0 | 2 | -2 |
| STRICTENC | 0 | 778 | -778 |
| WITNESS_PUBKEYTYPE | 0 | 20 | -20 |
| TAPROOT/TAPSCRIPT markers | 0 | 4 | -4 |

## Why Tidecoin Depth Is Dramatically Lower

1. Hard-cutover policy removes the largest historical matrix families.
   Bitcoin spends a large fraction of fixture depth on legacy ECDSA/secp policy (`STRICTENC`, `DERSIG`, `LOW_S`, pubkey-type checks). Tidecoin deliberately excludes these vectors.
2. Bitcoin's file is an accreted historical corpus.
   `script_tests.json` includes many generations of edge-case permutations and regression expansions accumulated over years and softfork eras.
3. Tidecoin spreads depth across multiple fixtures, not one giant script fixture.
   Tidecoin carries 162 script fixture rows plus 375 script-assets rows plus 50 tx rows; Bitcoin's 1264 number refers to one file only.
4. Tidecoin currently prioritizes representative consensus vectors over full cartesian expansion.
   Coverage scorecard guarantees category/polarity presence, but many families still have fewer permutations than Bitcoin.
5. Some generic interpreter negative-surface families remain thin.
   `BAD_OPCODE`, `DISABLED_OPCODE`, deep conditional matrices, and larger stack/arithmetic cartesian sets are still low in Tidecoin fixture depth.

Highest ROI depth expansion targets (applicable to Tidecoin policy):

1. Deepen `BAD_OPCODE` and `DISABLED_OPCODE` matrices beyond the PR-14 baseline (`3` wrapper cells each).
2. Expand conditional-flow combinatorics (`IF/NOTIF/ELSE/ENDIF/VERIFY`) with additional invalid-stack and branch-structure negatives.
3. Expand multisig depth beyond current 1-of-2 / 2-of-3 baseline (additional arities, signature placement/order variants).
4. Expand MINIMALDATA/MINIMALIF/NULLDUMMY/SIGPUSHONLY/CLEANSTACK cartesian flag interactions.
5. Expand CLTV/CSV success/failure permutations (sequence/locktime combinations) beyond current representative cases.

## Planned Expansion Program (PR-14 .. PR-17)

Cell IDs below are normative for the next expansion phase and are intended to be lint-enforced in PR-17.

Implementation status (2026-02-21):

- PR-14 complete (interpreter negative-surface cells landed and validated).
- PR-15 complete (multisig/policy cartesian cells landed and validated).
- PR-16 complete (timelock/witness matrix cells landed and validated).
- PR-17 complete (manifest-backed required-cell scorecard gate landed and validated).

| PR | Scope | Required cell families (exact IDs) |
|---|---|---|
| PR-14 | Interpreter negative-surface depth | `INT-BADOP-BARE`, `INT-BADOP-P2SH`, `INT-BADOP-P2WSH`, `INT-DISABLED-BARE`, `INT-DISABLED-P2SH`, `INT-DISABLED-P2WSH`, `INT-VERIFY-FAIL-BARE`, `INT-VERIFY-FAIL-P2SH`, `INT-VERIFY-FAIL-P2WSH`, `INT-STACK-UFLOW-*`, `INT-COND-UNBAL-*` |
| PR-15 | Multisig/policy cartesian depth | `MSIG-ARITY-*`, `MSIG-ORDER-WRONG`, `MSIG-MISSING-SIG`, `MSIG-WRONG-SIG`, `MSIG-WRONG-KEY`, `MSIG-EXTRA-SIG`, `MSIG-NULLDUMMY-*`, `MSIG-NULLFAIL-*`, `MSIG-CLEANSTACK-*`, `MSIG-SIGPUSHONLY-*` |
| PR-16 | Timelock + witness matrix depth | `TIME-CLTV-*`, `TIME-CSV-*`, `TIME-CLTVCSV-*`, `WIT-V0-*`, `WIT-V1512-*` |
| PR-17 | Scorecard gate v2 | `test/lint/pq_script_required_cells.json` + `test/lint/pq_script_assets_required_cells.json` required-cell manifests enforced by `test/lint/lint-pq-script-coverage.py` |

Required-cell wildcard expansions (must be materialized in fixtures/comments):

- `INT-STACK-UFLOW-*`:
- `INT-STACK-UFLOW-2DROP`, `INT-STACK-UFLOW-2DUP`, `INT-STACK-UFLOW-2OVER`, `INT-STACK-UFLOW-2ROT`, `INT-STACK-UFLOW-2SWAP`, `INT-STACK-UFLOW-3DUP`, `INT-STACK-UFLOW-PICK`, `INT-STACK-UFLOW-ROLL`, `INT-ALT-UFLOW-FROMALTSTACK`
- `INT-COND-UNBAL-*`:
- `INT-COND-UNBAL-IF-NO-ENDIF`, `INT-COND-UNBAL-ELSE-WO-IF`, `INT-COND-UNBAL-ENDIF-WO-IF`
- `MSIG-ARITY-*`:
- `MSIG-ARITY-1OF1-OK`, `MSIG-ARITY-1OF2-OK`, `MSIG-ARITY-1OF3-OK`, `MSIG-ARITY-2OF2-OK`, `MSIG-ARITY-2OF3-OK`, `MSIG-ARITY-3OF5-OK`
- `MSIG-NULLDUMMY-*`:
- `MSIG-NULLDUMMY-ENFORCED`, `MSIG-NULLDUMMY-NOT-ENFORCED`
- `MSIG-NULLFAIL-*`:
- `MSIG-NULLFAIL-ENFORCED`, `MSIG-NULLFAIL-NOT-ENFORCED`
- `MSIG-CLEANSTACK-*`:
- `MSIG-CLEANSTACK-ENFORCED`, `MSIG-CLEANSTACK-NOT-ENFORCED`
- `MSIG-SIGPUSHONLY-*`:
- `MSIG-SIGPUSHONLY-ENFORCED`, `MSIG-SIGPUSHONLY-NOT-ENFORCED`
- `TIME-CLTV-*`:
- `TIME-CLTV-EMPTY-STACK`, `TIME-CLTV-NEGATIVE`, `TIME-CLTV-UNSAT`, `TIME-CLTV-SAT-BARE`, `TIME-CLTV-SAT-P2SH`, `TIME-CLTV-SAT-P2WSH`
- `TIME-CSV-*`:
- `TIME-CSV-EMPTY-STACK`, `TIME-CSV-NEGATIVE`, `TIME-CSV-UNSAT`, `TIME-CSV-SAT-BARE`, `TIME-CSV-SAT-P2SH`, `TIME-CSV-SAT-P2WSH`
- `TIME-CLTVCSV-*`:
- `TIME-CLTVCSV-COMBINED-SAT`, `TIME-CLTVCSV-COMBINED-UNSAT`
- `WIT-V0-*`:
- `WIT-V0-MISMATCH`, `WIT-V0-MALLEATED`, `WIT-V0-UNEXPECTED`, `WIT-V0-WRONG-VALUE`, `WIT-V0-WRONG-LEN`
- `WIT-V1512-*`:
- `WIT-V1512-SIGHASH-ALL`, `WIT-V1512-SIGHASH-NONE`, `WIT-V1512-SIGHASH-SINGLE`, `WIT-V1512-SIGHASH-ALL-ACP`, `WIT-V1512-SIGHASH-NONE-ACP`, `WIT-V1512-SIGHASH-SINGLE-ACP`, `WIT-V1512-ZERO-SIGHASH-REJECT`, `WIT-V1512-WRONG-KEY`, `WIT-V1512-MISMATCH`, `WIT-V1512-MALLEATED`, `WIT-V1512-UNEXPECTED`, `WIT-V1512-WRONG-VALUE`, `WIT-V1512-WRONG-LEN`, `WIT-V1512-DISCOURAGED`

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
