# Tidecoin PQ Script Coverage Gap Matrix (vs Bitcoin)

## Snapshot (2026-02-20)

- `script_build` vectors:
  - Tidecoin: 50 (`src/test/script_tests.cpp`)
  - Bitcoin: 134 (`/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp`)
- Script JSON fixture size:
  - Tidecoin: 50 (`src/test/data/script_tests_pq.json`)
  - Bitcoin: 1264 (`/home/yaroslav/dev/bitcoin/bitcoin/src/test/data/script_tests.json`)
- Script assets corpus size:
  - Tidecoin: 136 (`src/test/data/script_assets_test.json`)
  - Flags present: `PQ_STRICT` and `P2SH,WITNESS,PQ_STRICT` only

## How Tidecoin Script Tests Run

1. `script_build` (`src/test/script_tests.cpp:384`) builds in-memory vectors with `TestBuilder`, runs each via `DoTest`, and can regenerate JSON via `TIDE_SCRIPT_TESTS_GEN_OUTPUT`.
2. `script_json_test` (`src/test/script_tests.cpp:593`) replays `script_tests_pq.json` through the same `DoTest` harness.
3. `script_assets_test` (`src/test/script_assets_tests.cpp:145`) loads `script_assets_test.json` objects and validates each success/failure across `ALL_CONSENSUS_FLAGS` subset/superset rules (`src/test/script_assets_tests.cpp:96`).

## Coverage Matrix

| Category | Bitcoin coverage reference | Tidecoin coverage reference | Tidecoin applicability | Status |
|---|---|---|---|---|
| P2PK + P2PKH pass/fail | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:430` | `src/test/script_tests.cpp:409`, `src/test/script_tests.cpp:417` | Keep | Covered |
| P2SH wrapper semantics | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:451` | `src/test/script_tests.cpp:433` | Keep | Covered |
| Multisig semantics | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:468` | `src/test/script_tests.cpp:445`, `src/test/script_tests.cpp:730`, `src/test/script_tests.cpp:752` | Keep | Covered |
| Sighash mode behavior (`ALL/NONE/SINGLE/ANYONECANPAY`) | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:446` | `src/test/script_tests.cpp:423` | Keep | Covered |
| NULLDUMMY | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:641` | `src/test/script_tests.cpp:453` | Keep | Covered |
| SIGPUSHONLY | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:653` | `src/test/script_tests.cpp:459` | Keep | Covered |
| CLEANSTACK | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:674` | `src/test/script_tests.cpp:465` | Keep | Covered |
| Witness v0 core + mismatch/malleation/unexpected | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:690` | `src/test/script_tests.cpp:478`, `src/test/script_tests.cpp:550`, `src/test/script_tests.cpp:563` | Keep | Covered |
| Witness wrong value / wrong length / future-version discourage | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/script_tests.cpp:739` | `src/test/script_tests.cpp:518`, `src/test/script_tests.cpp:540`, `src/test/script_tests.cpp:531` | Keep | Covered |
| MINIMALDATA | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/data/script_tests.json:2527` | `src/test/script_tests.cpp:1036` | Keep | Partial (unit coverage exists; fixture/corpus coverage absent) |
| CLTV behavior | Bitcoin fixture + unit coverage | `src/test/script_tests.cpp:684` | Keep | Partial (truncated-stack only; no broad vector set) |
| CSV behavior | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/data/script_tests.json:2524` | No `CHECKSEQUENCEVERIFY` vectors in `script_tests_pq.json` or `script_assets_test.json` | Keep | Missing |
| MINIMALIF behavior | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/data/script_tests.json:2532` | No `MINIMALIF` vectors in `script_tests_pq.json` or `script_assets_test.json` | Keep (where active) | Missing |
| NULLFAIL behavior | `/home/yaroslav/dev/bitcoin/bitcoin/src/test/data/script_tests.json:2671` | No `NULLFAIL` vectors in `script_tests_pq.json` or `script_assets_test.json` | Keep (where active) | Missing |
| Tidecoin-specific `OP_SHA512` | N/A | `src/test/script_tests.cpp:1228` | Keep | Covered |
| Tidecoin-specific witness v1_512 / sighash512 policy | N/A | `src/test/script_tests.cpp:1270`, `src/test/script_tests.cpp:1304` | Keep | Covered |
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

- 136 total entries
- 82 legacy spend paths (`PQ_STRICT`)
- 54 witness spend paths (`P2SH,WITNESS,PQ_STRICT`)
- Broad sighash combinations are present, but flag-space breadth is still narrow.

## Priority Additions (for broad applicable parity)

1. Add explicit CSV vectors to `script_tests_pq.json` (positive + negative + minimal encoding edge cases).
2. Add explicit CLTV vectors beyond truncated-stack (`NEGATIVE_LOCKTIME`, `UNSATISFIED_LOCKTIME`, satisfied path).
3. Add MINIMALIF vectors for witness and P2SH-witness contexts.
4. Add NULLFAIL vectors for PQ signatures in multisig and singlesig failure paths.
5. Expand `script_assets_test.json` generation to include additional flag sets (at minimum combinations with `CHECKLOCKTIMEVERIFY`, `CHECKSEQUENCEVERIFY`, and where meaningful `MINIMALIF`/`MINIMALDATA`/`NULLFAIL`).
6. Add a drift gate in PR-08 for both vector count and category-presence assertions so these categories cannot regress.
