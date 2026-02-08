# Unit Test Failures Map

## Current status (after fixes)
- Rerun command:
  - `./build/bin/test_tidecoin --report_level=detailed`
- Rerun log:
  - `/tmp/test_tidecoin_unit_full_rerun.log`
- Result:
  - `EXIT_CODE:0`
  - `653 / 716` passed
  - `63 / 716` skipped
  - `0` failed
  - `0` aborted

## Run metadata
- Command:
  - `./build/bin/test_tidecoin --report_level=detailed`
- Full log:
  - `/tmp/test_tidecoin_unit_full.log`
- Binary exit code:
  - `201`

## Top-level summary
- Test module: `Tidecoin Core Test Suite`
- Passed test cases: `643 / 716`
- Failed test cases: `10 / 716`
- Aborted test cases: `5 / 716`
- Failed assertions: `66`

---

## Failing/aborted suites
- `rpc_tests`
- `script_tests`
- `txvalidation_tests`
- `validation_chainstate_tests`
- `validation_chainstatemanager_tests`
- `validation_tests`

---

## Failing/aborted test cases map

### 1) `rpc_tests/help_example` [FAILED]
- Assertions:
  - `5 / 11` passed
  - `6 / 11` failed
- Key failures:
  - `src/test/rpc_tests.cpp:595`
  - Expected help examples with `bitcoin-cli`, actual output contains `tidecoin-cli`.
- Notes:
  - Pure expectation mismatch in test vectors/messages.
- Status:
  - [x] Fixed
- Fix applied:
  - Updated `src/test/rpc_tests.cpp` `HelpExampleCliNamed(...)` expectations from `bitcoin-cli` to `tidecoin-cli`.
- Verification:
  - `./build/bin/test_tidecoin --run_test=rpc_tests/help_example --report_level=detailed`
  - Result: pass (`11 / 11` assertions).

### 2) `script_tests/script_GetScriptAsm` [FAILED]
- Assertions:
  - `14 / 20` passed
  - `6 / 20` failed
- Key failures:
  - `src/test/script_tests.cpp:1298` and following checks.
  - Expected DER-style sighash tags (`[ALL]`, `[NONE]`, etc.) in asm output, actual output shows raw trailing byte in these vectors.
- Notes:
  - This aligns with recent core change to PQ-only signature-sighash decoding in asm.
- Status:
  - [x] Fixed
- Fix applied:
  - Updated legacy DER-tag expectations in `src/test/script_tests.cpp` to assert raw trailing sighash bytes for the DER-shaped vectors when `attempt_sighash_decode=true`.
  - This keeps the test aligned with Tidecoin’s PQ-only sighash-tag decode behavior in `ScriptToAsmStr(...)`.
- Verification:
  - `./build/bin/test_tidecoin --run_test=script_tests/script_GetScriptAsm --report_level=detailed`
  - Result: pass (`20 / 20` assertions).

### 3) `txvalidation_tests/ephemeral_tests` [FAILED]
- Assertions:
  - `26 / 66` passed
  - `40 / 66` failed
- Key failures:
  - `src/test/txvalidation_tests.cpp:181`
  - Repeated failures of:
    - `CheckEphemeralSpends(...)`
    - `child_state.IsValid()`
    - `child_wtxid == Wtxid()` expectations
- Notes:
  - Strongly coupled to dust/ephemeral policy behavior after PQ dust threshold migration.
- Status:
  - [x] Fixed
- Fix applied:
  - Made `src/test/txvalidation_tests.cpp` test builders scheme-aware by parameterizing output value in `make_tx(...)` and `make_ephemeral_tx(...)`.
  - In `ephemeral_tests`, replaced hardcoded `10000` “non-dust” assumption with:
    - `non_dust_output_value = GetDustThreshold(CTxOut{0, CScript() << OP_TRUE}, dustrelay) + 1`.
  - Updated ephemeral test transaction construction to use `non_dust_output_value`, preserving intended behavior (“exactly one dusty output”) under new PQ dust policy.
- Verification:
  - `./build/bin/test_tidecoin --run_test=txvalidation_tests/ephemeral_tests --report_level=detailed`
  - Result: pass (`66 / 66` assertions).

### 4) `validation_chainstate_tests/chainstate_update_tip` [ABORTED]
- Assertions:
  - `3 / 4` passed
  - `1 / 4` failed
- Fatal check:
  - `src/test/validation_chainstate_tests.cpp:94`
  - `CreateAndActivateUTXOSnapshot(... )` failed.
- Status:
  - [x] Fixed
- Root cause:
  - Height-110 regtest `m_assumeutxo_data` entry in `src/kernel/chainparams.cpp` drifted from the deterministic `TestChain100Setup` chain used by snapshot unit tests.
- Fix applied:
  - Restored height-110 AssumeUTXO vector to the deterministic unit-test values:
    - `base_hash=28c79d24...`
    - `txoutset_hash=6cdd7e27...`
- Verification:
  - `./build/bin/test_tidecoin --run_test=validation_chainstate_tests/chainstate_update_tip --report_level=no`
  - Result: pass.

### 5) `validation_chainstatemanager_tests/chainstatemanager_activate_snapshot` [ABORTED]
- Assertions:
  - `114 / 115` passed
  - `1 / 115` failed
- Fatal check:
  - `src/test/validation_chainstatemanager_tests.cpp:266`
  - `CreateAndActivateUTXOSnapshot(this)` failed.
- Status:
  - [x] Fixed
- Root cause:
  - Same height-110 AssumeUTXO vector drift as item 4.
- Fix applied:
  - Same chainparams height-110 vector restoration.
- Verification:
  - `./build/bin/test_tidecoin --run_test=validation_chainstatemanager_tests/chainstatemanager_activate_snapshot --report_level=no`
  - Result: pass.

### 6) `validation_chainstatemanager_tests/chainstatemanager_loadblockindex` [FAILED]
- Assertions:
  - `11 / 17` passed
  - `6 / 17` failed
- Key failures:
  - `src/test/validation_chainstatemanager_tests.cpp:531`
  - `setBlockIndexCandidates` expected non-empty candidates, actual counts are zero.
- Status:
  - [x] Fixed
- Root cause:
  - Snapshot activation precondition failed due mismatched AssumeUTXO vector, cascading into candidate set expectations.
- Fix applied:
  - Same chainparams height-110 vector restoration.
- Verification:
  - `./build/bin/test_tidecoin --run_test=validation_chainstatemanager_tests/chainstatemanager_loadblockindex --report_level=no`
  - Result: pass.

### 7) `validation_chainstatemanager_tests/chainstatemanager_snapshot_init` [ABORTED]
- Assertions:
  - `114 / 115` passed
  - `1 / 115` failed
- Fatal check:
  - `src/test/validation_chainstatemanager_tests.cpp:266`
  - `CreateAndActivateUTXOSnapshot(this)` failed.
- Status:
  - [x] Fixed
- Root cause:
  - Same height-110 AssumeUTXO vector drift as item 4.
- Fix applied:
  - Same chainparams height-110 vector restoration.
- Verification:
  - `./build/bin/test_tidecoin --run_test=validation_chainstatemanager_tests/chainstatemanager_snapshot_init --report_level=no`
  - Result: pass.

### 8) `validation_chainstatemanager_tests/chainstatemanager_snapshot_completion` [ABORTED]
- Assertions:
  - `114 / 115` passed
  - `1 / 115` failed
- Fatal check:
  - `src/test/validation_chainstatemanager_tests.cpp:266`
  - `CreateAndActivateUTXOSnapshot(this)` failed.
- Status:
  - [x] Fixed
- Root cause:
  - Same height-110 AssumeUTXO vector drift as item 4.
- Fix applied:
  - Same chainparams height-110 vector restoration.
- Verification:
  - `./build/bin/test_tidecoin --run_test=validation_chainstatemanager_tests/chainstatemanager_snapshot_completion --report_level=no`
  - Result: pass.

### 9) `validation_chainstatemanager_tests/chainstatemanager_snapshot_completion_hash_mismatch` [ABORTED]
- Assertions:
  - `114 / 115` passed
  - `1 / 115` failed
- Fatal check:
  - `src/test/validation_chainstatemanager_tests.cpp:266`
  - `CreateAndActivateUTXOSnapshot(this)` failed.
- Status:
  - [x] Fixed
- Root cause:
  - Same height-110 AssumeUTXO vector drift as item 4.
- Fix applied:
  - Same chainparams height-110 vector restoration.
- Verification:
  - `./build/bin/test_tidecoin --run_test=validation_chainstatemanager_tests/chainstatemanager_snapshot_completion_hash_mismatch --report_level=no`
  - Result: pass.

### 10) `validation_tests/test_assumeutxo` [FAILED]
- Assertions:
  - `7 / 10` passed
  - `3 / 10` failed
- Key failures:
  - `src/test/validation_tests.cpp:139`
  - `hash_serialized` mismatch against hardcoded expected hash.
  - `m_chain_tx_count` mismatch.
- Status:
  - [x] Fixed
- Root cause:
  - Test expectations and chainparams had diverged from deterministic height-110 snapshot values.
- Fix applied:
  - Restored expected hash/blockhash in `src/test/validation_tests.cpp` to the deterministic vector.
  - Restored matching height-110 vector in `src/kernel/chainparams.cpp`.
- Verification:
  - `./build/bin/test_tidecoin --run_test=validation_tests/test_assumeutxo --report_level=no`
  - Result: pass.

---

## Suggested patch order
1. `rpc_tests/help_example` (low-risk message expectation alignment)
2. `script_tests/script_GetScriptAsm` (align DER-tag expectations with current asm policy)
3. `txvalidation_tests/ephemeral_tests` (reconcile dust/ephemeral assertions with PQ dust policy)
4. AssumeUTXO group:
   - `validation_tests/test_assumeutxo`
   - `validation_chainstate_tests/chainstate_update_tip`
   - `validation_chainstatemanager_tests/*snapshot*`
   - `validation_chainstatemanager_tests/chainstatemanager_loadblockindex`

---

## Progress log template (for each patched test)
- Test case:
- Root cause:
- Files changed:
- Why fix is correct:
- Verification command(s):
- Result:

---

## Wallet-suites rerun (explicitly enabled)
- Date/context:
  - Rerun after confirming wallet suites are intentionally skipped by default unless `TIDECOIN_RUN_WALLET_TESTS=1`.
- Command:
  - `TIDECOIN_RUN_WALLET_TESTS=1 ./build/bin/test_tidecoin --run_test=coinselection_tests,coinselector_tests,db_tests,feebumper_tests,group_outputs_tests,init_tests,ismine_tests,psbt_wallet_tests,scriptpubkeyman_tests,spend_tests,wallet_crypto_tests,wallet_rpc_tests,wallet_tests,wallet_transaction_tests,walletdb_tests,walletload_tests --report_level=detailed --log_level=test_suite`
- Result:
  - `63 / 716` test cases passed (all selected wallet suites)
  - `653 / 716` test cases skipped (non-selected suites disabled by filter)
  - `0` failed
  - `0` aborted
- Notable runtime observation:
  - Several wallet-heavy tests are slow in PQ mode (many cases around `~56-78s` each), but all completed successfully in this run.
- Non-failure note:
  - `walletload_tests/wallet_load_descriptors` reports "did not check any assertions" in this run output; this is informational and did not fail the suite.
