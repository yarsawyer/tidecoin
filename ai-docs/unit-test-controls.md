# Unit Test Controls

## Wallet Tests (PQ-heavy)

Wallet-related unit test suites are disabled by default because post-quantum key
generation can dominate runtime and make `test_tidecoin` impractical to run as a
fast smoke test.

Enable wallet suites explicitly:

```bash
TIDECOIN_RUN_WALLET_TESTS=1 ./build/bin/test_tidecoin --run_test=wallet_tests
TIDECOIN_RUN_WALLET_TESTS=1 ./build/bin/test_tidecoin --run_test=coinselector_tests
TIDECOIN_RUN_WALLET_TESTS=1 ./build/bin/test_tidecoin --run_test=psbt_wallet_tests
```

Suites gated behind `TIDECOIN_RUN_WALLET_TESTS`:
- `coinselection_tests`, `coinselector_tests`
- `db_tests`, `walletdb_tests`, `walletload_tests`
- `wallet_tests`, `wallet_transaction_tests`, `wallet_rpc_tests`, `wallet_crypto_tests`
- `spend_tests`, `feebumper_tests`, `group_outputs_tests`, `scriptpubkeyman_tests`, `ismine_tests`, `init_tests`

Implementation notes:
- The gating is enforced centrally in `src/test/main.cpp` by disabling these
  suites at Boost.Test startup (so expensive fixtures don’t run at all).

## Optional Unit Test Data

Some tests may look for optional test vectors via environment variables. For
example `script_assets_tests` will run only if `DIR_UNIT_TEST_DATA` is set and
the expected file exists.

