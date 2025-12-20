# Taproot Removal Plan and Progress

## Overview
This document tracks the detailed plan and progress for removing Taproot
(BIP340/341/342) and tapscript support from this codebase.

## Status Legend
- TODO: not started
- IN-PROGRESS: work underway
- DONE: completed
- BLOCKED: waiting on decision/input

## Decisions (Track Here)
- Taproot removal is immediate (no activation height; no backward compatibility).
- Keep or remove secp256k1 schnorr module: TODO
- Descriptor wallet support scope after removal: TODO

## Detailed Plan and Checklist

### 1) Consensus and deployments
- DONE Remove DEPLOYMENT_TAPROOT from consensus params
  - Files: `src/consensus/params.h`
- DONE Remove taproot deployment settings from chainparams
  - Files: `src/kernel/chainparams.cpp`
- DONE Remove taproot softfork status reporting
  - Files: `src/rpc/blockchain.cpp`
- DONE Verify no references to DEPLOYMENT_TAPROOT remain

### 2) Script and consensus validation
- DONE Remove tapscript script-version handling and validation rules
  - Files: `src/script/interpreter.cpp`, `src/script/interpreter.h`,
    `src/script/script_error.cpp`
- DONE Remove taproot output type and solver mappings
  - Files: `src/script/solver.cpp`, `src/script/solver.h`
- DONE Remove taproot sighash caching paths and schnorr verification call sites
  - Files: `src/script/sigcache.cpp`, `src/script/sign.cpp`
- DONE Remove taproot tree builder / control block logic
  - Files: `src/script/interpreter.h`, `src/script/signingprovider.*`

### 3) Addressing, output types, and key handling
- DONE Remove P2TR output type handling and Bech32m paths
  - Files: `src/outputtype.cpp`, `src/key_io.cpp`, `src/outputtype.h`
- DONE Remove x-only pubkey and schnorr helpers now that taproot is gone
  - Files: `src/key.h`, `src/key.cpp`, `src/pubkey.h`, `src/pubkey.cpp`,
    `src/test/key_tests.cpp`, `src/test/compress_tests.cpp`

### 4) PSBT and signing
- DONE Remove PSBT taproot fields (parse/serialize) and taproot signing data paths
  - Files: `src/psbt.h`, `src/psbt.cpp`, `src/script/sign.h`, `src/script/sign.cpp`

### 5) Wallet and UI
- DONE Remove taproot-enabled wallet checks and bech32m UI option
  - Files: `src/interfaces/wallet.h`, `src/wallet/interfaces.cpp`, `src/qt/receivecoinsdialog.cpp`
- DONE Remove taproot address generation and descriptor support
  - Files: `src/qt/receivecoinsdialog.cpp`, `doc/descriptors.md`

### 6) RPC and CLI surface area
- DONE Remove taproot fields from RPC results/help
  - Files: `src/rpc/rawtransaction.cpp`
- DONE Remove taproot from softfork listing
  - Files: `src/rpc/blockchain.cpp`

### 7) Tests and test framework
- DONE Remove taproot functional tests
  - Files: `test/functional/feature_taproot.py`, `test/functional/wallet_taproot.py`,
    `test/functional/rpc_psbt.py`, `test/functional/rpc_decodescript.py`,
    `test/functional/wallet_migration.py`, `test/functional/wallet_backwards_compatibility.py`,
    `test/functional/wallet_miniscript.py`, `test/functional/test_runner.py`
- DONE Remove taproot helpers from test framework utilities
  - Files: `test/functional/test_framework/segwit_addr.py`,
    `test/functional/test_framework/script_util.py`
- DONE Remove taproot unit tests and vectors
  - Files: `src/test/script_tests.cpp`, `src/test/script_standard_tests.cpp`,
    `src/test/miniscript_tests.cpp`, `src/test/data/script_tests.json`

### 8) Benchmarks
- DONE Remove taproot benchmarks
  - Files: `src/bench/sign_transaction.cpp`, `src/bench/connectblock.cpp`

### 9) secp256k1 schnorr module (decision-dependent)
- BLOCKED Decide if schnorr module is retained for non-taproot use
  - If removing: `src/secp256k1/src/modules/schnorrsig/*`, `src/secp256k1/src/tests.c`

### 10) Documentation and release notes
- DONE Remove/update taproot references in docs (leave historical release notes)
  - Files: `doc/descriptors.md`, `doc/bips.md`, `doc/man/*.1`, `share/examples/bitcoin.conf`

### 11) Build and verification
- TODO Ensure no leftover includes or link refs to removed taproot code
- TODO Run unit + functional tests for script, wallet, and RPC surfaces

## Progress Log
- 2025-12-19: Removed taproot deployment entries and softfork reporting; cleared chainparams taproot exception.
- 2025-12-19: Disabled taproot witness validation path; removed taproot policy limits; removed taproot output type mapping in solver.
- 2025-12-19: Removed taproot/tapscript verification flags, errors, and schnorr validation scaffolding from script interpreter.
- 2025-12-19: Removed schnorr signature creation/caching and taproot signing paths from script signing code.
- 2025-12-19: Removed taproot builders/providers and related key lookup helpers from signing provider code.
- 2025-12-19: Removed taproot address types (P2TR, P2A, witness unknown), bech32m output type, and related wallet/UI hooks.
- 2025-12-19: Removed taproot PSBT fields and RPC exposure; pruned taproot-related unit/functional tests and benchmarks.
- 2025-12-20: Removed segwit v1+ test data and anchor cases; restricted segwit test utilities to v0; updated docs and wallet migration expectations.
- 2025-12-20: Removed segwit v1+ key_io valid vectors, aligned bech32 error expectations, simplified segwit version functional coverage, and pruned taproot PSBT invalid vectors/testgen inputs.
- 2025-12-20: Removed MuSig2 PSBT fields, signing-provider hooks, and decodepsbt RPC output; dropped MuSig2 tests/data and musig build sources.
- 2025-12-20: Removed x-only pubkey and schnorr helpers (CKey/CPubKey) plus related unit tests.
