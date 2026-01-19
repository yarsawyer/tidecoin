# OP_SHA512 + PQ-Native Address (Post-Auxpow) Plan — Clean Rewrite

This plan replaces earlier drafts and aligns with the current Tidecoin codebase.
Goal: introduce a **post-auxpow** address type that provides **~256-bit PQ
security** by committing to **64-byte SHA-512** hashes, and add an
`OP_SHA512` opcode for script-level use. No code changes in this document.

## 0. Decisions (Frozen for Implementation)

1) **Address commitment size**: 64 bytes (full SHA-512).
   - We do **not** support a 32-byte truncation for this address type.
   - Reason: 32 bytes only yields ~128-bit PQ security (same as SHA-256).

2) **Address construction**: **Witness v1** program with 64-byte payload.
   - Program = `SHA512(witnessScript)` (scripthash-only; no keyhash type).
   - Encoding uses **Bech32m** (v1+ rules), **new PQ HRP** introduced in this upgrade.
   - RPC/Qt exposes a new address_type label: `bech32pq` (v1 scripthash).
   - Post-auxpow: v1 program length must be exactly 64 bytes; other lengths are invalid.

3) **Consensus gating**: feature activates at `nAuxpowStartHeight`.
   - Pre-auxpow (consensus): v1 witness programs are **accepted as anyone-can-spend**,
     matching Bitcoin’s softfork behavior (no v1 enforcement).
   - Pre-auxpow (policy/mempool/wallet): **reject creation of v1 outputs** to avoid footguns.
     This is enforced in mempool accept (height-aware policy gate), not in consensus.
     `IsStandard()` / `IsStandardTx()` remain height-agnostic; the gate lives in
     mempool acceptance (Bitcoin-style for height-aware policy).

4) **OP_SHA512 opcode**: **mandatory** for committed-hash multisig templates.
   - It must be **gated by height**.
   - Opcode value must be within `MAX_OPCODE` (currently `OP_NOP10` / 0xb9).
   - **Chosen opcode**: repurpose `OP_NOP4` (`0xb3`) as `OP_SHA512` post-auxpow.

5) **SigVersion + sighash**: **new v1_512 path with 64-byte SHA-512 sighash**.
   - Introduce `SigVersion::WITNESS_V1_512`.
   - Add a 64-byte sighash pipeline (SHA-512 based) for v1 outputs.
   - Witness v0 remains 32-byte SHA-256 (`SigVersion::WITNESS_V0`).

## 1. High-Level Design

### 1.1 New PQ-native address (P2WSH512-only, v1)

- ScriptPubKey format: `OP_1 <64-byte program>`
- Program = `SHA512(witnessScript)`
- Witness stack: `<arg1> ... <argN> <witnessScript>` (witnessScript is top item)
- Verify path:
  1. `SHA512(witnessScript)` equals program
  2. Execute `witnessScript` under `SigVersion::WITNESS_V1_512`

Single-sig is expressed as a script:
```
<pubkey> OP_CHECKSIG
```
Witness stack:
```
<sig> <witnessScript>
```

**Failure cases (consensus)**
- Reject if witness program length is not exactly 64 bytes.
- Reject if witness stack is empty or does not end with `witnessScript`.
- Reject if `SHA512(witnessScript) != program`.

This mirrors P2WSH, but with SHA-512 and witness v1.

### 1.2 OP_SHA512 opcode (script-level)

Purpose: allow script-level SHA-512 commitments in non-witness scripts or
P2WSH templates (e.g., committed-key multisig). This is **required** for the
committed-hash multisig template we plan to support, even though the new
address type itself does not require it.

If enabled:
- `OP_SHA512` pops 1 item and pushes its 64-byte SHA-512 hash.
- Only valid after auxpow activation (flag-gated).
- Fails if stack is empty.
- Input size is still bounded by `MAX_SCRIPT_ELEMENT_SIZE` (consensus).

### 1.3 Sighash v1_512 (64-byte)

For **full 256-bit PQ security**, v1_512 signatures must hash a 64-byte
message. This requires a **parallel 64-byte sighash path**, not reuse of the
existing 32-byte `SignatureHash`.

Design constraints:
- v1_512 sighash must be **SHA-512 based** (tagged single SHA-512).
- v0 (and BASE) continue using 32-byte SHA-256 sighash.
- SigVersion cleanly separates v0 vs v1_512 rules.
- Introduce `uint512` (like `uint256`) for type-safe 64-byte hashes.

Proposed construction (BIP143-style structure, SHA-512):
- `hashPrevouts_512`, `hashSequence_512`, `hashOutputs_512` computed with SHA-512.
- Final sighash = `SHA512(taghash || taghash || preimage)` where
  `taghash = SHA512("TidecoinSighashV1_512")`.
- This mirrors BIP340’s tagged hash format exactly (SHA-512 instead of SHA-256).
- Note: cache `taghash` (static) to avoid recomputing it per signature, as done
  by `TaggedHash(...)` in `src/hash.{h,cpp}`.

**Preimage layout (exact order)**
- version (4 bytes)
- hashPrevouts_512 (64 bytes)
- hashSequence_512 (64 bytes)
- outpoint (32-byte txid + 4-byte vout)
- scriptCode (varint length + script bytes; for v1_512 this is `witnessScript`)
- amount (8 bytes)
- sequence (4 bytes)
- hashOutputs_512 (64 bytes)
- locktime (4 bytes)
- sighash_type (4 bytes)

**SIGHASH_DEFAULT**
- SIGHASH_DEFAULT (0x00) is **not** valid for v1_512; require explicit type
  (SIGHASH_ALL/NONE/SINGLE plus flags as applicable).

## 2. Code Touchpoints (Exact Files)

### 2.1 Consensus + Script Engine

**Witness v1 support (scripthash-only)**
- `src/script/script.cpp`
  - `CScript::IsWitnessProgram` currently allows 2–40 bytes only.
  - Update to permit 64 bytes **for v1 only**.
- `src/script/interpreter.cpp`
  - `VerifyWitnessProgram` currently rejects `witversion != 0`.
  - Add v1 path:
    - Validate 64-byte program
    - Check `SHA512(witnessScript)` vs program
    - Execute `witnessScript` with `SigVersion::WITNESS_V1_512`
- `src/script/interpreter.h`
  - Add `SCRIPT_VERIFY_WITNESS_V1_512` flag
  - Add `SigVersion::WITNESS_V1_512`
- `src/validation.cpp`
  - Set `SCRIPT_VERIFY_WITNESS_V1_512` at/after `nAuxpowStartHeight`

**OP_SHA512 opcode (mandatory for committed-hash multisig)**
- `src/script/script.h`
  - Repurpose `OP_NOP4` (`0xb3`) as `OP_SHA512` in opcode enum
  - Keep `MAX_OPCODE` unchanged
- `src/script/script.cpp`
  - `GetOpName` mapping for `OP_SHA512`
- `src/script/interpreter.cpp`
  - Execute SHA-512 and push 64-byte output
  - Gate with `SCRIPT_VERIFY_SHA512`
- `src/script/interpreter.h`
  - Add `SCRIPT_VERIFY_SHA512`
- `src/validation.cpp`
  - Enable `SCRIPT_VERIFY_SHA512` at/after auxpow height

**64-byte sighash + signing path**
- `src/script/interpreter.h/.cpp`
  - Add `SignatureHash512(...)` returning `uint512`
  - Extend `PrecomputedTransactionData` / `SigHashCache` for SHA-512 hashes
- `src/uint512.h` (new)
  - `class uint512 : public base_blob<512>`
- `src/script/sign.cpp`
  - Use v1_512 sighash for v1_512 outputs; keep v0 unchanged
- `src/key.h/.cpp`
  - Add `CKey::Sign512(std::span<const uint8_t, 64>, ...)`
  - Keep `CKey::Sign(uint256)` for v0
- `src/pq/pq_api.h`
  - Add `pq::Sign64(...)` / `pq::Verify64(...)` (or generalize to accept 64-byte)
  - Keep msg32 path for v0 intact

### 2.2 Address / Destination Types

**New destination type**
- `src/addresstype.h`
  - Add `WitnessV1ScriptHash512` (64-byte hash container)
  - Extend `CTxDestination` variant
- `src/script/standard.h/.cpp`
  - Add new `TxoutType` value (e.g., `WITNESS_V1_SCRIPTHASH_512`)
  - Extend `Solver()` to detect v1 64-byte programs
- `src/addresstype.cpp`
  - Script hash: `SHA512(witnessScript)` for v1
  - `GetScriptForDestination`: `OP_1 <64 bytes>`
  - `ExtractDestination`: parse v1 64-byte program into `WitnessV1ScriptHash512`

**Encoding/decoding**
- `src/key_io.cpp`
  - Decode: allow bech32m + witness version 1
  - Accept **64-byte** program only for v1
  - Encode: `WitnessV1ScriptHash512` => bech32m (v1)

### 2.3 Standardness / Policy
- `src/policy/policy.cpp`
  - `IsStandard`: accept new TxoutType for v1 64-byte programs (no height logic here)
  - No changes to scriptSig size rules (witness-based)
- `src/validation.cpp`
  - Mempool policy gate: pre-auxpow, reject any tx that creates v1 outputs
    (use next_height vs `nAuxpowStartHeight`).

### 2.4 Wallet + Output Types
- `src/outputtype.h/.cpp`
  - Add `OutputType::BECH32PQ` (name TBD)
- `src/wallet/wallet.cpp`
  - Gate new output type by auxpow height
- `src/wallet/walletutil.cpp`
  - Descriptor creation for v1-512
- `src/wallet/rpc/addresses.cpp` + `src/rpc/util.cpp`
  - Allow `address_type=bech32pq`
- `src/qt/*`
  - Wallet options output type selection gated by height

## 3. Tests (Required)

**Consensus / script tests**
- `src/test/script_tests.cpp`
  - Add OP_SHA512 vectors (if opcode enabled)
  - Add v1_512 sighash unit tests (known vectors)
- `src/test/key_io_tests.cpp`
  - Encode/decode v1 64-byte addresses (bech32m)
  - Decode PQ HRP v1 64-byte succeeds
  - Decode PQ HRP v0 20/32-byte fails
  - Decode legacy HRP v1 fails
  - Encode `WitnessV1ScriptHash512` → PQ HRP string
- `src/test/script_standard_tests.cpp`
  - `IsStandard` acceptance for v1 64-byte outputs
- `src/test/script_tests.cpp` or `src/test/transaction_tests.cpp`
  - Spend roundtrip of v1-512 outputs (valid sig + pubkey)
  - Verify v0 paths still use 32-byte sighash
- Additional negative tests:
  - Invalid v1 program sizes (not 64 bytes)
  - Wrong witness element count
  - SIGHASH_DEFAULT rejected for v1_512
  - Mixed v0/v1 inputs in same tx
  - OP_SHA512 empty-stack failure
  - OP_SHA512 input size boundary
  - Policy: pre-auxpow mempool rejects txs that create v1 outputs

**Functional tests**
- `test/functional/wallet_address_types.py` (or new):
  - Pre-auxpow: v1 address rejected
  - Post-auxpow: v1 address accepted, spendable

## 4. PR Slices (Workable Units)

**PR-1: 64-byte sighash + SigVersion v1_512**
- Add `SigVersion::WITNESS_V1_512`
- Add `SignatureHash512(...)` and SHA-512 precomputed hashes
- Add `CKey::Sign512` and `pq::Sign64` / `pq::Verify64`
- Unit tests for v1_512 sighash

**PR-2: Consensus v1 witness recognition**
- Update `CScript::IsWitnessProgram`
- Add `SCRIPT_VERIFY_WITNESS_V1_512` and height gating
- Update `VerifyWitnessProgram` with v1 scripthash logic
- Add mempool policy gate to reject v1 outputs pre-auxpow (height-aware)
- Add unit tests for v1 program validation

**PR-3: Address types + encoding**
- New `WitnessV1ScriptHash512` destination type
- bech32m encode/decode for v1 64-byte
- `Solver`/`GetScriptForDestination` updates
- Key IO tests

**PR-4: Wallet / OutputType integration**
- New output type, descriptor creation
- RPC address_type support
- Auxpow gating for new output type
- Qt options gating (if desired in this PR)

**PR-5: OP_SHA512 opcode**
- Add opcode + interpreter execution
- Gate by height with `SCRIPT_VERIFY_SHA512`
- Tests for OP_SHA512

## 5. Descriptor and RPC conventions

**Descriptor syntax**
- Define a dedicated descriptor form for v1_512 scripthash outputs (e.g., `wsh512(SCRIPT)`).
- Map `wsh512` to `OutputType::BECH32PQ`.
- SCRIPT can be expressed using existing script descriptors (e.g., `pk(KEY)`),
  where KEY is a TidePubKey (prefixed raw pubkey bytes), consistent with current
  PQ descriptor handling.

**RPC / UI**
- `address_type=bech32pq` selects v1_512 (bech32m encoding, PQ HRP).

## 6. HRP changes (same upgrade)

**Goal**: introduce a distinct HRP for PQ v1 addresses, shipped together with
OP_SHA512 so no legacy-HRP v1 addresses ever exist.

**Allowlist**
- PQ HRP accepts **only** v1 + 64-byte programs.
- Legacy HRP accepts **only** v0 (reject v1).

**Touchpoints**
- `src/kernel/chainparams.h/.cpp` add PQ HRP per network.
- `src/key_io.cpp` encode/decode with PQ HRP for v1.
- `src/rpc/util.h` / `src/rpc/output_script.cpp` update examples.
- `src/qt/guiutil.cpp` update dummy bech32 examples.
- `src/qt/optionsdialog.*` / `src/qt/bitcoingui.cpp` update UI hints.

**HRP values (must be set alongside legacy HRP)**
- Add `bech32pq_hrp` in chainparams for each network (main/test/reg).
- Mainnet: `q`
- Testnet: `tq`
- Regtest: `rq`

## 7. Test vectors (appendix required)

Include explicit vectors for:
- Tagged SHA-512: `taghash` and final hash
- v1_512 sighash (preimage -> expected 64-byte hash)
- bech32m address encoding (program -> address)
- OP_SHA512 input/output

## 8. Open Questions (Need Confirmation)

None. All choices above are frozen for implementation.
   
