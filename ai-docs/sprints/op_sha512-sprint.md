# OP_SHA512 + PQ v1_512 Scripthash — Sprint Plan

This sprint plan breaks `ai-docs/op_sha512_plan.md` into PR-sized tasks.
Scope: implement **v1 scripthash-only** outputs with **tagged SHA-512 sighash**
and **OP_SHA512**, gated by auxpow, **including the PQ HRP change**.

## PR-1 — SigVersion v1_512 + 64-byte sighash pipeline

**Goal**: introduce a 64-byte signing path and tagged SHA-512 sighash.

**Tasks**
1) [x] Add `SigVersion::WITNESS_V1_512`.
2) [x] Implement `SignatureHash512(...)` (tagged SHA-512).
3) [x] Introduce `uint512` (type-safe 64-byte hashes).
4) [x] Extend precomputed hashes for SHA-512:
   - `hashPrevouts_512`, `hashSequence_512`, `hashOutputs_512`.
5) [x] Add `CKey::Sign512(...)` and `pq::Sign64/Verify64(...)`.
6) [x] Wire `SignStep`/`CreateSig` to use v1_512 for v1 outputs.

**Touchpoints**
- `src/script/interpreter.h/.cpp`
- `src/script/sign.cpp`
- `src/key.h/.cpp`
- `src/pq/pq_api.h`
- `src/uint512.h` (new)

**Acceptance**
- v1_512 signatures are produced/verified with 64-byte message.
- v0 remains unchanged (32-byte sighash).

**Tests**
- [x] New unit vectors for `SignatureHash512(...)` in `src/test/script_tests.cpp`.

---

## PR-2 — Witness v1 scripthash validation (consensus)

**Goal**: implement v1 witness program handling for 64-byte scripthash.

**Tasks**
1) [x] `CScript::IsWitnessProgram` accepts 64-byte program for v1 only.
2) [x] `VerifyWitnessProgram`:
   - enforce 64-byte program length,
   - hash witnessScript with SHA-512,
   - execute witnessScript with `SigVersion::WITNESS_V1_512`.
3) [x] Add `SCRIPT_VERIFY_WITNESS_V1_512` gated by auxpow.
4) [x] Pre-auxpow: consensus treats v1 as anyone-can-spend; policy rejects.
5) [x] Mempool policy gate: pre-auxpow reject txs that create v1 outputs (height-aware).
   - Keep `IsStandard()` / `IsStandardTx()` height-agnostic; gate lives in mempool accept.

**Touchpoints**
- `src/script/script.cpp`
- `src/script/interpreter.cpp`
- `src/script/interpreter.h`
- `src/validation.cpp`

**Acceptance**
- Post-auxpow v1 outputs validate correctly.
- Pre-auxpow v1 outputs are consensus-valid but policy-rejected.

**Tests**
- [x] v1 program length enforcement (valid 64, invalid others).
- [x] mixed v0/v1 inputs in same tx.
- [x] policy rejects v1 outputs pre-auxpow (mempool).

---

## PR-3 — Address types + solver + encoding + PQ HRP (v1 scripthash only)

**Goal**: add destination + TxoutType + bech32m encoding for v1 scripthash.

**Tasks**
1) [x] Add `WitnessV1ScriptHash512` destination type.
2) [x] Add `TxoutType::WITNESS_V1_SCRIPTHASH_512` and update `Solver()`.
3) [x] Encode/decode bech32m for v1 64-byte programs in `key_io.cpp`.
4) [x] Enforce v1 length = 64 bytes (reject others).
5) [x] Add PQ HRP to chainparams (main/test/reg): `q` / `tq` / `rq`.
6) [x] Enforce decode policy: PQ HRP → v1+64 only; legacy HRP → v0 only.

**Touchpoints**
- `src/addresstype.h/.cpp`
- `src/script/standard.h/.cpp`
- `src/key_io.cpp`
- `src/kernel/chainparams.h/.cpp`

**Acceptance**
- `DecodeDestination` handles v1 64-byte only.
- `GetScriptForDestination` returns `OP_1 <64>`.
- v1 addresses encode with PQ HRP (`q1...`).
- PQ HRP decodes v1+64 only; legacy HRP rejects v1.

**Tests**
- [x] `src/test/key_io_tests.cpp` (v1 encode/decode).
- [x] `src/test/script_standard_tests.cpp` (IsStandard for v1).
- [x] Decode PQ HRP v1 64-byte succeeds.
- [x] Decode PQ HRP v0 fails.
- [x] Decode legacy HRP v1 fails.

---

## PR-4 — Wallet output type + descriptor syntax (wsh512) + UI hints

**Goal**: allow wallet to generate PQ v1 scripthash outputs.

**Tasks**
1) [x] Add `OutputType::BECH32PQ`.
2) [x] Add descriptor form `wsh512(SCRIPT)`.
3) [x] Map `wsh512` to `OutputType::BECH32PQ`.
4) [x] Gate wallet output type by auxpow height (policy).
5) [x] Update RPC examples and Qt dummy bech32 address helpers (PQ HRP).

**Touchpoints**
- `src/outputtype.h/.cpp`
- `src/script/descriptor.cpp`
- `src/wallet/walletutil.cpp`
- `src/wallet/wallet.cpp`
- `src/wallet/rpc/addresses.cpp`
- `src/rpc/util.cpp`
- `src/rpc/output_script.cpp`
- `src/qt/guiutil.cpp`
- `src/qt/optionsdialog.*` / `src/qt/bitcoingui.cpp`

**Acceptance**
- `address_type=bech32pq` works post-auxpow.
- pre-auxpow: wallet refuses to create v1 outputs.

**Tests**
- [ ] functional wallet address types (pre/post auxpow).

---

## PR-5 — OP_SHA512 opcode (script-level)

**Goal**: add OP_SHA512 for committed-hash multisig and script hashing.

**Tasks**
1) [x] Repurpose `OP_NOP4` → `OP_SHA512`.
2) [x] Interpreter: pop 1, push 64-byte SHA-512; fail if stack empty.
3) [x] Gate with `SCRIPT_VERIFY_SHA512` at auxpow height.

**Touchpoints**
- `src/script/script.h`
- `src/script/script.cpp`
- `src/script/interpreter.cpp`
- `src/script/interpreter.h`
- `src/validation.cpp`

**Tests**
- [x] OP_SHA512 vectors (empty stack, fixed input).

**Acceptance**
- [x] OP_SHA512 produces 64-byte output.
- [x] OP_SHA512 fails on empty stack.
- [x] OP_SHA512 rejected pre-auxpow.

---

## Cross-PR test coverage checklist

- [x] Invalid v1 program lengths rejected post-auxpow.
- [x] v1 programs treated as anyone-can-spend pre-auxpow (consensus), rejected by policy.
- [x] SIGHASH_DEFAULT rejected for v1_512.
- [x] Mixed v0/v1 inputs in same tx.
- [x] OP_SHA512 input size boundary.
- [x] Decode PQ HRP v1 64-byte succeeds.
- [x] Decode legacy HRP v1 rejected.
- [x] Pre-auxpow mempool rejects v1 outputs (policy gate).
