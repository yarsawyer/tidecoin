# AuxPoW + Scrypt + Post‑AuxPoW Difficulty Plan

This document captures the **research + planning** path to bring AuxPoW, scrypt
PoW, and post‑AuxPoW difficulty adjustment into Tidecoin. No code changes are
proposed here.

Reference repo (Bellscoin 0.28):
- `/home/yaroslav/dev/bellscoin/bels/0.28/bellscoinV3`

Current Tidecoin status:
- PoW hash: yespower (`src/primitives/block.cpp::CBlockHeader::GetPoWHash`)
- Difficulty: legacy Bitcoin/Litecoin‑style retarget (`src/pow.{h,cpp}`)
- AuxPoW: not implemented (no `auxpow.*`, no header auxpow fields)
- Scrypt: not present in repo (no `crypto/scrypt.*` or `scrypt_1024_1_1_256`)

---

## 1. What Exists in Bellscoin (Authoritative Source)

### AuxPoW core + header format
Key files:
- `src/auxpow.h`, `src/auxpow.cpp`  
  - `CAuxPow` class, `check()`, `createAuxPow()`, `initAuxPow()`
  - Merge‑mining merkle branch handling
- `src/primitives/block.h/.cpp`
  - `std::shared_ptr<CAuxPow> auxpow` in `CBlockHeader`
  - Conditional serialization when auxpow flag is set
- `src/primitives/pureheader.h/.cpp`
  - `CPureBlockHeader` for clean dependency separation
  - Chain ID bits and auxpow flag in block version

### Validation logic
- `src/validation.cpp::CheckProofOfWork`
  - Non‑auxpow: check block PoW hash
  - Auxpow: validate auxpow + check parent block PoW hash
  - Enforce chain ID in version bits

### RPC + miner support
- `src/rpc/auxpow_miner.{h,cpp}`
- `src/rpc/mining.cpp` (`getauxblock`, `submitauxblock`)
- `src/wallet/rpc/getauxrpc.cpp`
- `src/rpc/blockchain.cpp` (auxpow JSON)

### Post‑AuxPoW difficulty adjustment
- `src/pow.{h,cpp}` defines:
  - `GetNextWorkRequiredOld/New`
  - `CalculateNextWorkRequiredOld/New`
  - switch by `nNewPowDiffHeight`
- Per‑block retarget with averaging window (Zcash‑style envelope)

### Scrypt PoW
- `src/crypto/scrypt.*` + `crypto/scrypt-sse2.cpp`
- `CPureBlockHeader::GetPoWHash()` uses `scrypt_1024_1_1_256`

### Tests
- `src/test/auxpow_tests.cpp`
- `src/test/pow_tests.cpp`

---

## 2. Tidecoin Integration Targets (No Code Yet)

### A) AuxPoW data model + header format
Bring in:
- `auxpow.h/.cpp`
- `CPureBlockHeader` + chain‑ID bits
- `CBlockHeader::auxpow` + conditional serialization

Tidecoin touchpoints:
- `src/primitives/block.h/.cpp`
- `src/primitives/pureheader.h/.cpp` (new)
- `src/consensus/params.h`
- `src/kernel/chainparams.cpp`

### B) Scrypt PoW integration
Goal: keep **yespower + legacy header format + legacy difficulty** pre‑auxpow,
then switch to **scrypt PoW + new header format + new retarget** post‑auxpow.

Tidecoin touchpoints:
- `src/primitives/block.cpp::GetPoWHash`
- `src/crypto/scrypt.*` (new)
- any PoW hash call sites/tests

### C) Post‑AuxPoW difficulty adjustment
Goal: port Bellscoin’s old/new retarget logic and switch by height:
- pre‑auxpow: legacy Tidecoin retarget (current)
- post‑auxpow: Bellscoin “new” retarget
- also port Bellscoin retarget **parameters** (window sizes, bounds, switch
   height) into Tidecoin `Consensus::Params`/chainparams.
- **Tidecoin will choose its own switch height** (do not reuse Bellscoin height).

Tidecoin touchpoints:
- `src/pow.h/.cpp`
- `src/consensus/params.h`
- `src/kernel/chainparams.cpp`

### D) Consensus validation changes
Goal: enforce auxpow presence/absence by height; validate auxpow + parent PoW.

Tidecoin touchpoints:
- `src/validation.cpp` (CheckProofOfWork + AcceptBlockHeader path)

### E) RPC + miner support (optional but likely required)
Goal: support mining workflow for merged‑mining.

Tidecoin touchpoints:
- `src/rpc/mining.cpp`
- `src/rpc/blockchain.cpp`
- `src/rpc/auxpow_miner.{h,cpp}` (new)
- `src/wallet/rpc/getauxrpc.cpp` (if needed)

### F) Tests
Goal: port Bellscoin tests and tune for Tidecoin params.

Tidecoin touchpoints:
- `src/test/auxpow_tests.cpp` (new/ported)
- `src/test/pow_tests.cpp` (ported/adapted)
- functional tests for auxpow activation & retarget switch

---

## 3. Open Decisions (Need Confirmation)

1) **Activation semantics**
   - Pre‑auxpow: reject auxpow blocks or allow?
   - Post‑auxpow: must blocks include auxpow?

2) **PoW hash switch**
   - scrypt used only for auxpow blocks?
   - or scrypt from auxpow activation onward for all blocks?

3) **Chain ID**
   - adopt Bellscoin chain‑ID bit scheme exactly?
   - define Tidecoin chain ID constant

4) **RPC scope**
   - do we need full auxpow mining RPCs in mainnet?

---

## 4. Next Research Steps

1) Extract exact Bellscoin consensus constants:
   - `nAuxpowStartHeight`
   - `nAuxpowChainId`
   - retarget parameters (`nNewPowDiffHeight`, window sizes)

2) Diff Tidecoin vs Bellscoin difficulty rules:
   - confirm how Tidecoin’s yespower retarget aligns with Bellscoin’s
     pre‑/post‑switch rules

3) Draft PR‑sized implementation plan:
   - sequence with tests and activation gating

---

## 5. Suggested Work Order (High‑Level)

1) **PR‑A0 — Import scrypt + build wiring (no behavior change yet)**
   - Port Bellscoin files:
     - `src/crypto/scrypt.h`
     - `src/crypto/scrypt.cpp`
     - `src/crypto/scrypt-sse2.cpp` (optional; can be built only when SSE2 is enabled)
   - Wire into build system (CMakeLists; Makefile.am if still used).
   - Note: Bellscoin defaults to the generic implementation if `scrypt_detect_sse2()`
     is never called (no call sites in Bellscoin). We can keep that behavior initially.
2) Data model + header format (auxpow + pureheader)
3) PoW hash switch logic (yespower vs scrypt)
4) Difficulty switch (old/new retarget)
5) Consensus validation (auxpow checks)
6) RPC/miner surface (if required)
7) Tests and fixtures
