# AuxPoW + Scrypt + Post‑AuxPoW Difficulty Plan

This document captures the **research + planning** path to bring AuxPoW, scrypt
PoW, and post‑AuxPoW difficulty adjustment into Tidecoin. No code changes are
proposed here.

Reference repo (Bellscoin 0.28):
- `/home/yaroslav/dev/bellscoin/bels/0.28/bellscoinV3`

Current Tidecoin status:
- PoW hash: **height‑gated** yespower (pre‑auxpow) / scrypt (post‑auxpow).
- Difficulty: legacy Bitcoin/Litecoin‑style retarget (`src/pow.{h,cpp}`)
- AuxPoW: data model + header serialization added (PR‑A1 done; validation not wired)
- Scrypt: present in `src/crypto/scrypt*` and wired into PoW (PR‑A2 done)

---

## 1. What Exists in Bellscoin (Authoritative Source)

### Chain ID encoding + version bits (critical)
Key files:
- `src/primitives/pureheader.h`
- `src/primitives/pureheader.cpp`
- `src/node/miner.cpp`
- `src/validation.cpp`

**How chain ID is encoded (Bellscoin):**
- Stored in `nVersion` bits **16..20** (5 bits total).
  - `VERSION_START_BIT = 16`
  - `MASK_AUXPOW_CHAINID_SHIFTED = (0x001f << VERSION_START_BIT)`
- Auxpow flag is **bit 8** (`VERSION_AUXPOW = (1 << 8)`).
- Chain ID is only **decoded when auxpow flag is set**:
  - `GetChainId()` returns `(ver & MASK) >> 16` if auxpow flag set, else returns **0**.
- Base version is considered the “non‑auxpow, non‑chain‑ID” part.
- Top bits **28..30** are masked out when validating base version:
  - `VERSIONAUXPOW_TOP_MASK = (1<<28)|(1<<29)|(1<<30)`
  - `SetBaseVersion()` asserts `(nBaseVersion & ~VERSIONAUXPOW_TOP_MASK) < (1 << 16)`

**Versionbits interaction (Bellscoin):**
- Mining uses `ComputeBlockVersion()` (BIP9/versionbits) and then calls
  `SetBaseVersion(nVersion, nChainId)` in `src/node/miner.cpp`.
- Top bits (versionbits) are preserved; the chain ID is OR‑ed into bits 16..20.
- `GetBaseVersion()` clears auxpow + **only the configured chain‑ID bits**:
  - It uses `~VERSION_AUXPOW_CHAINID_SHIFTED` (built from a **hard‑coded CHAINID=16**).
  - This works for Bellscoin because chain ID is fixed to 16 (bit 20 only).
  - **For Tidecoin, this must be generalized to clear all 5 chain‑ID bits** (mask‑based),
    or base‑version parsing will be wrong for any chain ID ≠ 16.

**Auxpow chain ID checks (Bellscoin):**
- `Consensus::Params` defines:
  - `nAuxpowChainId` (Bellscoin uses **16**)
  - `fStrictChainId` (true on main/test/reg)
- In `CheckProofOfWork()` / `ContextualCheckBlockHeader()`:
  - If not legacy and strict chain ID:
    - auxpow blocks must have `chainid == nAuxpowChainId`
    - non‑auxpow blocks must have `chainid == 0`
  - Pre‑auxpow height can still allow legacy `nVersion==1` blocks.

**Auxpow parent chain ID rule (Bellscoin):**
- In `CAuxPow::check()`:
  - If parent block has auxpow flag and its chain ID equals ours → **invalid**.
  - If parent has no auxpow flag (chain ID 0) → allowed.
- Purpose: prevent same chain ID reuse in merge‑mining, reduce collision risk.

**Deterministic merkle position (chain ID dependent):**
- `CAuxPow::getExpectedIndex(nNonce, nChainId, h)` uses chain ID to pick a
  deterministic leaf index in the auxpow merkle tree:
  ```
  rand = nNonce
  rand = rand * 1103515245 + 12345
  rand %= 2^h
  rand += nChainId
  rand = rand * 1103515245 + 12345
  rand %= 2^h
  ```
- This binds chain ID into the coinbase merkle placement and prevents reuse
  across chains.

**Implications for Tidecoin:**
- Chain ID must be **0..31** (5‑bit space), and **must differ from Bellscoin (16)**.
- CPureBlockHeader must not hard‑code CHAINID; use consensus param instead.
- `GetBaseVersion()` should clear **all chain‑ID bits** using the mask, not a
  chain‑specific constant.
- Decide whether to preserve Bellscoin’s strict parent‑chain‑ID check
  (`fStrictChainId=true`) or relax it (not recommended).

### Safe VersionBits map + chain ID safety (Tidecoin)
Goal: keep BIP9/VersionBits signaling intact while encoding AuxPoW metadata.

**Bitcoin rule (reference):**
- BIP9 requires top 3 bits `001` (`VERSIONBITS_TOP_BITS`), leaving **bits 0..28**
  for deployments. Any auxpow/chain‑ID metadata must not touch the top bits.

**Bellscoin pattern (why it works):**
- Auxpow flag uses **bit 8**.
- Chain‑ID field uses **bits 16..20** (5 bits).
- VersionBits checks `GetBaseVersion()` (which strips auxpow/chain‑ID) before
  evaluating deployment bits.
- Deployments avoid bits 8 and 16..20 (Bellscoin uses bits 2 and 28).

**Tidecoin safe deployment bits (given auxpow flag + 5‑bit chain ID):**
- **Reserved** (never use): bit **8**, bits **16..20**, and top bits **29..31**.
- **Safe range**: **0–7, 9–15, 21–28**.
- With `DEPLOYMENT_TESTDUMMY.bit = 28`, remaining safe bits are:
  **0–7, 9–15, 21–27**.

**Chain ID safety (most conservative choice):**
- Must be **1..31** (0 means no auxpow in `GetChainId()`).
- Use a **bit‑sparse value** to minimize incidental overlap: power‑of‑two
  recommended.
- **Chosen Tidecoin chain ID: 8**, which sets only chain‑ID bit **19**.
  - Distinct from Bellscoin/Syscoin (16).
  - Leaves other chain‑ID bits 16–20 unused.
  - Safe with BIP9 as long as `GetBaseVersion()` clears the full 5‑bit mask.

**Critical requirement for Tidecoin:**
- `GetBaseVersion()` must strip **all 5 chain‑ID bits** using the mask
  `(0x001f << 16)`, not a chain‑specific constant.
  Otherwise chain‑ID bits would appear as VersionBits signals.

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

### Serialization patterns (Bellscoin vs Tidecoin)

**Bellscoin patterns (older style):**
- `CBlockHeader` uses custom `Serialize/Unserialize` templates (not
  `SERIALIZE_METHODS`). It casts to `CPureBlockHeader` and conditionally reads
  `auxpow` if the auxpow flag is set.
- `CAuxPow::SERIALIZE_METHODS` writes a legacy “merkle‑tx” envelope:
  it serializes `coinbaseTx`, a **dummy** `hashBlock`, a **dummy** `nIndex`,
  then the auxpow merkle branches and `parentBlock`.
  - This is intentional to remain compatible with existing auxpow formats.
- `CPureBlockHeader::GetPoWHash()` uses raw memory (`BEGIN(nVersion)` macro),
  not a serialized byte stream.

**Tidecoin (modern Core style) expectations:**
- Prefer `SERIALIZE_METHODS` with `SER_READ/SER_WRITE` and `READWRITE`.
- Ensure `nVersion` is read **before** checking `IsAuxpow()` for conditional
  auxpow deserialization.
- Avoid raw‑memory hashing. Use `HashWriter`/`DataStream` to serialize the header
  into 80 bytes before calling scrypt (consistent with current `GetPoWHash` style).
- Avoid non‑const `shared_ptr` serialization; Tidecoin’s `serialize.h` only
  supports `shared_ptr<const T>`. For auxpow, either:
  - keep custom serialize/unserialize, or
  - use `std::unique_ptr<CAuxPow>` and manual `SER_READ` allocation.

**Compatibility constraints to keep:**
- Preserve the auxpow serialization envelope (dummy `hashBlock` + `nIndex`) and
  ordering in `CAuxPow::SERIALIZE_METHODS`.
- Keep conditional auxpow serialization tied to the auxpow flag in `nVersion`.

**Specific modernization requirements (must‑haves):**
1) **Header hashing**
   - `CPureBlockHeader::GetPoWHash()` must hash the serialized 80‑byte header
     (DataStream/HashWriter), not raw memory.
2) **Auxpow header serialization**
   - `CBlockHeader` must serialize as:
     - base header, then auxpow **only if** auxpow flag is set.
   - Deserialization must read `nVersion` first and conditionally read auxpow.
3) **Pointer type handling**
   - Avoid `std::shared_ptr<CAuxPow>` serialization (only `shared_ptr<const T>`
     is supported in current `serialize.h`).
   - Use manual `SER_READ/SER_WRITE` with `unique_ptr` or keep custom
     Serialize/Unserialize to handle auxpow.
4) **Base‑version parsing**
   - Clear the **full 5‑bit chain‑ID field** when extracting base version
     (mask‑based), not a chain‑specific shifted bit.

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

## 3. Decisions Summary (Final)

1) **Activation semantics**
   - Pre‑auxpow: **reject auxpow blocks** (consensus + policy).
   - Post‑auxpow: **accept both auxpow and non‑auxpow blocks**, but **scrypt only**
     (no yespower).
   - Mirrors Bellscoin’s production behavior.

2) **PoW hash switch**
   - **Pre‑auxpow**: yespower.
   - **Post‑auxpow**: scrypt for **all** blocks (auxpow or non‑auxpow).

3) **Chain ID**
   - Tidecoin chain ID = **8** (see §3.1).

4) **RPC scope**
   - **Yes** — implement the full Bellscoin auxpow mining RPC surface:
     `getauxblock`, `submitauxblock`, and auxpow JSON in
     `getblock`/`getblockheader`.

---

## 3.1 Decision — Tidecoin Chain ID (Final)

- **Chosen chain ID:** `8`
- **Rationale:**
  - Non‑zero and within the 5‑bit chain‑ID field (1..31).
  - Distinct from Bellscoin’s chain ID (`16`) to avoid merge‑mining collisions.
  - Safe with versionbits **if** base‑version parsing clears the full 5‑bit field.

### Correct base‑version handling (required)

Bellscoin’s `GetBaseVersion()` only clears a chain‑specific shifted bit
(`VERSION_AUXPOW_CHAINID_SHIFTED`), which is safe only when chain ID is a single
bit (their `16`). For Tidecoin’s chain ID `8`, we **must** clear the full
5‑bit field:

- Chain‑ID field mask:
  - `MASK_AUXPOW_CHAINID_SHIFTED = (0x001f << VERSION_START_BIT)`
- Base‑version extraction should clear:
  - `VERSION_AUXPOW` flag **and**
  - `MASK_AUXPOW_CHAINID_SHIFTED` (not a chain‑specific constant).

### Consensus / validation expectations

- `nAuxpowChainId = 8` in `Consensus::Params`.
- `fStrictChainId = true` (keep Bellscoin behavior):
  - auxpow blocks must have chain ID `8`
  - non‑auxpow blocks must have chain ID `0`
- Auxpow parent chain ID must **not** equal `8` when parent uses auxpow.

---

## 3.2 Decision — AuxPoW acceptance semantics (Final)

**Goal:** follow Bellscoin’s proven production behavior.

### Pre‑auxpow (consensus + policy)
- **Reject auxpow blocks** (auxpow not yet allowed).
- Accept non‑auxpow blocks only, using **yespower** PoW.

### Post‑auxpow (consensus)
- **Accept both auxpow and non‑auxpow blocks**, but **scrypt only** (no yespower).
- Auxpow blocks must have chain‑id = 8 and auxpow flag set.
- Non‑auxpow blocks must have chain‑id = 0 and auxpow flag unset.

---

## 3.3 Decision — AuxPoW RPC surface (Final)

Implement the full Bellscoin RPC toolchain (no partial subset):
- `getauxblock` (template + chainid + target)
- `submitauxblock` (submit auxpow)
- `getblock` / `getblockheader` auxpow JSON payload
- `getblocktemplate` support (auxpow aware where applicable)

Reason: this is the production‑proven tooling used by pools; Tidecoin should
match Bellscoin for compatibility.

---

## 4. PR Breakdown (Workable Slices)

PR‑A0 — Import scrypt + build wiring (no behavior change yet) **[DONE]**
- Port Bellscoin files:
  - `src/crypto/scrypt.h`
  - `src/crypto/scrypt.cpp`
  - `src/crypto/scrypt-sse2.cpp` (compiled when `-DENABLE_SSE2=ON`)
- Wire into build system (CMake).  
- No call‑site changes yet.

PR‑A1 — Data model + header format (auxpow + pureheader) **[DONE]**
- [x] Add `CPureBlockHeader` and auxpow data model.
- [x] Add auxpow fields/chain‑ID to consensus params and chainparams.
- [x] Wire auxpow/pureheader sources into CMake build.
- Touchpoints:
  - `src/primitives/pureheader.{h,cpp}` (new)
  - `src/primitives/block.{h,cpp}`
  - `src/auxpow.{h,cpp}` (new)
  - `src/consensus/params.h`
  - `src/kernel/chainparams.cpp`
  - `src/CMakeLists.txt`
- Acceptance:
  - [x] Serialization round‑trips (auxpow present/absent).
  - [x] No consensus changes yet.

PR‑A2 — PoW hash switch (yespower ↔ scrypt) **[DONE]**
- [x] Add scrypt PoW hash helpers on header:
  - `CPureBlockHeader::GetScryptPoWHash()` (`src/primitives/pureheader.{h,cpp}`)
  - `CBlockHeader::GetScryptPoWHash()` (`src/primitives/block.{h,cpp}`)
- [x] Add height‑gated PoW selection helpers:
  - `UseScryptPoW`, `CheckProofOfWork(block,height)`, `CheckProofOfWorkAny`
    (`src/pow.{h,cpp}`)
- [x] Route validation and storage to height‑aware PoW checks:
  - `CheckBlockHeader` and `AcceptBlockHeader` (`src/validation.cpp`)
  - `BlockManager::ReadBlock` avoids double PoW checks (`src/node/blockstorage.cpp`)
  - Header‑chain PoW checks use height when prev header known
    (`HasValidProofOfWork` in `src/validation.cpp`,
     `PeerManagerImpl::CheckHeadersPoW` in `src/net_processing.cpp`)
- [x] Update miner/test PoW loops to use height‑aware checks:
  - `GenerateBlock` (`src/rpc/mining.cpp`)
  - `src/test/util/mining.cpp`
- [x] Auxpow parent PoW hash uses scrypt (`src/auxpow.h`)
- [x] Initialize scrypt SSE2 detection at startup (`src/init.cpp`)
- [x] Remove redundant scrypt scratchpad zeroing (`src/crypto/scrypt.cpp`)
- Acceptance:
  - [x] Pre‑auxpow uses yespower.
  - [x] Post‑auxpow uses scrypt.
  - [ ] Explicit tests added (see PR‑A6).

PR‑A3 — Difficulty switch (old ↔ new retarget) **[DONE]**
- [x] Port Bellscoin retarget logic and parameters.
- Touchpoints:
  - `src/pow.{h,cpp}` (old/new retarget + height switch)
  - `src/consensus/params.h` (new retarget params + helpers)
  - `src/kernel/chainparams.cpp` (per‑network params)
  - `src/test/pow_tests.cpp` (new‑algo smoke test)
- Acceptance:
  - [x] Height‑based switch works (`nNewPowDiffHeight`).
  - [x] Unit tests cover both algorithms (legacy tests + new‑algo smoke test).

PR‑A4 — Consensus validation (auxpow checks) **[DONE]**
- [x] Enforce auxpow presence/absence by height.
- [x] Validate chain‑ID bits and auxpow parent PoW.
- [x] Base‑version checks use `GetBaseVersion()` and enforce
      `IsValidBaseVersion()` post‑auxpow.
- Touchpoints:
  - `src/validation.cpp` (auxpow context checks in `CheckBlockHeader`)
- Acceptance:
  - [x] Auxpow blocks rejected/accepted per activation semantics.
  - [x] Tests: `./build/bin/test_tidecoin -t auxpow_serialization_tests`,
    `./build/bin/test_tidecoin -t pow_tests`.

PR‑A5 — RPC + miner support **[DONE]**
- [x] Add merged‑mining RPC flow.
- Touchpoints:
  - `src/rpc/mining.cpp`
  - `src/rpc/blockchain.cpp`
  - `src/rpc/auxpow_miner.{h,cpp}`
  - `src/wallet/rpc/getauxrpc.cpp`
  - `src/rpc/blockchain.h`
  - `src/rest.cpp`
  - `src/CMakeLists.txt`, `src/wallet/CMakeLists.txt` (link + build wiring)
- Acceptance:
  - [x] `createauxblock` / `submitauxblock` registered under `mining`.
  - [x] `getauxblock` registered under `wallet` and uses reserved keypool address.
  - [x] `getblock`/REST JSON include `auxpow` when present.
  - [x] Build passes; ran `./build/bin/test_tidecoin -t auxpow_serialization_tests`.

PR‑A6 — Tests
- Port Bellscoin tests and adapt for Tidecoin params.
- Touchpoints:
  - `src/test/auxpow_tests.cpp`
  - `src/test/pow_tests.cpp`
  - Functional tests for activation and retarget switch
- Acceptance:
  - [x] Pre/post‑activation behavior covered (unit tests).
  - PoW switch tests:
    - [x] `UseScryptPoW(params, height)` returns false at `nAuxpowStartHeight-1`, true at `nAuxpowStartHeight`.
    - [x] `CheckProofOfWork(block, params, height)` matches pre‑auxpow yespower hash and post‑auxpow scrypt hash (deterministic header).
  - [x] Invalid auxpow rejected (strict chain‑ID + missing header tests).
  - [ ] Functional tests for activation/retarget switch.

---

## 5. Next Research Steps

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

## 6. Suggested Work Order (High‑Level)

1) PR‑A1 (data model + header format)
2) PR‑A2 (PoW hash switch)
3) PR‑A3 (difficulty switch)
4) PR‑A4 (consensus validation)
5) PR‑A5 (RPC/miner, if required)
6) PR‑A6 (tests)
