# ECDSA/DER Surface Audit (Tidecoin Core)

## Scope
This document tracks the specific ECDSA/DER-framed surfaces you listed and maps each one to:
- current Tidecoin behavior,
- impact/risk,
- logic flow and dependencies,
- Bitcoin 30.2 baseline,
- fix options with implementation notes.

Audit targets:
- `src/wallet/rpc/spend.cpp` (73-byte DER guidance in RPC help)
- `src/key.h` (DER wording)
- `src/script/sign.h` (71/72-byte dummy wording)
- `src/script/descriptor.h`, `src/script/descriptor.cpp`, `src/wallet/spend.cpp` (high-R ECDSA wording)
- `src/policy/policy.cpp` (dust constants: 107/148 model)
- `src/qt/coincontroldialog.cpp` (input size estimator still ECDSA-centric)

---

## Progress update

- Implemented (comment-only cleanup, no runtime behavior changes):
  - `src/key.h` (`Sign()` wording made PQ-neutral)
  - `src/script/sign.h` (dummy signature comments no longer 71/72-byte ECDSA specific)
  - `src/script/descriptor.h` (`use_max_sig` docs now describe worst-case signature sizing)
  - `src/script/descriptor.cpp` (helper/miniscript comments no longer mention high-R ECDSA)
  - `src/wallet/spend.cpp` (`UseMaxSig` and `MaxInputWeight` docs made PQ-neutral)
- Implemented (behavioral fix):
  - `src/pq/pq_scheme.h`
    - Added centralized helpers `MaxKnownPubKeyBytes()` / `MaxKnownPubKeyBytesInScript()`.
  - `src/policy/policy.cpp`
    - Replaced legacy dust-size assumptions with PQ-aware conservative proxies for:
      - non-witness spends,
      - witness v0 keyhash,
      - witness v0 scripthash,
      - witness v1_512,
      - unknown witness programs (conservative fallback).
  - `src/test/transaction_tests.cpp`
    - Switched dust assertions to dynamic `GetDustThreshold(...)` boundaries (no stale fixed values).
  - `test/functional/mempool_dust.py`
    - Updated functional dust model to mirror core PQ dust math.
- Verification status:
  - `transaction_tests` passed
  - `mempool_dust.py` passed
  - `mempool_ephemeral_dust.py` passed
- **Phase complete:** `policy.cpp` dust model migration is complete.
- Implemented (behavioral fix):
  - `src/qt/coincontroldialog.cpp`
    - Replaced hardcoded ECDSA input-size heuristics (`107/4`, `148`) with wallet descriptor-based sizing (`CalculateMaximumSignedInputSize`).
    - Removed witness-version throw path and added conservative PQ fallback sizing for unresolved inputs.
    - Stopped double-counting witness stack-item varints in the aggregate estimate path.
  - `src/wallet/rpc/spend.cpp`
    - Replaced stale DER/ECDSA `input_weights.weight` guidance with PQ-neutral wording based on conservative worst-case signature sizing.
- **Phase complete:** remaining non-policy documentation/API wording cleanup is complete for this audit set.

---

## 1) RPC help text still says 73-byte DER signatures

### Status
- **Done** (RPC help wording updated to PQ-neutral guidance).

### Code references
- `src/wallet/rpc/spend.cpp:819`
- `src/wallet/rpc/spend.cpp:1271`
- `src/wallet/rpc/spend.cpp:1740`

### What it currently does
The text shown to RPC users for `input_weights` now says:
- signature size depends on script type and PQ scheme, and conservative worst-case sizing should be used.

The runtime logic itself is not DER-bound:
- input weight parsing: `src/wallet/rpc/spend.cpp:697`
- weight floor check uses generic txin skeleton weight: `src/wallet/rpc/spend.cpp:715`
- weights are consumed by coin control: `src/wallet/rpc/spend.cpp:724`
- wallet sizing path uses descriptors/PQ-aware sizing: `src/wallet/spend.cpp:168`, `src/wallet/spend.cpp:179`, `src/wallet/spend.cpp:205`

### Impact
- **Behavioral/core correctness:** no direct bug from these strings alone.
- **API/operator risk:** callers can submit underestimated `input_weights` if they follow stale DER wording; this can produce fee underestimation and mismatched expectations for funded tx construction.
- **Test/interop risk:** external tooling that follows help text may produce poor results on PQ inputs.

### Dependencies / connected components
- `FundTransaction()` option handling and `CCoinControl::SetInputWeight`.
- Wallet tx-size estimator pipeline (`InferDescriptor` -> `MaxInputWeight` -> `GetVirtualTransactionSize`).

### Bitcoin 30.2 comparison
- Bitcoin 30.2 contains the same DER wording in the equivalent help text.
- In Tidecoin this is stale because signatures are PQ-sized and much larger.

### Fix direction
- Replace ECDSA/DER guidance with PQ-neutral guidance:
  - “supply worst-case signed input weight in WU”
  - optionally reference scheme-dependent max via Tidecoin docs.
- Keep existing parser/weight checks unchanged.

### Fix implemented
- Updated all `input_weights.weight` help strings in:
  - `fundrawtransaction`
  - `send`
  - `walletcreatefundedpsbt`
- New wording now says signature size depends on script type/PQ scheme and should be provided as conservative worst-case for expected signing path.

---

## 2) `key.h` comment says “Create a DER-serialized signature”

### Status
- **Done** (comment-only cleanup applied).

### Code reference
- `src/key.h:170`

### What it currently does
- Comment-level mismatch only.
- Runtime signing paths are PQ-backed (`Sign`, `Sign512`) with scheme-aware internals.

### Impact
- **Behavioral/core correctness:** none.
- **Maintenance risk:** high confusion for future contributors and audits.

### Dependencies
- None at runtime; this is API documentation debt in header comments.

### Bitcoin 30.2 comparison
- Bitcoin uses ECDSA and DER wording is correct there.
- Tidecoin inherited wording but semantics changed.

### Fix direction
- Completed in `src/key.h` by replacing DER/ECDSA framing with generic PQ-neutral wording.

---

## 3) `sign.h` dummy creator comments still say 71/72-byte signatures

### Status
- **Done** (comment-only cleanup applied).

### Code references
- `src/script/sign.h:58`
- `src/script/sign.h:60`

### Runtime implementation reference
- `src/script/sign.cpp:610` onward (`DummySignatureCreator`)
- Scheme-aware sizing now implemented:
  - uses `pq::SchemeFromPrefix(pubkey[0])`: `src/script/sign.cpp:623`
  - uses `pq::SigLenFixedInScript` / `pq::SigLenMaxInScript`: `src/script/sign.cpp:625`
  - fallback to max known PQ: `src/script/sign.cpp:629`

### What it currently does
- Comments are stale.
- Runtime dummy signatures are already PQ-sized.

### Impact
- **Behavioral/core correctness:** none.
- **Audit risk:** comment suggests old behavior while code is correct PQ behavior.

### Fix direction
- Completed in `src/script/sign.h`:
  - fixed-size dummy signatures
  - maximum-size dummy signatures

---

## 4) “high-R ECDSA” wording in descriptor/spend surfaces

### Status
- **Done** (comment-only cleanup applied).

### Code references
- `src/script/descriptor.h:131`
- `src/script/descriptor.cpp:650`
- `src/script/descriptor.cpp:1216`
- `src/wallet/spend.cpp:57`

### Related runtime path
- `MaxInputWeight` calls descriptor max satisfaction weight with `use_max_sig`:
  - `src/wallet/spend.cpp:110`
  - `src/wallet/spend.cpp:113`
- Descriptor sizing itself is PQ-aware in current Tidecoin:
  - `SigLenInScript`: `src/script/descriptor.cpp:779`
  - fallback uses `pq::MaxKnownSigBytesInScript`: `src/script/descriptor.cpp:789`, `src/pq/pq_scheme.h:120`

### What it currently does
- Names/comments still frame the toggle as “high-R ECDSA”.
- Actual semantics now are “fixed-size vs worst-case signature-size estimation” for PQ schemes.

### Impact
- **Behavioral/core correctness:** currently correct behavior.
- **Design clarity risk:** medium; can mislead future modifications and test assumptions.

### Fix direction
- Completed comment refactor in:
  - `src/script/descriptor.h`
  - `src/script/descriptor.cpp`
  - `src/wallet/spend.cpp`
- Runtime logic was not changed in this step.

---

## 5) Dust threshold still uses Bitcoin 107/148 spend-size model

### Status
- **Done** (behavioral policy fix applied for non-witness + witness v0/v1 paths).

### Code reference
- `src/policy/policy.cpp:27`
- `src/policy/policy.cpp:73`
- `src/pq/pq_scheme.h:110`
- `src/test/transaction_tests.cpp:866`
- `test/functional/mempool_dust.py:63`

### Current logic flow
1. Dust threshold calculation:
   - `GetDustThreshold(txout, dustRelayFee)`: `src/policy/policy.cpp:26`
2. For non-witness outputs, uses conservative PQ scriptSig proxy:
   - max known PQ signature in script + max known PQ pubkey in script + compact-size overhead.
3. For witness-v0 keyhash (`OP_0 <20-byte program>`), uses dedicated PQ witness key-spend proxy.
4. For witness-v0 scripthash (`OP_0 <32-byte program>`) and witness-v1_512 (`OP_1 <64-byte program>`), uses dedicated PQ witness script-spend proxy.
5. For unknown witness programs, uses conservative PQ witness script proxy (not legacy `107/4`).
6. All proxies are built from centralized scheme maxima:
   - max known PQ signature size in script (`pq::MaxKnownSigBytesInScript(true)`),
   - max known PQ pubkey size in script (`pq::MaxKnownPubKeyBytesInScript()`),
   - compact-size and script-push serialization overhead.
7. Used by mempool policy and wallet policy checks:
   - mempool/reject path: `src/rpc/mining.cpp:533`, `src/policy/policy.cpp:150`, `src/policy/ephemeral_policy.cpp:26`
   - wallet send/change checks: `src/wallet/spend.cpp:1106`, `src/wallet/spend.cpp:1241`, `src/wallet/spend.cpp:1412`

### Tidecoin-specific mismatch
- Tidecoin has `OutputType::BECH32PQ` as `wsh512(pk(...))` (`src/wallet/walletutil.cpp:81`, `src/outputtype.cpp:75`, `src/addresstype.cpp:139`).
- Tidecoin also supports non-witness and witness-v0 script families spent with PQ signatures.
- Bitcoin-era `148/107` assumptions materially underestimate spend cost under PQ and can underprice dust policy.

### Impact
- **Consensus:** none (policy only).
- **Policy/economic correctness:** significant; may relay/mine outputs that are practically uneconomic to spend under PQ costs.
- **Wallet behavior:** wallet dust checks inherit same low threshold and may create outputs that are expensive relative to value.

### Bitcoin 30.2 comparison
- Bitcoin also uses 107 model intentionally (including Taproot) to avoid lowering dust level and preserve policy continuity.
- Tidecoin differs materially because PQ spend sizes are far above ECDSA/Schnorr assumptions.

### Fix implemented
- Replaced legacy `148` non-witness proxy with PQ non-witness scriptSig proxy.
- Replaced witness handling with PQ-aware split:
  - v0 keyhash -> PQ key-spend proxy,
  - v0 scripthash + v1_512 -> PQ script-spend proxy,
  - unknown witness -> conservative PQ script-spend proxy.
- Centralized max signature/pubkey sizes in `pq_scheme.h` helpers.
- Updated unit tests to use dynamic `GetDustThreshold(...)` boundaries (removed hardcoded `546/540/294/330` assumptions).
- Updated functional dust harness (`mempool_dust.py`) to mirror core policy math.

### Connected components to touch if changed
- `src/policy/policy.cpp` + related policy tests
- wallet spend dust assumptions via existing shared `GetDustThreshold` calls
- functional tests for dust policy (`mempool_dust.py`, `mempool_ephemeral_dust.py`, wallet send tests)

---

## 6) Qt Coin Control input-size estimation still ECDSA-centric and v1-incomplete

### Status
- **Done** (behavioral wallet UI sizing fix applied).

### Code reference
- `src/qt/coincontroldialog.cpp:460`
- conservative fallback estimator: `src/qt/coincontroldialog.cpp:55`

### Current logic flow
1. Coin Control gathers selected UTXOs from wallet model:
   - `CoinControlDialog::updateLabels`: `src/qt/coincontroldialog.cpp:419`
2. For each selected input, asks wallet sizing path for descriptor-based maximum signed input vsize:
   - `wallet::CalculateMaximumSignedInputSize(...)`
3. If descriptor inference/sizing is unavailable, uses conservative PQ fallback estimator.
4. Witness presence only toggles marker/flag aggregate adjustment; no witness-version throw path remains.

### Tidecoin-specific risk
- Tidecoin supports witness v1 script-hash 512 destinations (`WitnessV1ScriptHash512`):
  - script form: `src/addresstype.cpp:139`
  - output type mapping: `src/outputtype.cpp:75`, `src/outputtype.cpp:97`
  - wallet change/address selection can prefer `BECH32PQ`: `src/wallet/wallet.cpp:2469`, `src/wallet/wallet.cpp:2489`
- Previously, selected witness v1_512 UTXOs could throw in UI path; this is now fixed.

### Impact
- **Consensus/core:** none.
- **Wallet UI correctness:** improved; fee/bytes estimate now follows wallet descriptor sizing and no longer crashes on witness v1.
- **User trust:** reduced divergence risk between dialog estimate and actual constructed tx fee.

### Bitcoin 30.2 comparison
- Bitcoin handles witness v0 and v1(Taproot) in coin control (`66/4` for v1 keypath).
- Tidecoin still has pre-v1 generalized behavior and no PQ-aware sizing.

### Fix options
1. **Robust fix (recommended):**
   - Replace hardcoded heuristic in coin control with wallet-side sizing API for selected inputs:
     - use descriptor-driven max signed input size (`CalculateMaximumSignedInputSize` path in wallet).
   - Keeps UI estimate aligned with actual wallet construction logic.
2. **Interim fix:**
   - Add witness v1_512 branch and use conservative PQ worst-case proxy; remove throw.
3. **Do not keep current throw path** for future segwit versions in Tidecoin wallet UI.

### Fix implemented
- Implemented option 1 (robust):
  - `CoinControlDialog::updateLabels` now queries `wallet::CalculateMaximumSignedInputSize(...)` for each selected input.
  - If sizing inference fails, falls back to conservative PQ proxy (mirrors policy-side conservative assumptions).
  - Any witness program version now participates in estimation without runtime throws.
  - Marker+flag accounting kept in aggregate path; per-input witness varint accounting no longer duplicated.

### Connected components
- Qt wallet model + coin control dialog
- wallet descriptor sizing path in `src/wallet/spend.cpp`
- potential unit/functional GUI-facing tests (if present in your CI matrix)

---

## Cross-cutting dependency map

- Descriptor-based sizing center:
  - `InferDescriptor` -> `Descriptor::MaxSatisfactionWeight` -> `MaxInputWeight` -> tx-size/fee estimation
  - refs: `src/wallet/spend.cpp:154`, `src/wallet/spend.cpp:179`, `src/wallet/spend.cpp:205`
- Policy dust center:
  - `GetDustThreshold` consumed by mempool policy and wallet dust checks
  - refs: `src/policy/policy.cpp:26`, `src/wallet/spend.cpp:1106`
- RPC docs/users:
  - `input_weights` instructions should match descriptor/PQ runtime sizing semantics

---

## Prioritized remediation order

1. **`policy.cpp` dust model** (behavioral policy/economic impact).
2. **`coincontroldialog.cpp` witness v1_512 handling and PQ fee estimate** (UI correctness + crash risk).
3. **RPC `input_weights` help text updates** (operator/API safety).
4. **Comment-only cleanup** (`key.h`, `sign.h`, descriptor/spend ECDSA wording) **[done]**.

---

## Implementation note
Several surfaces are inherited from Bitcoin 30.2, but in Tidecoin they are no longer neutral because PQ signature and script sizes are materially different. The main non-cosmetic risks are dust policy economics and Qt coin control estimation/runtime behavior.
