# PQHD Planning Notes (Hardened-Only) — Expanded

This is a planning + specification write-up for Tidecoin’s post-quantum HD
wallet (“PQHD”): keep Bitcoin-style UX (deterministic wallets, keypools,
address rotation, change outputs) **without** relying on BIP32 public derivation
(`xpub`), which is not viable for PQ signature keys.

This document is a target design. It intentionally includes both “repo reality”
and “new spec” pieces.

---

## 0. Scope and Non-Goals

### In scope
- Deterministic key generation for PQ signatures using **hardened-only** derivation.
- Multi-scheme support (first-class):
  - Falcon-512 / Falcon-1024
  - ML-DSA-44 / ML-DSA-65 / ML-DSA-87
- Descriptor-based wallet model for new wallets (recommended).
- Legacy migration from oldtidecoin legacy (BDB) wallets.
- PSBT workflows (RPC/Qt) using standard BIP174 PSBT framing, with Tidecoin
  proprietary fields for PQHD metadata.

### Out of scope (for PQHD itself)
- ML-KEM (it is a KEM, not a signature scheme; not used by OP_CHECKSIG).
  - ML-KEM is relevant for the PQ v2 transport work (bip324_pq), but it is not
    part of PQHD.
- Public-derivation tokens (xpub equivalents) for PQ keys.
- Full consensus spec for a future PQ-native output type (we outline
  requirements and hardfork touchpoints).

---

## 0.1 Current Codebase Alignment and Gaps

### Already matches existing code
- Scheme IDs/prefix bytes match `src/pq/pq_scheme.h`:
  - Falcon-512 = 0x07, Falcon-1024 = 0x08, ML-DSA-44/65/87 = 0x09/0x0A/0x0B.
- `SchemeId` is a `uint8_t` and equals the serialized prefix byte.
- The prefix byte is part of the pubkey bytes (scheme selection is a parsing
  problem; see `src/pq/pq_api.h` and `src/pq/pq_scheme.h`).

### Not implemented yet (big gaps)
- PQHD seed storage (encrypted) + derivation logic (NodeSecret/ChainCode).
- Deterministic scoped RNG stream for PQClean keygen (a thread/scope local
  `randombytes()` backend).
- Descriptor language support for `pqhd(...)` key expressions.
- Per-scheme keypool refill and change/external tracking driven by PQHD.
- PSBT proprietary field integration for PQHD origin metadata.
- Any explicit seed identity rules (SeedID32 storage + de-dup semantics).
- **Multi-scheme public key container support**:
  - Current `CPubKey` is effectively Falcon-512-only:
    - `CPubKey::SIZE` is fixed to Falcon-512 pubkey bytes + 1 prefix.
    - `CPubKey::GetLen()` only recognizes `pq::kFalcon512Info.prefix` (`0x07`).
    - See `src/pubkey.h`.
  - Many existing subsystems assume a fixed `CPubKey::SIZE` (descriptors, PSBT
    partial sig key parsing, etc.). Supporting multiple PQ schemes in-wallet
    requires either refactoring `CPubKey` to be scheme-aware/variable-length,
    or introducing a new byte-oriented PQ pubkey type and updating all call
    sites to use it.
  - `CPubKey` still exposes legacy BIP32-oriented APIs (e.g. `Derive(...)` in
    `src/pubkey.h`). PQHD will not use these; PQHD derivation state lives in
    wallet-managed seed material, not in CPubKey objects.

---

## 1. Terminology (Practical Definitions)

**SchemeId**
- A `uint8_t` identifier of the signature scheme.
- In current code, **SchemeId == pubkey prefix byte** (`src/pq/pq_scheme.h`).

**TidePubKey**
- Public key encoding committed to by address/script:
  - `tide_pubkey = scheme_prefix(1 byte) || scheme_pubkey_bytes`

**CPubKey (repo type)**
- The codebase’s “one public key” container (`src/pubkey.h`).
- In Tidecoin it currently stores a `tide_pubkey` byte string (prefix + scheme
  pubkey bytes), and is used as the leaf key identifier in many subsystems:
  scripts, descriptors, wallet key maps, and PSBT maps (e.g. `partial_sigs`).
- **CPubKey is not an HD token**:
  - It represents exactly one concrete public key, not a derivation subtree.
  - It does not carry PQHD seed state (NodeSecret/ChainCode) and cannot replace
    an xpub-like concept.

**xpub/xprv**
- BIP32 extended keys: `(pubkey or privkey) + chaincode + metadata`, enabling
  non-hardened public derivation in Bitcoin.
- PQHD explicitly does not use xpub/xprv because PQ signature keys do not have
  a safe “public derivation” mechanism.

**Master seed**
- 32 bytes from a CSPRNG, stored encrypted in wallet storage.

**NodeSecret**
- 32 bytes of secret state at each HD node in the PQHD tree.
- Not a scalar; just secret material.

**ChainCode**
- 32 bytes secret per node used as an HMAC key for child derivation.

**Hardened derivation**
- A derivation that requires secret data to derive children.
- In PQHD, we use hardened-only everywhere by design.

**Change branch**
- `change = 0`: external/receive addresses
- `change = 1`: internal/change addresses

---

## 2. Scheme IDs / Prefix Bytes (Repo Reality)

From `src/pq/pq_scheme.h`:

| Scheme | SchemeId / Prefix |
|---|---:|
| Falcon-512 | `0x07` |
| Falcon-1024 | `0x08` |
| ML-DSA-44 | `0x09` |
| ML-DSA-65 | `0x0A` |
| ML-DSA-87 | `0x0B` |

Notes:
- SchemeId space is 0..255 (by design; uint8_t).
- There is an “experimental” prefix range reserved (`0xF0..0xFF`) in
  `src/pq/pq_scheme.h`.

### 2.1 Per-scheme byte sizes (repo constants)

These are the compiled PQClean constants used by `pq::SchemeInfo`
(`src/pq/pq_scheme.h`) and the per-scheme `api.h` headers under `src/pq/`.

Note: `TidePubKey` adds 1 byte of prefix to the public key bytes.

| Scheme | Prefix | Pubkey bytes | TidePubKey bytes | Seckey bytes | Sig max bytes | Sig fixed bytes |
|---|---:|---:|---:|---:|---:|---:|
| Falcon-512 | 0x07 | 897 | 898 | 1281 | 752 | 666 |
| Falcon-1024 | 0x08 | 1793 | 1794 | 2305 | 1462 | 1280 |
| ML-DSA-44 | 0x09 | 1312 | 1313 | 2560 | 2420 | 2420 |
| ML-DSA-65 | 0x0A | 1952 | 1953 | 4032 | 3309 | 3309 |
| ML-DSA-87 | 0x0B | 2592 | 2593 | 4896 | 4627 | 4627 |

Implications:
- Any “fixed-size pubkey container” design (like current `CPubKey::SIZE`) is
  Falcon-512-specific and cannot represent the other schemes.
- Multi-scheme wallet + descriptor + PSBT work requires a scheme-aware/variable
  length public-key container (or a new byte-oriented PQ pubkey type).

### 2.2 Consensus-critical warning: pubkey encoding is committed on-chain

Because the prefix byte is part of the pubkey byte string, it affects any
construction that commits to pubkey bytes, including:
- `HASH160(tide_pubkey)` (P2PKH/P2WPKH-style commitments)
- any script/witness that directly pushes the pubkey bytes

Therefore:
- changing scheme-id encoding (e.g., 1-byte prefix → varint) is a **hardfork**
  once there are UTXOs on-chain that commit to the old encoding.

Conclusion:
- treat the current 1-byte scheme prefix encoding as stable consensus surface.

---

## 3. Addresses, HASH160, and PQ Security Margin

Current output types (P2PKH/P2WPKH-like) commit to:
- `HASH160(tide_pubkey)` (where tide_pubkey includes the scheme prefix)

This has important implications:
- Different schemes yield different addresses because the prefix byte changes
  the committed bytes.
- The address itself doesn’t “encode the scheme” explicitly; scheme becomes
  obvious when the pubkey is revealed at spend.

PQ-security concerns (long-term):
- Classical second-preimage on 160-bit hash is ~2^160.
- Under Grover, this drops to ~2^80 (and multi-target search reduces effective
  cost further across many UTXOs).
- HASH160 is a deliberate truncation choice from 2008; it is not designed for
  PQ longevity.

Implication:
- it is reasonable to ship PQHD using current output types short-term, but we
  should plan a PQ-native output type with >=256-bit commitments at a hardfork
  boundary (e.g., auxpow activation).

---

## 4. Keypair Entropy Consumption (PQClean Reality)

From current in-tree implementations:
- Falcon-512 / Falcon-1024 keypair: 48 bytes of random seed.
- ML-DSA-44/65/87 keypair: 32 bytes (SEEDBYTES=32).
- ML-KEM-512 keypair: 64 bytes (2*KYBER_SYMBYTES=64).

PQHD must not assume a fixed “seed length per scheme”. Instead:
- PQHD must provide a deterministic randomness **stream** that supplies any
  number of bytes needed by the scheme’s keygen.
- This makes PQHD robust to upstream changes (e.g., if PQClean consumes
  randomness differently in future versions).

---

## 5. Why Hardened-Only? (BIP32 meaning and PQ implication)

In classic BIP32:
- non-hardened children allow public derivation (xpub → child pubkeys)
- hardened children require private derivation (xprv only)

For PQ signature schemes (Falcon/ML-DSA):
- there is no group law enabling “pubkey tweak” derivation like secp256k1.
- therefore public derivation is not available (no safe xpub equivalent).

PQHD invariant:
- **all child derivations are hardened**
- watch-only cannot auto-extend from a public token
- watch-only must be explicit-only or bounded-export

---

## 6. PQHD Path Structure

We use a familiar shape but hardened-only at every level:

`m / purpose' / coin_type' / scheme' / account' / change' / address_index'`

### 6.1 Scheme index mapping (decision)
Decision:
- `scheme'` value is the same number as the 1-byte SchemeId/prefix.
  - Falcon-512: `scheme' = 7'`
  - ML-DSA-65: `scheme' = 10'`

### 6.2 Purpose constant (still to finalize)
The purpose field is a namespace selector (BIP43 concept).

Recommendation:
- choose a Tidecoin-specific purpose in SLIP/BIP43 reserved range 10001–19999
  (avoid implying BIP44 semantics).

Candidate:
- 10007' (mnemonic tie to Falcon-512 prefix 0x07)

### 6.3 coin_type' (still to finalize)
Must be defined for wallet discovery. Options:
- register in SLIP-0044 (preferred long-term)
- define a Tidecoin-internal constant (short-term)

---

## 7. PQHD v1: Concrete Derivation + Deterministic RNG Specification

This section is intended to be implementable and testable. If adopted, it must
ship with test vectors and be treated as versioned spec (“PQHD v1”).

### 7.1 Constants (ASCII)
- `PQHD_MASTER_KEY = "Tidecoin PQHD seed"`
- `PQHD_HKDF_SALT  = "Tidecoin PQHD hkdf v1"`
- `PQHD_STREAM_INFO = "Tidecoin PQHD stream key v1"`
- `PQHD_RNG_PREFIX = "Tidecoin PQHD rng v1"`

Helper:
- `ser32be(i)` = 32-bit unsigned integer big-endian.

### 7.2 Master node generation
Input:
- `master_seed`: 32 bytes

Compute:
- `I = HMAC-SHA512(key=PQHD_MASTER_KEY, msg=master_seed)`
- `NodeSecret = I[0:32]`
- `ChainCode  = I[32:64]`

### 7.3 Child derivation (hardened-only)
Given parent `(NodeSecret_par, ChainCode_par)` and hardened index `i_h`:
- `data = 0x00 || NodeSecret_par || ser32be(i_h)`
- `I = HMAC-SHA512(key=ChainCode_par, msg=data)`
- `NodeSecret_child = I[0:32]`
- `ChainCode_child  = I[32:64]`

Notes:
- Unlike BIP32, there is no “invalid scalar” edge case.

### 7.4 Leaf → deterministic randomness stream for PQClean keygen
Given `NodeSecret_leaf`:

1) HKDF-Extract (HMAC-SHA512):
- `PRK = HMAC-SHA512(key=PQHD_HKDF_SALT, msg=NodeSecret_leaf)`

2) HKDF-Expand to 64-byte stream key:
- `info = PQHD_STREAM_INFO || ser32be(scheme_id) || concat(ser32be(path_elem_i))`
- `stream_key = HKDF-Expand(PRK, info, L=64)`

3) Deterministic stream blocks:
For counter `ctr = 0,1,2,...`:
- `block_ctr = HMAC-SHA512(key=stream_key, msg=PQHD_RNG_PREFIX || ser32be(ctr))`

Stream is concatenation of blocks.

### 7.5 Deterministic keypair generation rule
- Determine `scheme_id` from path `scheme'` element.
- Instantiate deterministic stream from §7.4.
- Override PQClean `randombytes(out, n)` so it consumes from the stream.
- Call scheme’s PQClean keypair.
- Construct TidePubKey = prefix byte || pk bytes.

Implementation constraint:
- The deterministic RNG override must be **scoped** (RAII/thread-local) so no
  unrelated code draws from the deterministic stream by accident.

---

## 8. Seed Identity and Collision Handling

### 8.1 Current repo reality: no collision rules
The current repository does not implement explicit collision handling rules for:
- 4-byte master fingerprints (`KeyOriginInfo::fingerprint`)
- `hd_seed_id` (20-byte Hash160 identifier in legacy wallet metadata)

Values are assumed unique and used as-is.

### 8.2 Existing “analogues” (background only; not used for PQHD)
The wallet/descriptor system already has short identifiers/origin metadata:
- `hd_seed_id` (20 bytes): stored per-key metadata and exposed via RPC as
  `hdseedid` (Hash160-derived identifier).
- 4-byte master fingerprint: used in descriptors/PSBT origin records.

These are fine in Bitcoin’s BIP32 model because xpubs/xprvs (or descriptors that
embed them) provide a strong disambiguator. In PQHD we explicitly avoid any
xpub-like token, so **we will not reuse these short identifiers** for PQHD seed
references.

### 8.3 Decision: SeedID32 only (no short handles)

Decision:
- Use a **32-byte canonical seed identifier** (`SeedID32`) everywhere.
- Do not introduce 4-byte or 8-byte short seed handles, even for display.

Rationale:
- In PQHD descriptors and PSBT origin metadata, the seed reference is the only
  root pointer (there is no xpub-like disambiguator). Any truncated identifier
  introduces an ambiguity risk that can break restore/signing workflows.

Definition:
- `SeedID32 = SHA256("Tidecoin PQHD seedid v1" || master_seed)`

Storage/display rules:
- Wallet DB keys and all exports must use full `SeedID32` (64 hex chars when
  printed).
- If we want a user-friendly label, it must be a free-form name stored in the
  wallet (not a truncated identifier).
- Seed imports must be de-duplicated by `SeedID32` (re-importing the same seed
  yields the same internal seed record, not multiple entries).

---

## 9. Descriptor Strategy (PQ-aware)

New wallets should be descriptor wallets internally. PQHD introduces one new
key expression (`pqhd(...)`), and otherwise uses existing descriptor constructs
unchanged.

### 9.0 Guiding goals
- Keep descriptor strings “Bitcoin-shaped” where possible to minimize invasive
  changes across wallet/RPC/Qt.
- Avoid introducing any short seed handles (no fingerprints/aliases); the
  descriptor must carry the full SeedID32.
- Make canonical printing deterministic so descriptor checksums are stable.

### 9.1 Explicit pubkeys: use hex TidePubKey (no new wrapper)
Descriptor KEY expressions already support raw hex public keys:
- `wpkh(<hex_pubkey>)`
- `wsh(sortedmulti(2,<hex_pubkey_1>,<hex_pubkey_2>,...))`

For Tidecoin, the canonical explicit key representation is:
- `<hex_pubkey> = hex(tide_pubkey)`
- `tide_pubkey = <SchemeId-prefix byte> || <scheme_pubkey_bytes>`

This matches current descriptor implementation behavior:
`ConstPubkeyProvider::ToString()` prints pubkeys as raw hex.

### 9.2 PQHD key expression: `pqhd(<SeedID32>)`

We introduce a new KEY expression that references a wallet-stored PQHD seed:

- `pqhd(<seedid32_hex>)/<path>`

Where:
- `<seedid32_hex>` is exactly 64 hex characters (32 bytes).
- `<path>` follows descriptor/BIP32-style syntax (slash-separated indices), but
  with PQHD-specific restrictions below.

#### 9.2.1 Path restrictions (PQHD v1)
- Hardened-only: every component must be hardened (`h` or `'`).
- If the key expression is ranged, the terminal wildcard must be `/*h` (or `/*'`).
- Multipath expressions (`{a,b}`) are not supported for PQHD v1.
- `m` prefix is not used inside the descriptor key expression.

Canonical keypool templates (receive/change):
- Receive: `wpkh(pqhd(<SeedID32>)/<purpose>h/<coin>h/<scheme>h/<account>h/0h/*h)`
- Change:  `wpkh(pqhd(<SeedID32>)/<purpose>h/<coin>h/<scheme>h/<account>h/1h/*h)`

Scheme rules:
- The `scheme` path component value must equal the 1-byte SchemeId/prefix.
  Example: Falcon-512 uses `7h`, ML-DSA-65 uses `10h`.
- Derived pubkeys must serialize with the same SchemeId prefix.

Solvability:
- `pqhd(...)` is solvable only when the wallet contains the referenced seed
  material (stored encrypted separately). The descriptor never contains the
  master seed itself.

#### 9.2.2 Canonical printing rules
To keep descriptor strings stable:
- Always print hardened components using `h` (not `'`).
- Always print `<seedid32_hex>` as lowercase hex.
- Always print indices in decimal (matching `FormatHDKeypath` behavior).
- For PQHD, `ToString()`, `ToNormalizedString()`, and `ToPrivateString()` all
  print the same `pqhd(<SeedID32>)/...` form (no secrets are ever embedded in
  descriptors).

---

## 10. PSBT (BIP174) Strategy for PQHD

Decision:
- Keep standard BIP174 PSBT framing and existing RPC/Qt workflows.
- Do not introduce a separate “TidePSBT” container format at this stage.
- Store PQHD origin metadata in PSBT proprietary fields (BIP174 type 0xFC),
  so we avoid reinterpreting BIP32/xpub fields and we avoid any short seed
  handles/fingerprints.

Rationale:
- Minimal disruption to existing wallet/RPC/Qt behavior.
- PSBT already has a proprietary key/value mechanism, and `decodepsbt` already
  exposes proprietary entries.
- External tool compatibility is not a goal; internal correctness/ergonomics is.

### 10.0 What stays vs what changes (field-by-field)

We keep PSBT as “the container” (BIP174 framing, base64 in RPC, same core flows:
create → update → sign → finalize → extract). The changes are primarily about
which optional metadata fields we populate.

Key points:
- PQ signatures do not require any change to the PSBT container; signatures are
  just byte vectors attached to pubkeys/scripts.
- BIP32/xpub-related metadata will not be written by PQHD wallets, because:
  - there is no xpub concept for PQHD, and
  - BIP32 derivation records encode a 4-byte fingerprint (a truncated handle),
    which we decided to avoid for PQHD (SeedID32 only).
- We still parse/retain these legacy fields for interoperability with existing
  PSBTs and to avoid unnecessary churn, but PQHD logic ignores them.

Field matrix (“PQHD wallet behavior”):

**Global PSBT map**
- `PSBT_GLOBAL_UNSIGNED_TX`: keep (required)
- `PSBT_GLOBAL_VERSION`: keep (required by v2/optional by v0, but we keep)
- `PSBT_GLOBAL_PROPRIETARY`: keep (used for extensions; optional)
- `PSBT_GLOBAL_XPUB`: parse/retain only; PQHD wallet does not write

**Per-input PSBT map**
- `PSBT_IN_NON_WITNESS_UTXO`: keep (sometimes required for signing)
- `PSBT_IN_WITNESS_UTXO`: keep (preferred for segwit inputs; smaller)
- `PSBT_IN_PARTIAL_SIG`: keep (holds PQ script signatures; algorithm-agnostic)
- `PSBT_IN_SIGHASH`: keep (still needed: SIGHASH type is part of script sig)
- `PSBT_IN_REDEEMSCRIPT`: keep (P2SH / nested cases)
- `PSBT_IN_WITNESSSCRIPT`: keep (P2WSH / nested cases)
- `PSBT_IN_BIP32_DERIVATION`: parse/retain only; PQHD wallet does not write
- `PSBT_IN_[RIPEMD160|SHA256|HASH160|HASH256]` preimages: keep (script tooling)
- `PSBT_IN_PROPRIETARY`: keep (used for `tidecoin/PQHD_ORIGIN`)
- `PSBT_IN_[SCRIPTSIG|SCRIPTWITNESS]` final fields: keep (finalize step)

**Per-output PSBT map**
- `PSBT_OUT_REDEEMSCRIPT`: keep (for P2SH outputs)
- `PSBT_OUT_WITNESSSCRIPT`: keep (for P2WSH outputs)
- `PSBT_OUT_BIP32_DERIVATION`: parse/retain only; PQHD wallet does not write
- `PSBT_OUT_PROPRIETARY`: keep (used for `tidecoin/PQHD_ORIGIN` on change outputs)

What changes in user-visible RPC output:
- `decodepsbt` will still show `global_xpubs` and `bip32_derivs` arrays (because
  the RPC schema is generic), but for PQHD wallets these will usually be empty.
- The PQHD path/seed linkage will instead be present under `proprietary` (and
  later we can add a parsed JSON view for `tidecoin/PQHD_ORIGIN`).

What changes in the `bip32derivs` knob:
- Today `walletprocesspsbt(..., bip32derivs=true)` means “include KeyOriginInfo
  (4-byte fingerprint + path) via `GetKeyOrigin()`”.
- For PQHD we keep the knob for UX/backward compatibility, but its meaning
  becomes: “include origin metadata”, implemented as writing
  `tidecoin/PQHD_ORIGIN` proprietary records (SeedID32 + hardened path).
  The RPC help text will need updating when we implement PQHD.

### 10.1 What we will not use for PQHD
- `PSBT_GLOBAL_XPUB` (no xpub concept for PQHD).
- `PSBT_IN_BIP32_DERIVATION` / `PSBT_OUT_BIP32_DERIVATION` for PQHD (these embed
  a 4-byte fingerprint by design).

These fields may remain for legacy/non-PQHD wallets, but PQHD itself will not
populate them.

Important repo constraint:
- Current PSBT code still uses `CPubKey` as the “pubkey-sized key” for several
  standard fields (e.g., `PSBT_IN_PARTIAL_SIG` parsing checks
  `key.size() == CPubKey::SIZE + 1` in `src/psbt.h`).
- Because `CPubKey` is currently Falcon-512-only, full multi-scheme PSBT support
  will require updating these assumptions (even if PQHD metadata is carried via
  proprietary fields).

### 10.2 Tidecoin proprietary PSBT fields (registry)

We define one proprietary family under the identifier:
- `identifier = "tidecoin"` (ASCII bytes)

Subtypes (CompactSize integers):
- `subtype = 1`: `PQHD_ORIGIN`

`PQHD_ORIGIN` is valid in:
- PSBT input maps (`PSBT_IN_PROPRIETARY`)
- PSBT output maps (`PSBT_OUT_PROPRIETARY`)

Keydata format:
- `keydata = <tide_pubkey_bytes>` (the exact pubkey bytes, including 1-byte SchemeId prefix)

Value format:
- `value = <SeedID32> || <path>`
  - `<SeedID32>`: 32 bytes (as defined in §8.3)
  - `<path>`: zero or more `uint32` indices, serialized using Bitcoin’s standard
    integer serialization (little-endian), matching existing PSBT derivation
    style. Every element must be hardened (`index & 0x80000000 != 0`).

Consistency rules:
- The SchemeId prefix in `<tide_pubkey_bytes>` must equal the `scheme` element
  inside `<path>`, if present.
- If `<path>` is empty, the record is still valid as a “seed association” but
  is insufficient for deterministic derivation; wallet/signers may treat it as
  informational only.

### 10.3 RPC/Qt surface (planned behavior)

We keep existing RPC names and payloads (base64 PSBT). We extend interpretation:

- `walletprocesspsbt` (when `bip32derivs=true`):
  - Add `tidecoin/PQHD_ORIGIN` proprietary records for all PQHD-derived keys
    involved in the PSBT (inputs and relevant outputs).
  - Do not add `bip32_derivs` for PQHD.

- `decodepsbt`:
  - Continue to expose raw proprietary entries (already implemented).
  - Planned: add a parsed view (new JSON fields) for Tidecoin PQHD origin, e.g.:
    - `pqhd_derivs`: list of `{ pubkey, seedid32, path }`
    - `path` formatted using `WriteHDKeypath(..., apostrophe=false)` so hardened
      elements use `h` markers.

- `analyzepsbt` / Qt PSBT operations:
  - Planned: treat PQHD origin metadata as informational and use it to report
    “missing signatures” per scheme/path in a human-friendly way.

None of these are consensus critical; they are wallet/tooling UX.

### 10.4 Optional cleanup (later): remove xpub/BIP32 PSBT metadata

PQHD v1 keeps BIP174 PSBT framing and keeps parsing/round-tripping legacy PSBT
metadata (xpubs, BIP32 derivations), but PQHD itself will not write them.

Once PQHD origin metadata is fully implemented and stable, we can optionally do
a “cleanup” pass to remove xpub/BIP32-specific parts from Tidecoin’s PSBT stack,
to reduce surface area and avoid any confusion around `bip32derivs`/xpub in a
PQ-only wallet world.

Two reasonable cleanup levels (choose later):

**A) Soft cleanup (recommended first)**
- Continue to accept and preserve existing PSBTs that contain:
  - `PSBT_GLOBAL_XPUB`
  - `PSBT_IN_BIP32_DERIVATION` / `PSBT_OUT_BIP32_DERIVATION`
- But stop treating them as “first-class structured data”:
  - parse them as unknown/proprietary key/value pairs instead
  - do not expose dedicated JSON (`global_xpubs`, `bip32_derivs`) in `decodepsbt`
- This keeps PSBT round-trip semantics while simplifying internal structures.

**B) Hard cleanup (strict Tidecoin-only)**
- Reject or drop the above legacy fields during PSBT parsing/merging.
- This is simplest internally, but it breaks interoperability with PSBTs that
  include those fields (even if Tidecoin otherwise doesn’t use them).

Code touchpoints for cleanup:
- PSBT core:
  - `src/psbt.h`: cases for `PSBT_GLOBAL_XPUB`, `PSBT_IN_BIP32_DERIVATION`,
    `PSBT_OUT_BIP32_DERIVATION`; data members `PartiallySignedTransaction::m_xpubs`,
    `PSBTInput::hd_keypaths`, `PSBTOutput::hd_keypaths`.
  - `src/psbt.cpp`: merge logic for `m_xpubs`; signature-data plumbing that
    currently threads `hd_keypaths` into `SignatureData`.
- Wallet/descriptor integration:
  - `src/wallet/scriptpubkeyman.cpp`: `FillPSBT(..., bip32derivs=...)` currently
    hides/exposes `KeyOriginInfo` via `GetKeyOrigin(...)`.
  - `src/wallet/rpc/spend.cpp`: RPC arg `bip32derivs` naming/help text.
- RPC output:
  - `src/rpc/rawtransaction.cpp`: `decodepsbt` schema fields `global_xpubs` and
    `bip32_derivs` (and their help strings).
- Tests:
  - any wallet/PSBT unit tests and RPC functional tests that assert presence of
    `global_xpubs` / `bip32_derivs` (must be updated if we remove/repurpose them).

Decision note:
- This cleanup is explicitly *optional* and should be scheduled only after PQHD
  origin metadata (`tidecoin/PQHD_ORIGIN`) is fully integrated into
  walletprocesspsbt/PSBT analysis and we have confidence in the replacement UX.

---

## 11. Watch-Only Wallets

Because there is no public derivation token:
- watch-only cannot auto-extend like xpub wallets
- supported workflows:
  - explicit-only imports (pubkeys/scripts/descriptors)
  - bounded export from signer (export next N pubkeys/addresses)

---

## 12. Wallet Storage and Migration

### 12.1 Legacy wallet reality
- oldtidecoin uses legacy BDB wallet storage.
- HD scaffolding exists, but HD is effectively disabled in practice:
  - `CWallet::GenerateNewKey()` asserts `!IsHDEnabled()` and always uses random
    key generation; HD derivation branch is commented.
  - keypool/upgrade logic is guarded similarly; HD seed activation is commented.

Implication:
- migration from oldtidecoin BDB wallets should treat them as **non-HD** and
  import concrete keys (and any watch-only scripts). Ignore HD metadata if
  present.

### 12.2 Migration approach (target)
- Import old keys as explicit entries (no derivation).
- Create one PQHD seed for new deterministic keypool usage.
- Generate new receive/change descriptors driven by PQHD.
- Optionally sweep funds into PQHD-derived outputs for cleanliness.

Note:
- multi-scheme support does not require multiple seeds; scheme separation is a
  path component and domain separation input. Multiple seeds remain possible
  for compartmentalization or multiple signers.

### 12.3 Scheme selection policy (wallet vs `pq::ActiveScheme`)

The codebase currently has a notion of an “active scheme” in the PQ API:
- `pq::ActiveScheme()` returns Falcon-512 unconditionally (`src/pq/pq_api.h:72`).
- It is used as a default scheme when generating a new random key in
  `CKey::MakeNewKey()` (`src/key.cpp:37`).

This is acceptable for the current single-scheme world, but it does not scale
to a multi-scheme PQHD wallet. For PQHD:
- **Scheme selection must be a wallet policy decision**, not a crypto-library
  global.
- **Signing/verifying must always be per-key**, driven by the key’s scheme
  (ultimately: the prefix byte in the serialized TidePubKey).

Practical design:
- Wallets can hold keys for multiple schemes simultaneously (legacy imports +
  PQHD-derived keys + future scheme keys).
- The wallet needs an explicit policy for **which scheme to use for new keys**
  (receive addresses) and **which scheme to use for change outputs**.

#### 12.3.1 Default scheme (receive addresses)

Proposed behavior:
- The wallet stores a **default scheme id** (e.g. `default_scheme_id`) used when
  generating new receive keys/addresses (via the external keypool / receive
  descriptor).
- RPC/UI can override this per call (e.g. `getnewaddress scheme=...`) without
  changing the wallet default.

Implementation implication for PQHD:
- New wallets should maintain per-scheme receive descriptors/templates, and
  “default scheme” chooses which descriptor is used for `getnewaddress`.

#### 12.3.2 Change scheme selection

We need an explicit rule for the scheme used by automatically-generated change
outputs. Proposed precedence (most specific wins):
1) If the user provides an explicit change destination (RPC `change_address` /
   CoinControl destChange), the scheme is implicitly fixed by that destination.
2) Else if the user provides an explicit `change_scheme` override (new RPC /
   CoinControl option), use it.
3) Else if the wallet has a default change scheme (e.g. `default_change_scheme_id`),
   use it; otherwise fall back to the wallet default scheme.

This mirrors how output type selection works today:
- output type is controlled by `-changetype` / `m_default_change_type`
  (`src/wallet/wallet.h:742`)
- scheme selection should be controlled by an analogous wallet setting and/or
  RPC/CoinControl override.

Important: output type and scheme are independent knobs:
- Output type selects the script template (legacy vs segwit v0, etc.).
- Scheme selects which TidePubKey bytes are committed to/revealed.

#### 12.3.3 Keypool implications (per-scheme)

Because schemes differ in key sizes and (future) policies/activation heights:
- Keypools should be tracked per-scheme, and split by external vs internal
  (`change=0` vs `change=1`).
- The wallet should be able to “top up” each per-scheme keypool independently.

#### 12.3.4 Consensus/policy interplay

Scheme selection policy must align with network policy and hardfork activation:
- The wallet should avoid generating new keys for schemes that are not yet
  activated (or are deprecated) for the intended inclusion height.
- When a future hardfork activates new default schemes (or PQ-native output
  types), the wallet may update its defaults, but must still be able to spend
  older-scheme UTXOs.

---

## 13. Consensus/Policy Hooks (Interplay)

Existing direction in code:
- PQ strictness can be gated via `SCRIPT_VERIFY_PQ_STRICT` and activated by
  height (e.g., `nAuxpowStartHeight`).

PQHD should align with consensus/policy activation:
- disallow generating new keys for deprecated schemes after activation heights
  (wallet policy)
- select new default output types (PQ-native commitments) after hardfork
- ensure wallet/PSBT analysis uses the intended consensus flags based on chain
  tip or target inclusion height

---

## 14. Test Vectors (Required)

If PQHD v1 is adopted, we must ship:
- derivation test vectors (master → path → NodeSecret/ChainCode)
- RNG stream test vectors (first N bytes for given leaf)
- per-scheme keygen reproducibility tests inside our own build (because it
  depends on the deterministic `randombytes()` override behavior)

Any “example vectors” from drafts must be treated as non-authoritative until
validated by an implementation + tests.

---

## 15. Decisions and Open Questions

### Decided
- SchemeId is 1-byte prefix and stable.
- scheme index in PQHD path equals SchemeId/prefix.
- Hardened-only derivation, no xpub.
- PQHD deterministic RNG must be stream-based (not “fixed N bytes”).
- Seed references use full SeedID32 only (no short handles).
- Descriptors: explicit TidePubKey keys are raw hex; PQHD uses `pqhd(<SeedID32>)/...` and canonical printing uses `h`.
- PSBT: keep BIP174 PSBT framing; store PQHD origin in `tidecoin` proprietary keys (`subtype=1`).
- Scheme selection for new keys is wallet policy (default receive scheme + change scheme), not `pq::ActiveScheme()`.
- Watch-only is explicit-only or bounded export.
- PQ-native output type planned at auxpow hardfork boundary.

### Still to finalize
- purpose' constant for PQHD subtree.
- coin_type' constant.
- Concrete RPC/Qt surface for scheme policy overrides (names + UX).
- (Optional) whether `PQHD_ORIGIN` is also written for outputs that are not
  change/receive but still contain PQHD-derived pubkeys (e.g., multisig).
- (Optional, later) PSBT cleanup: remove xpub/BIP32 PSBT metadata (see §10.4).

---

## 16. Implementation Readiness (What We Still Need)

Before we start implementing PQHD, we should lock down these items to avoid
large rework:

### 16.1 Remaining spec decisions
- `purpose'` and `coin_type'` constants (wallet discovery, restore behavior).
- Clarify whether PQHD v1 supports exactly one “wallet PQHD seed” vs multiple
  seeds per wallet (the spec allows multiple; UX may prefer one).

### 16.2 Major code prerequisites
- Multi-scheme public key handling:
  - Current `CPubKey` is Falcon-512-only (`src/pubkey.h:36`), but PQHD targets
    Falcon-1024 and ML-DSA schemes with larger pubkeys (§2.1).
  - We need to decide between:
    - refactoring `CPubKey` to be scheme-aware/variable-length, or
    - introducing a new PQ pubkey byte container type and migrating call sites.
- Consensus/policy size limits vs scheme sizes:
  - Falcon-1024 / ML-DSA signatures and pubkeys exceed legacy Bitcoin script
    element sizes; we must ensure our consensus limits and mempool policy can
    accept transactions produced by future schemes (likely gated by height).
- Wallet database schema for PQHD seed storage:
  - Define how `master_seed`, `NodeSecret`, and `ChainCode` are stored encrypted
    (and how backups/restore work), including versioning of PQHD seed records.
- Deterministic keygen stability contract:
  - PQHD v1 currently relies on “deterministic `randombytes()` stream + PQClean
    keypair call”. Any PQClean upgrade that changes randomness consumption can
    change derived keys unless we freeze code or define stable per-scheme
    keygen-from-seed APIs.

### 16.3 Tooling integration that must exist for a usable first release
- Descriptors:
  - Add parsing/serialization support for `pqhd(<SeedID32>)/...` (§9.2).
  - Ensure descriptor checksum stability under canonical printing rules (§9.2.2).
- PSBT:
  - Implement `tidecoin/PQHD_ORIGIN` write/read paths in walletprocesspsbt and
    PSBT analysis (§10.2–§10.3).
  - Update RPC help text for `bip32derivs` to reflect “origin metadata” rather
    than BIP32 fingerprints/paths (when PQHD is enabled).
- Watch-only workflow:
  - Define concrete “bounded export” RPC(s) for ranges of derived pubkeys (or
    descriptors expanded to explicit pubkeys), because there is no xpub.

### 16.4 Tests that must be in place to avoid silent breakage
- PQHD test vectors for derivation + deterministic RNG stream (§14).
- Per-scheme keygen reproducibility tests (same seed/path must yield same pk/sk
  across platforms/builds).
- Wallet restore tests (wipe wallet DB, restore from seed, confirm address
  regeneration and signing works).

---

## 17. Implementation Risks (What Can Go Wrong)

### 17.1 Large refactor blast radius (`CPubKey`)
- `CPubKey` is used across scripts, wallet key maps, descriptors, PSBT parsing,
  and RPC output; making it variable-length or introducing a parallel PQ key
  type will touch many call sites (high regression risk).

### 17.2 Consensus/policy mismatches
- If the wallet starts generating keys for schemes whose pubkeys/signatures do
  not fit current consensus/policy limits, it can create transactions that are
  locally valid but rejected by the network (funds “stuck” until hardfork).

### 17.3 Deterministic RNG scoping mistakes
- A global/unguarded deterministic `randombytes()` override can accidentally
  leak into signing/non-keygen code paths (catastrophic for security).
- Must be strictly scoped (thread-local + RAII) and covered by tests.

### 17.4 PQClean upgrades and long-term restorability
- If PQHD keygen depends on PQClean’s internal randomness consumption pattern,
  updating PQClean can change derived keys for the same seed/path.
- Mitigation: freeze PQClean code used for PQHD v1, or define explicit stable
  “KeyGenFromSeed” wrappers and bump PQHD version when changing algorithms.

### 17.5 Performance and UX
- PQ keygen is significantly more expensive than secp derivation; keypool refill
  and descriptor range expansion can become slow without caching/background work.
- SeedID32-only references make descriptors longer; UI/RPC must handle this
  cleanly (labels, not truncated IDs).

### 17.6 External signer / hardware wallet ecosystem
- Standard PSBT `bip32_derivs` and `global_xpubs` won’t be populated for PQHD.
  Any external tooling must understand `tidecoin/PQHD_ORIGIN` proprietary fields.

---

## Appendix: Code Touchpoints (Current)

- Scheme registry: `src/pq/pq_scheme.h`
- PQ pubkey encode/decode: `src/pq/pq_api.h`
- Existing origin metadata structures: `src/script/keyorigin.h`
- Wallet key metadata: `src/wallet/walletdb.h`
- oldtidecoin legacy wallet behavior: `/home/yaroslav/dev/tidecoin/oldtidecoin/tidecoin/src/wallet/wallet.cpp`
