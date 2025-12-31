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
- Deterministic key generation contract:
  - versioned per-scheme `KeyGenFromSeed` wrappers (see §7.5) so wallet restore
    is stable across Tidecoin/PQClean upgrades.
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
    requires refactoring `CPubKey` to be scheme-aware/variable-length.
    Decision: **refactor `CPubKey`** (see §16.2).
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

### 6.2 Purpose constant (decision)
The purpose field is a namespace selector (BIP43 concept).

Decision:
- `purpose' = 10007'`

Rationale:
- Tidecoin PQHD is not BIP44 (extra `scheme'` component, hardened-only
  everywhere), so using `44'` would be misleading.
- 10007 is in the SLIP/BIP43 reserved range 10001–19999 and is mnemonic with
  the historical Falcon-512 prefix `0x07`.

### 6.3 coin_type' (decision)
Decision:
- `coin_type' = 6868'`

Notes:
- This is a Tidecoin-internal constant for now (not yet registered in SLIP-0044).
- This value must be treated as stable once shipped, because changing it breaks
  wallet restore/discovery (it changes the derivation subtree).

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

### 7.4 Leaf → deterministic keygen material (PQHD v1)
Given `NodeSecret_leaf` and the full hardened path (including the hardened `scheme'` element at index 2):

1) HKDF-Extract (HMAC-SHA512):
- `PRK = HMAC-SHA512(key=PQHD_HKDF_SALT, msg=NodeSecret_leaf)`

2) HKDF-Expand to a 64-byte keygen stream key:
- `scheme_id = (path_hardened[2] & 0x7FFFFFFF)` and MUST fit into one byte (`scheme_id <= 255`)
- `info = PQHD_STREAM_INFO || ser32be(scheme_id) || concat(ser32be(path_elem_i))`
- `stream_key = HKDF-Expand(PRK, info, L=64)`

3) Deterministic stream blocks:
For counter `ctr = 0,1,2,...`:
- `block_ctr = HMAC-SHA512(key=stream_key, msg=PQHD_RNG_PREFIX || ser32be(ctr))`

Stream is concatenation of blocks.

Notes:
- This stream is **internal PQHD v1 key material**. It is *not* a contract that
  “PQClean will call `randombytes()` the same way forever”. The determinism
  contract is defined in §7.5.
- All path elements MUST be hardened. Any non-hardened element is an error and
  derivation must fail explicitly (no “all-zero node” fallback).

### 7.5 KeyGenFromSeed (per-scheme, versioned) — determinism contract
Decision: **Option B** (selected).

We do **not** define PQHD v1 as “override `randombytes()` and call PQClean
keypair”, because PQClean is free to change how many bytes it consumes (or when),
which would silently change derived keys and break wallet restore.

Instead, PQHD v1 defines a versioned, stable API surface implemented by Tidecoin:

- `KeyGenFromSeed(pqhd_version, scheme_id, key_material[64]) -> (sk, pk)`

Where:
- `pqhd_version` is stored with the seed record (`CPQHDSeedRecord::pqhd_version`,
  see §12.5.1) and is part of the wallet restore contract.
- `scheme_id` is the 1-byte SchemeId/prefix (Falcon-512=7, etc.).
- `key_material` is derived from §7.4 for the leaf path (stream bytes and/or
  derived fixed-length seeds; the exact interpretation is defined by the
  scheme+version wrapper).

PQHD v1 requirements:
- For a given `(SeedID32/master_seed, scheme_id, path)`, the produced `(sk, pk)`
  must be identical across Tidecoin versions and across builds/platforms.
- Any change to a scheme’s `KeyGenFromSeed` behavior must bump `pqhd_version`,
  and new seeds/descriptors must opt into the new version explicitly. Existing
  seeds continue to use their original version indefinitely.

Implementation guidance (non-normative, but strongly preferred):
- Prefer deterministic “seed/coins” keypair entrypoints (e.g. `*_keypair_derand`
  style APIs) or Tidecoin-owned keygen wrappers that do not depend on PQClean’s
  internal randomness consumption pattern.
- Avoid a global `randombytes()` override. If any scoped override is used for
  a legacy scheme wrapper, it must be strictly limited (thread-local + RAII) and
  treated as part of the versioned `KeyGenFromSeed` implementation (i.e., pinned
  behavior for PQHD v1).

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

### 9.1 Explicit pubkeys: use hex TidePubKey (canonical)
Descriptor KEY expressions already support raw hex public keys:
- `wpkh(<hex_pubkey>)`
- `wsh(sortedmulti(2,<hex_pubkey_1>,<hex_pubkey_2>,...))`

For Tidecoin, the canonical explicit key representation is:
- `<hex_pubkey> = hex(tide_pubkey)`
- `tide_pubkey = <SchemeId-prefix byte> || <scheme_pubkey_bytes>`

This matches current descriptor implementation behavior:
`ConstPubkeyProvider::ToString()` prints pubkeys as raw hex.

Rule (frozen for PQHD v1):
- Descriptor “pubkey keys” are interpreted as variable-length `tide_pubkey`
  bytes (`<prefix byte> || <scheme pubkey bytes>`), and are validated by:
  - SchemeId prefix lookup (`src/pq/pq_scheme.h`), and
  - scheme-specific expected length (`SchemeInfo.pubkey_bytes + 1`).
- No secp-specific pubkey assumptions (33/65 bytes) apply to Tidecoin PQ keys.

Optional (later): add a readability wrapper `pkpq(<hex_tide_pubkey>)`.
- This would be syntactic sugar only (parser expands to the raw hex key form).
- Canonical printing should remain the raw hex form so descriptor checksums stay
  stable and we minimize descriptor-system churn.

### 9.2 PQHD key expression: `pqhd(<SeedID32>)`

We introduce a new KEY expression that references a wallet-stored PQHD seed:

- `pqhd(<seedid32_hex>)/<path>`

Where:
- `<seedid32_hex>` is exactly 64 hex characters (32 bytes).
- `<path>` follows descriptor/BIP32-style syntax (slash-separated indices), but
  with PQHD-specific restrictions below.

#### 9.2.1 Path restrictions (PQHD v1)
This section is intentionally strict. PQHD descriptors must be deterministic,
easy to canonicalize, and must not accidentally imply “public derivation” (there
is no xpub).

Allowed path element forms (informal grammar):
- Hardened index: `<n>h` or `<n>'` where `0 <= n < 2^31`
- Terminal ranged wildcard (only as the final path element): `*h` or `*'`

Hard rules:
- Hardened-only: every numeric component must be hardened (`h` or `'`).
- If wildcard is present, it must be the terminal path element and must be
  hardened (`/*h` or `/*'`).
- Exactly one wildcard maximum (or none).
- Multipath expressions are not supported (no `{a,b}` anywhere inside PQHD v1).
- No `m` prefix inside the key expression (use only slash-separated indices).
- No “range endpoints” syntax (e.g. `/<0;100>h`) for PQHD v1.
- Reject negative numbers and reject values `>= 2^31` before hardening.

Canonical keypool templates (receive/change):
- Receive: `wpkh(pqhd(<SeedID32>)/10007h/6868h/<scheme>h/<account>h/0h/*h)`
- Change:  `wpkh(pqhd(<SeedID32>)/10007h/6868h/<scheme>h/<account>h/1h/*h)`

Scheme rules:
- The `scheme` path component value must equal the 1-byte SchemeId/prefix.
  Example: Falcon-512 uses `7h`, ML-DSA-65 uses `10h`.
- Derived pubkeys must serialize with the same SchemeId prefix.

Solvability:
- `pqhd(...)` can only be expanded when the wallet has access to the referenced
  seed record. The descriptor never contains the `master_seed` itself.

#### 9.2.2 Seed availability and wallet behavior

`pqhd()` is a **wallet-private key source**: unlike xpub descriptors (which can
derive pubkeys from public data embedded in the descriptor), `pqhd()` requires
wallet-local seed material.

Wallet usability rules:
- If the wallet does **not** have the referenced `SeedID32`:
  - the descriptor can be parsed as a string, but it is **not usable** by the
    wallet (cannot be expanded into scriptPubKeys, cannot be made active, cannot
    top up keypools).
  - `importdescriptors` must reject such descriptors unless the seed is imported
    first. PQHD v1 does not support “seedless pqhd watch-only”.
- If the wallet has the seed record but is **encrypted and locked**:
  - the wallet can still watch and use already-derived scriptPubKeys that are
    already persisted in the descriptor/keypool state,
  - but cannot derive new pubkeys or top up PQHD keypools (derivation requires
    decrypting `master_seed`),
  - and cannot sign while locked (see §12.5.2A).
- If the wallet is **unlocked**:
  - PQHD derivation and keypool top-up are permitted (subject to scheme policy),
  - signing requires unlocked state, same as any encrypted private key material.

#### 9.2.3 Canonical printing rules
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
- With the decision to refactor `CPubKey` to be variable-length and scheme-aware,
  we must update these fixed-size checks to accept variable-length TidePubKeys
  (while still enforcing internal PSBT invariants like “keydata contains exactly
  one serialized pubkey”).

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
  - Add `tidecoin/PQHD_ORIGIN` proprietary records for all PQHD-derived keys the
    wallet can attribute to a `SeedID32` + hardened path.
  - Write scope (frozen policy for PQHD v1):
    - Inputs: write for every input pubkey that the wallet can sign for (and/or
      that appears in satisfactions/scripts the wallet is expected to satisfy).
    - Outputs:
      - Always write for wallet-owned outputs (includes change outputs).
      - For any wallet-owned output whose script contains PQHD-derived pubkeys
        (including multisig), write `tidecoin/PQHD_ORIGIN` for each such pubkey
        that the wallet recognizes as its own.
      - Never write for recipient outputs that are not wallet-owned (avoid
        leaking internal origin structure; not useful to the recipient).
  - Do not add `bip32_derivs` for PQHD.

- `decodepsbt`:
  - Continue to expose raw proprietary entries (already implemented).
  - Planned: add a parsed view (new JSON fields) for Tidecoin PQHD origin, e.g.:
    - `pqhd_origins`: list of `{ pubkey, seedid32, path }`
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
- Create at least one PQHD seed for new deterministic keypool usage.
- Generate new receive/change descriptors driven by PQHD.
- Optionally sweep funds into PQHD-derived outputs for cleanliness.

Note:
- multi-scheme support does not require multiple seeds; scheme separation is a
  path component and domain separation input.

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

#### 12.3.5 Concrete rule (decided): only Falcon-512 before auxpow

Decision:
- Before auxpow activation (`height < nAuxpowStartHeight`), the wallet MUST only
  generate new outputs (receive/change keypool items) using **Falcon-512**
  (`SchemeId = 0x07`).
- Other schemes (Falcon-1024, ML-DSA-44/65/87) are **disabled for new output
  generation** until auxpow activation.

Rationale:
- Prevents the wallet from creating outputs that may be non-standard, non-relay,
  or otherwise unusable before the hardfork boundary that we already plan to use
  for “big” consensus/policy changes (auxpow + PQ-native output type).
- Keeps pre-auxpow wallet behavior fully compatible with existing Tidecoin chain
  history (Falcon-512-only).

Enforcement requirements:
- Any RPC/Qt per-call override (e.g. `getnewaddress scheme=...`, `change_scheme`,
  or coin control options) MUST be rejected (or ignored with a clear error) when
  it would select a non-Falcon-512 scheme and the intended inclusion height is
  `< nAuxpowStartHeight`.
- The same gating applies to background keypool refill/top-up.
- After auxpow activation (`height >= nAuxpowStartHeight`), additional schemes
  may be enabled for generation (subject to any further policy/consensus gating,
  and likely coupled with switching the default output type to the planned
  PQ-native commitment).

Network notes:
- `nAuxpowStartHeight` is per-network (main/test/regtest) via chainparams.
- For regtest, it is reasonable to set `nAuxpowStartHeight = 0` to make all
  schemes immediately testable, while still exercising the same gating logic.

#### 12.3.6 RPC/Qt surface (frozen) — scheme policy + overrides

This section freezes the user-facing naming, UX, and precedence rules. These
controls determine which per-scheme descriptors/keypools are considered “active”.

Terminology:
- “Receive scheme” controls `getnewaddress` (external keypool / receive descriptors).
- “Change scheme” controls automatically-generated change outputs (internal keypool).

**Persistent wallet policy (stored in wallet DB)**
- `default_receive_scheme_id` (required, `uint8` SchemeId)
  - default for generating new receive addresses.
- `default_change_scheme_id` (optional, `uint8` SchemeId)
  - if unset, change falls back to `default_receive_scheme_id`.

Defaults:
- New wallets default to:
  - `default_receive_scheme_id = 0x07` (Falcon-512)
  - `default_change_scheme_id = unset` (“same as receive”)
- Before auxpow (`height < nAuxpowStartHeight`), any persisted defaults MUST
  resolve to Falcon-512 (§12.3.5).

**Introspection RPC**
- `getwalletinfo` (extended) should report:
  - `receive_scheme` (string + numeric SchemeId)
  - `change_scheme` (string + numeric SchemeId; or `"same_as_receive"`)
  - `auxpow_start_height` (for clarity; from chainparams)
  - (optional) `seed_for_scheme` mapping (SchemeId -> SeedID32) + `default_seedid32`
    to make multi-root policy auditable.

**Wallet policy mutation RPC**
- New RPC (name frozen): `setwalletscheme`
  - Named arguments:
    - `receive_scheme` (required): string scheme name or numeric SchemeId
    - `change_scheme` (optional): string SchemeId, numeric SchemeId, or `"same"`
  - Behavior:
    - Updates wallet defaults persistently (DB write).
    - Validates auxpow gating:
      - if chain tip (or `target_height`, if provided) is `< nAuxpowStartHeight`,
        only `0x07` is accepted.
    - Does not change per-scheme seed policy (that is separate; see §12.4.1).

Scheme encoding in RPC:
- Accept both:
  - numeric SchemeId (e.g. `7`), and
  - canonical names: `falcon512`, `falcon1024`, `mldsa44`, `mldsa65`, `mldsa87`.
- RPC responses should always include both name + numeric id for clarity.

**Per-call overrides (non-persistent)**

Goal: match Bitcoin’s pattern where wallet defaults exist, but transaction
creation calls can override behavior without changing wallet policy.

- `getnewaddress`:
  - Add optional named argument `scheme=<...>` (same encoding rules as above).
  - If provided, it selects which receive descriptor/keypool is used for this call.
  - Gating: must obey §12.3.5 and must return a clear error if disallowed.

- Transaction creation flows (`send`, `walletcreatefundedpsbt`, and any other
  wallet-driven funding RPCs):
  - Add two optional fields to the options object:
    - `scheme` (receive/default scheme override, if a new change output is needed)
    - `change_scheme` (explicit change override)
  - Precedence (frozen):
    1) explicit `change_address` (scheme implied by destination/script)
    2) `change_scheme` override (if present)
    3) wallet `default_change_scheme_id` (if set)
    4) `scheme` override (if present)
    5) wallet `default_receive_scheme_id`
  - Gating:
    - any scheme selection resulting in non-Falcon-512 before auxpow must error.

**Qt UX**
- Wallet settings:
  - “Default signature scheme (receive)” dropdown (Falcon-512, Falcon-1024, ML-DSA-44/65/87).
  - “Default signature scheme (change)” dropdown with:
    - “Same as receive” (default)
    - the same scheme options.
- When auxpow is not active:
  - non-Falcon scheme choices are disabled/hidden, or selectable but show an
    immediate error explaining “available after auxpow activation height”.

**Keypool/descriptor implications**
- The wallet must maintain per-scheme (and per external/internal) keypool state.
- Changing the default scheme does not invalidate existing keys:
  - it only changes which descriptor/keypool is used for new allocations.
- When a scheme becomes newly “active” (policy changed or auxpow activated),
  the wallet should top up the corresponding keypool when unlocked; if locked,
  it should defer and surface “keypool ran out / unlock to refill” semantics
  consistent with Bitcoin (§9.2.2, §12.5.1).

---

### 12.4 Multiple PQHD seeds (multiple roots) — decided

Decision:
- A single wallet can contain **multiple PQHD roots** (multiple `SeedID32`
  entries), similar to how Bitcoin wallets can contain multiple independent
  roots/keys.

Rationale (practical + codebase alignment):
- Descriptor wallets already support importing multiple independent private key
  sources (for Bitcoin: multiple xprv descriptors; see
  `src/wallet/test/psbt_wallet_tests.cpp`).
- Wallet code already has infrastructure for tracking multiple HD chains
  (active + inactive) even in the classic BIP32 world:
  - `m_hd_chain` and `m_inactive_hd_chains` in `src/wallet/scriptpubkeyman.h`
  - loading/migration paths in `src/wallet/walletdb.cpp` and
    `src/wallet/scriptpubkeyman.cpp`
- PQHD has no xpub/public-derivation token; therefore the *only* robust way to
  disambiguate roots in descriptors/PSBT is to carry a full root identifier.
  Supporting multiple roots is safe as long as every derived key is tagged with
  its `SeedID32`.

Implications:
- Every PQHD-derived key must be attributable to exactly one `SeedID32` (stored
  in key metadata and used for PSBT origin export).
- The wallet needs a policy for which root seed is used for new key generation:
  - minimum: one `default_seedid32` per wallet
  - optional: per-scheme defaults (e.g. Falcon keys from seed A, ML-DSA from seed B)
- Spending/signing does not require “default seed” selection: the wallet chooses
  the correct secret by looking up the specific key referenced by the script.

Non-goal:
- We do not attempt to replicate xpub-style “public-only discovery” across roots.
  Watch-only remains explicit-only or bounded export (§11).

#### 12.4.1 PQHD seed lifecycle rules — frozen

This subsection freezes the required behavior for PQHD seed creation/import/
export and “default seed” selection. These rules must be stable because they
affect restore/migration UX and wallet DB policy semantics.

**Seed identity**
- Seeds are uniquely identified by full `SeedID32` only (§8.3). No short aliases
  (4/8 byte fingerprints) are used anywhere, including UI.

**Seed states**
- Each PQHD seed record has an explicit lifecycle state:
  - `ENABLED`: eligible for new receive/change keypool usage.
  - `DISABLED`: not eligible for new keypool usage, but retained for spending
    existing UTXOs (signing) and for scanning/metadata.
- A “deleted” state is **not supported** for PQHD v1 (see deletion policy below).

**Seed creation**
- When creating a new wallet with private keys enabled:
  - Create exactly one PQHD seed by default.
  - Set it as the wallet’s `default_seedid32`.
  - Seed creation uses strong OS randomness (`GetStrongRandBytes(32)`).
- If the wallet already has PQHD seeds, creating another seed is a distinct
  action (“add seed”), not automatic.

**Seed import**
- A PQHD seed import provides `master_seed` (32 bytes) and optional label.
- Compute `SeedID32` and deduplicate by `SeedID32`:
  - If the `SeedID32` already exists, the import is a no-op (idempotent).
- Imported seeds default to `DISABLED` unless the caller explicitly enables
  them or sets them as default (to avoid accidental “silent re-rooting”).
- For encrypted wallets:
  - import requires the wallet to be unlocked (so the seed can be encrypted
    under the wallet master key).

**Seed export**
- Seed export returns `master_seed` (32 bytes) and metadata (`SeedID32`, label,
  created_time).
- For encrypted wallets:
  - export requires the wallet to be unlocked (seed must be decrypted).
- Security property (explicit):
  - exporting a PQHD seed is equivalent to exporting *all* keys under that root.

**Default seed selection (global + per-scheme)**
- Wallet policy stores:
  - a global `default_seedid32`, and
  - optional per-scheme default seed overrides.
- When generating a new receive address (or reserving from receive keypool):
  1) determine `scheme_id` (wallet default or RPC override, §12.3.1),
  2) select `seed_id`:
     - if `policy.seedid32_for_scheme[scheme_id]` exists, use it,
     - else use `policy.default_seedid32`,
  3) require the selected seed to be `ENABLED`; otherwise fail with an explicit
     error and require the user to select/enable a different seed.
- When generating change outputs:
  - determine `change_scheme_id` (§12.3.2), then apply the same `seedid32_for_scheme`
    lookup and `ENABLED` requirement for that scheme.

**Seed disabling**
- Disabling a seed:
  - prevents using it for new receive/change keypool derivation and for future
    address allocation,
  - does **not** remove the wallet’s ability to spend existing UTXOs that are
    already attributed to that seed (the wallet still derives the needed key at
    signing time once unlocked).
- Disabling the current `default_seedid32` is allowed only if done atomically
  with selecting a new enabled default seed (to keep policy consistent).

**Seed deletion policy (v1)**
- PQHD v1 does not support deleting seed records.
- Rationale:
  - Deleting a seed can make existing funds permanently unspendable if the seed
    is the only source of truth for the derived private keys.
  - “Rotation” is achieved by creating a new seed and disabling the old seed for
    new keypool usage (but retaining it for signing historical funds).
- Optional future work (explicitly out of v1 scope):
  - allow deletion only after a “sweep to a different seed” workflow and after
    verifying there are no remaining wallet descriptors/UTXOs tied to that seed.

---

### 12.5 Wallet DB schema/versioning (PQHD — frozen for implementation)

This section “freezes” the on-disk wallet state we need to store to implement
PQHD deterministically and safely. The goal is:
- restorability: a wallet can be restored from seed(s) + descriptor state
- determinism: a given `SeedID32` + path yields stable keys (under PQHD v1)
- no ambiguity: **all references use full `SeedID32`**
- parity with Bitcoin UX: keypool behavior, change handling, multi-root support

#### 12.5.1 Wallet feature flags / minimum version

Add a wallet feature flag (and corresponding min-version bump) to mark that the
wallet contains PQHD state, so older binaries fail cleanly:
- `WALLET_FLAG_PQHD` (name TBD)

Rationale:
- PQHD introduces new DB record types and new descriptor key expressions.
- A wallet without PQHD support must not “partially load” and then corrupt state.

#### 12.5.2 New DB record types (keys + values)

We store *PQHD seeds* separately from descriptors, and then reference seeds from
descriptors by `SeedID32` (as already specified in §8.3 and §9.2).

All DB keys below follow existing patterns in `src/wallet/walletdb.h`:
`(DBKeys::<TYPE>, <key-data...>) -> <value>`.

**A) PQHD seed records**

Key:
- `(DBKeys::PQHDSEED, <SeedID32>)`
  - `<SeedID32>`: 32 bytes, stored as raw bytes (not hex string)

Value: `CPQHDSeedRecord` (new struct; versioned)
- `uint32_t record_version` (start at 1)
- `uint16_t pqhd_version` (start at 1; bumps when PQHD derivation/keygen rules change)
- `uint64_t created_time` (unix seconds)
- `std::string label` (user-facing label; optional but recommended)
- `uint8_t state` (`ENABLED` or `DISABLED`, §12.4.1)
- `std::vector<uint8_t> seed_material`
  - If wallet is unencrypted: `seed_material = master_seed` (32 bytes)
  - If wallet is encrypted: `seed_material = Encrypt(master_seed)` (opaque bytes)

Encryption/locking semantics (frozen):
- **Store `master_seed` only**. Do not persist derived `NodeSecret`/`ChainCode`;
  they are deterministically derived from `master_seed` + constants (§7.3–§7.4).
- For encrypted wallets, encryption uses the wallet’s existing master-key
  mechanism (same as `CRYPTED_KEY` / `WALLETDESCRIPTORCKEY`), so locking/unlocking
  behavior matches current wallet expectations:
  - When the wallet is locked, `master_seed` cannot be decrypted, so:
    - new PQHD key derivation (keypool top-up) is not possible
    - seed export is not possible
    - **signing is not possible** for any wallet-managed private keys, because
      encrypted private key material cannot be decrypted while locked
      (see `src/wallet/rpc/util.cpp:87` and `src/wallet/scriptpubkeyman.cpp:941`).
    - the wallet can still perform watch-only operations and construct unsigned
      transactions/PSBTs, but any RPC/action that requires signing must either:
      - unlock the wallet (`walletpassphrase`), or
      - use an external signer (if configured).
  - When the wallet is unlocked, seed decryption is permitted. PQHD should
    **decrypt on demand** (e.g. during keypool top-up) and wipe temporary
    plaintext buffers after use, rather than keeping `master_seed` resident in
    memory indefinitely.
- Encryption primitive should reuse the wallet’s existing `EncryptSecret` /
  `DecryptSecret` helpers, with a deterministic IV derived from the seed id:
  - `iv = uint256(SeedID32)` (32 bytes interpreted as `uint256`)
  This mirrors how Bitcoin uses deterministic IVs for key encryption while the
  actual security comes from the master key.

Notes:
- We store the **master_seed** (not the derived NodeSecret/ChainCode) because
  it is the canonical root secret per §7.3, and because it allows us to define
  PQHD v2/v3 rules without inventing an “inverse derivation”.
- When the wallet is encrypted, PQHD seed records must be locked/unlocked
  together with existing wallet key material.

DBKeys naming:
- Add `DBKeys::PQHDSEED` (string constant) alongside existing key types.

De-dup semantics:
- Seed import is keyed by `SeedID32`; importing the same seed twice must be a
  no-op (same `SeedID32` record), and attempting to insert a seed with an
  existing `SeedID32` but different content must be treated as corruption.

**B) PQHD wallet policy record (defaults)**

Key:
- `(DBKeys::PQHDPOLICY)`

Value: `CPQHDPolicy` (new struct; versioned)
- `uint32_t record_version` (start at 1)
- `SeedID32 default_seedid32` (32 bytes)
- `uint8_t default_scheme_id` (for new receive addresses, §12.3.1)
- `std::optional<uint8_t> default_change_scheme_id` (or use “default scheme” fallback, §12.3.2)
- Optional future extension: per-scheme default seed overrides:
  - `map<uint8_t scheme_id, SeedID32> seedid32_for_scheme` (so schemes can be partitioned across roots)

Notes:
- This is the persistent representation of what today is “kind of” implied by
  `pq::ActiveScheme()`. PQHD requires it to be explicit and wallet-local.
- This record is small and can also be redundantly mirrored in `DBKeys::SETTINGS`
  if we prefer, but we should pick exactly one canonical location to avoid drift.

DBKeys naming:
- Add `DBKeys::PQHDPOLICY`.

**C) PQHD-derived private key storage for descriptor keypools**

Descriptors already store derived keys in the wallet DB via:
- `DBKeys::WALLETDESCRIPTORKEY` / `DBKeys::WALLETDESCRIPTORCKEY`
  keyed by `(desc_id, CPubKey)`

Decision:
- We will **refactor `CPubKey`** to be scheme-aware and variable-length, so
  `DBKeys::WALLETDESCRIPTORKEY` / `DBKeys::WALLETDESCRIPTORCKEY` continue to be
  usable for Falcon-1024 and ML-DSA keys.

Implications:
- `CPubKey` must be able to hold and serialize the canonical TidePubKey byte
  representation (`<SchemeId-prefix byte> || <scheme_pubkey_bytes>`, §2.1).
- Wallet DB descriptor-key storage remains “Bitcoin-shaped” (no parallel PQ key
  tables required), and keypool counters remain `WalletDescriptor.next_index`
  and `WalletDescriptor.range_end` (§12.5.3).

#### 12.5.3 Keypool counters (how they persist)

PQHD keypool counters are persisted through existing descriptor wallet fields:
- `WalletDescriptor.next_index` (next index to hand out)
- `WalletDescriptor.range_end` (how far the keypool has been topped up)

These fields are stored as part of the `DBKeys::WALLETDESCRIPTOR` record in
`WalletDescriptor` serialization (`src/wallet/walletutil.h`).

PQHD implication:
- We will have *multiple* `WalletDescriptor` entries (and corresponding
  ScriptPubKeyMan instances) to represent:
  - receive vs change (`change=0` vs `change=1`)
  - per-scheme pools (Falcon-512, ML-DSA-65, …)
  - optionally per-root pools (if per-scheme default seeds are used)

The currently-active receive/change ScriptPubKeyMan IDs remain a single pair
(`DBKeys::ACTIVEEXTERNALSPK` / `DBKeys::ACTIVEINTERNALSPK`), and are selected
according to wallet policy defaults (§12.3, §12.5.2B). Other scheme pools are
present but inactive until selected.

#### 12.5.4 Key metadata (seed + path) — frozen representation

We will need per-key metadata that records PQHD origin (seed + hardened path).
The current `CKeyMetadata` has BIP32-specific fields:
- `hd_seed_id` (20-byte hash160)
- `KeyOriginInfo` (4-byte fingerprint + path)

For PQHD v1, we standardize on:
- `SeedID32` (32 bytes) + full hardened path (vector<u32>)
- no short fingerprint handles

Decision (frozen for implementation):
- Extend `CKeyMetadata` to carry PQHD origin metadata directly.
- We do not require any secp/BIP32 key semantics in PQHD-only wallets. Existing
  BIP32-related fields (`hd_seed_id`, `KeyOriginInfo`) may remain for backward
  compatibility and legacy imports, but PQHD v1 does not populate or depend on
  them.

Concrete fields (proposal to implement in `src/wallet/walletdb.h`):
- `std::optional<uint256> pqhd_seed_id32;`
  - Stored as raw 32 bytes (a `uint256` is already a 32-byte container).
- `std::vector<uint32_t> pqhd_path;`
  - Full hardened path elements (purpose/coin_type/scheme/account/change/index),
    stored as 32-bit unsigned integers. Every element must have the hardened bit
    set (`0x80000000`).

Invariants:
- `pqhd_seed_id32` implies `pqhd_path` is non-empty and conforms to the PQHD
  shape (at minimum includes scheme element at the expected position).
- The scheme id implied by `pqhd_path[2]` (low 8 bits) must match the scheme id
  implied by the public key prefix byte (redundant sanity check).

Wallet serialization/versioning:
- `CKeyMetadata` serialization must be version-gated so older wallets can still
  be read and upgraded cleanly (existing Bitcoin walletdb patterns apply).
- New PQHD metadata must be persisted for both:
  - derived descriptor keypool keys (so PSBT origin export is available), and
  - any explicitly imported PQHD-derived keys (if we support that import path).

Frozen requirement (independent of the chosen code shape):
- Every stored PQ private key must have metadata that includes:
  - `SeedID32` (32 bytes)
  - hardened path (purpose/coin_type/scheme/account/change/index)
  - scheme id (redundant but useful for sanity checks)

This metadata is what drives:
- PSBT origin export (`tidecoin/PQHD_ORIGIN`)
- wallet GUI labels (“seed X, account Y, change, index Z”)
- migration/restore correctness

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
- keygen material test vectors (first N bytes / derived seeds for given leaf)
- per-scheme `KeyGenFromSeed` reproducibility tests (same seed+path must yield
  identical pk/sk across versions/builds/platforms)

Any “example vectors” from drafts must be treated as non-authoritative until
validated by an implementation + tests.

---

## 15. Decisions and Open Questions

### Decided
- SchemeId is 1-byte prefix and stable.
- scheme index in PQHD path equals SchemeId/prefix.
- Hardened-only derivation, no xpub.
- PQHD deterministic RNG must be stream-based (not “fixed N bytes”).
- Key generation determinism uses Tidecoin-owned, versioned `KeyGenFromSeed`
  wrappers per scheme; `pqhd_version` in the seed record pins behavior (§7.5).
- Seed references use full SeedID32 only (no short handles).
- Refactor `CPubKey` to be scheme-aware and variable-length (store TidePubKey bytes; remove fixed-size assumptions).
- Descriptors: explicit TidePubKey keys are raw hex; PQHD uses `pqhd(<SeedID32>)/...` and canonical printing uses `h`.
- PSBT: keep BIP174 PSBT framing; store PQHD origin in `tidecoin` proprietary keys (`subtype=1`).
- Scheme selection for new keys is wallet policy (default receive scheme + change scheme), not `pq::ActiveScheme()`.
- Scheme activation gating: only Falcon-512 outputs before auxpow activation; other
  schemes enabled for output generation only at/after `nAuxpowStartHeight` (§12.3.5).
- Watch-only is explicit-only or bounded export.
- PQ-native output type planned at auxpow hardfork boundary.
- PQHD path constants: `purpose' = 10007'`, `coin_type' = 6868'`.
- Wallet supports multiple PQHD seeds (multiple `SeedID32` roots) (§12.4).

### Still to finalize
- Seed lifecycle RPC/Qt surface:
  - We will not introduce a separate “seed management RPC family” at this stage.
  - Instead, we will extend/refactor existing wallet RPC/Qt flows (similar to
    how we keep PSBT workflows and extend them for PQHD metadata).
  - This work is explicitly deferred until after low-level PQHD storage,
    descriptor integration, and PSBT origin export are implemented.
- (Optional, later) PSBT cleanup: remove xpub/BIP32 PSBT metadata (see §10.4).

---

## 16. Implementation Readiness (What We Still Need)

Before we start implementing PQHD, we should lock down these items to avoid
large rework:

### 16.1 Remaining spec decisions
- Seed lifecycle RPC/Qt UX:
  - Deferred as described in §15 (“Still to finalize”).
  - Low-level implementation must still follow the frozen semantic rules in
    §12.4.1 and §12.5, so the later UI/RPC work is an interface layer, not a
    semantic redesign.

### 16.2 Major code prerequisites
- Multi-scheme public key handling:
  - Current `CPubKey` is Falcon-512-only (`src/pubkey.h:36`), but PQHD targets
    Falcon-1024 and ML-DSA schemes with larger pubkeys (§2.1).
  - Decision: **refactor `CPubKey`** to be scheme-aware and variable-length
    (store TidePubKey bytes, validate by SchemeId prefix, and remove fixed-size
    assumptions throughout wallet/script/descriptor/PSBT/RPC).
- Consensus/policy size limits vs scheme sizes:
  - Falcon-1024 / ML-DSA signatures and pubkeys exceed legacy Bitcoin script
    element sizes; we must ensure our consensus limits and mempool policy can
    accept transactions produced by future schemes (likely gated by height).
- Wallet database schema for PQHD seed storage:
  - Implement the frozen DB schema in §12.5 (seed records + policy defaults),
    including encryption behavior and record versioning.
- Deterministic keygen stability contract:
  - Implement PQHD v1 as versioned per-scheme `KeyGenFromSeed` wrappers (§7.5).
  - Do not rely on PQClean’s internal randomness consumption pattern for wallet
    restore; any incompatible keygen change must bump `pqhd_version`.

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
- A global/unguarded deterministic RNG hook (e.g. a `randombytes()` override)
  can accidentally leak into signing/non-keygen code paths (catastrophic).
- Preferred mitigation: avoid global hooks by using explicit seed/coins-based
  `KeyGenFromSeed` wrappers.
- If any legacy wrapper uses a scoped override, it must be strictly limited
  (thread-local + RAII) and covered by tests.

### 17.4 PQClean upgrades and long-term restorability
- If PQHD keygen depends on PQClean internals, updating PQClean can change
  derived keys for the same seed/path and break wallet restore.
- Mitigation (selected): PQHD uses explicit, versioned per-scheme
  `KeyGenFromSeed` wrappers (§7.5). Any behavior change requires bumping
  `pqhd_version` and opting in with new seeds/descriptors.

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
