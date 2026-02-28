# PQHD Specification (Implemented)

This document defines Tidecoin PQHD (Post-Quantum Hierarchical Deterministic
wallet) as implemented in the current codebase.

PQHD is a descriptor-wallet key derivation and policy system for post-quantum
signature schemes. It replaces BIP32/xpub-style public derivation in Tidecoin.

## 1. Scope

This specification covers:

- PQHD v1 key derivation and deterministic key generation
- Descriptor syntax and semantics for `pqhd(...)`
- Wallet storage records and policy behavior
- AuxPoW height-gated scheme policy
- PSBT proprietary PQHD origin metadata
- RPC-visible PQHD behavior

This specification does not define consensus script rules. It defines wallet,
descriptor, and metadata behavior.

## 2. Normative References

Primary implementation touchpoints:

- `src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`
- `src/pq/pqhd_params.h`
- `src/pq/pqhd_keygen.cpp`, `src/pq/pq_api.h`
- `src/pq/pq_scheme.h`
- `src/script/descriptor.h`, `src/script/descriptor.cpp`
- `src/wallet/pqhd.h`
- `src/wallet/wallet.cpp`, `src/wallet/walletdb.h`, `src/wallet/walletdb.cpp`
- `src/wallet/walletutil.cpp`
- `src/wallet/scriptpubkeyman.cpp`
- `src/wallet/rpc/wallet.cpp`, `src/wallet/rpc/addresses.cpp`,
  `src/wallet/rpc/spend.cpp`, `src/wallet/rpc/util.cpp`
- `src/psbt.h`, `src/psbt.cpp`

## 3. Scheme Registry

PQHD uses Tidecoin scheme prefix bytes from `src/pq/pq_scheme.h`:

| Scheme | Prefix (hex) | Prefix (dec) |
| --- | --- | ---: |
| Falcon-512 | `0x07` | 7 |
| Falcon-1024 | `0x08` | 8 |
| ML-DSA-44 | `0x09` | 9 |
| ML-DSA-65 | `0x0A` | 10 |
| ML-DSA-87 | `0x0B` | 11 |

`pq::SchemeFromPrefix()` is authoritative for recognizing scheme ids.

## 4. Path Constants and Shape

Constants from `src/pq/pqhd_params.h`:

- `PURPOSE = 10007`
- `COIN_TYPE = 6868`

PQHD v1 leaf paths MUST satisfy:

- exactly 6 elements
- every element hardened (bit 31 set)
- element 0 = `10007h`
- element 1 = `6868h`
- element 2 = known scheme prefix as hardened integer
- element 4 (`change`) is constrained by descriptor parser to `0h` or `1h`

Validation function: `pqhd::ValidateV1LeafPath()`.

## 5. Seed and Node Derivation (PQHD v1)

### 5.1 Master seed

PQHD master seed is exactly 32 bytes.

### 5.2 SeedID32

`SeedID32 = SHA256("Tidecoin PQHD seedid v1" || master_seed32)`

Implementation function: `pqhd::ComputeSeedID32()`.

Wallet storage uses `uint256` representation for seed ids. The wallet helper
normalizes byte order so `seed_id.ToString()` matches canonical SeedID32 hex.

### 5.3 Master node

`I = HMAC_SHA512(key="Tidecoin PQHD seed", msg=master_seed32)`

- `node_secret = I[0..31]`
- `chain_code = I[32..63]`

Implementation function: `pqhd::MakeMasterNode()`.

### 5.4 Child derivation

PQHD v1 is hardened-only.

Given parent `(node_secret, chain_code)` and hardened index `i`:

- `data = 0x00 || parent.node_secret || ser32be(i)`
- `I = HMAC_SHA512(key=parent.chain_code, msg=data)`
- child split as in master node

Implementation functions:

- `pqhd::DeriveChild()`
- `pqhd::DerivePath()`

## 6. Leaf Material and Stream Key

Given leaf `node_secret_leaf` and validated 6-element path:

1. `prk_full = HMAC_SHA512(key="Tidecoin PQHD hkdf v1", msg=node_secret_leaf)`
2. `scheme = path[2] & 0x7fffffff`
3. `info = "Tidecoin PQHD stream key v1" || ser32be(scheme) || ser32be(path[0]) || ... || ser32be(path[5]) || 0x01`
4. `stream_key64 = HMAC_SHA512(key=prk_full, msg=info)`

Output type:

- `LeafMaterialV1 { scheme_id, stream_key64 }`

Implementation functions:

- `pqhd::DeriveLeafMaterialV1()`
- `pqhd::DeriveKeygenStreamKey()`

## 7. Deterministic Key Generation

PQHD deterministic keygen entry points:

- `pq::KeyGenFromSeed()`
- `pq::KeyGenFromSeedBytes()`
- `pq::KeyGenFromLeafMaterial()`

Current supported version:

- `pqhd_version = 1` only

Algorithm (per `KeyGenFromSeed`):

1. Determine per-scheme deterministic seed length:
   - Falcon-512/1024: 48 bytes
   - ML-DSA-44/65/87: 32 bytes
2. For `ctr = 0..1023`:
   - `block64 = HMAC_SHA512(key=stream_key64, msg="Tidecoin PQHD rng v1" || ser32be(ctr))`
   - `seed = block64[0:seed_len]`
   - call scheme-specific deterministic PQClean keypair generator
3. First successful attempt is used.
4. If all attempts fail, keygen fails.

This deterministic retry loop is part of PQHD v1 behavior.

## 8. Descriptor Syntax and Semantics

### 8.1 PQHD key expression

Supported forms:

- fixed leaf:
  - `pqhd(SEEDID32)/purposeh/cointypeh/schemeh/accounth/changeh/indexh`
- ranged leaf:
  - `pqhd(SEEDID32)/purposeh/cointypeh/schemeh/accounth/changeh/*h`

Parser constraints in `src/script/descriptor.cpp`:

- Seed id must be 32-byte hex.
- Exactly 6 hardened elements in fixed form.
- Wildcard form must have exactly 5 fixed hardened elements before `*h`.
- Multipath (`<...;...>`) is rejected.
- Non-hardened derivation is rejected.
- `purpose` and `coin_type` must match constants.
- `scheme` must be recognized and fit in `uint8`.
- `change` must be 0 or 1.

Both `h` and apostrophe input are accepted by parser; canonical descriptor
printing uses `h`.

### 8.2 Expansion behavior

`PQHDPubkeyProvider` derives pubkeys/private keys by:

1. loading wallet-local seed by seed id (`SigningProvider::GetPQHDSeed`)
2. deriving leaf material via PQHD KDF
3. generating deterministic keypair via `KeyGenFromLeafMaterial(..., v1)`
4. serializing pubkey as prefixed TidePubKey bytes (`scheme_prefix || raw_pubkey`)

`pqhd(...)` is wallet-private key source syntax. No seed bytes are embedded in
descriptor strings.

### 8.3 Key origin metadata

Descriptor key-origin bracket metadata (`[fingerprint/path]`) is not supported
for PQHD descriptors in parser (`"Key origin metadata is not supported"`).

## 9. Wallet Storage and State

### 9.1 DB records

Wallet DB record keys (`src/wallet/walletdb.cpp`):

- `pqhdseed`: plaintext PQHD seed record (`PQHDSeed`)
- `cpqhdseed`: encrypted PQHD seed record (`PQHDCryptedSeed`)
- `pqhdpolicy`: policy record (`PQHDPolicy`)

`PQHDPolicy` fields:

- `default_receive_scheme`
- `default_change_scheme`
- `default_seed_id`
- `default_change_seed_id`

### 9.2 Metadata records

`CKeyMetadata` version includes PQHD origin fields:

- `has_pqhd_origin`
- `pqhd_seed_id`
- `pqhd_path`

Current metadata version: `VERSION_WITH_PQHD_ORIGIN = 13`.

### 9.3 Seed lifecycle

Import behavior (`ImportPQHDSeed`):

- descriptor wallet required
- seed length must be 32 bytes
- re-import is idempotent (`inserted=false`)
- encrypted wallets require unlocked state for import
- first imported seed initializes default PQHD policy if missing

Removal behavior (`RemovePQHDSeed`):

- descriptor wallet required
- cannot remove non-existent seed
- cannot remove last seed
- cannot remove default receive/change seed
- cannot remove seed referenced by existing descriptors

## 10. Wallet Descriptor Provisioning

For descriptor wallets with local keys (`SetupOwnDescriptorScriptPubKeyMans`):

- wallet creates one random 32-byte PQHD seed
- default scheme is Falcon-512 for receive and change
- default seed ids for receive and change are that seed
- descriptors are generated for output types in `OUTPUT_TYPES`
- `BECH32PQ` descriptors are not created before AuxPoW activation height

Descriptor template from `GeneratePQHDWalletDescriptor`:

`pqhd(SEEDID32)/10007h/6868h/<scheme>h/0h/<change>h/*h`

Address wrappers by output type:

- `LEGACY` -> `pkh(...)`
- `P2SH_SEGWIT` -> `sh(wpkh(...))`
- `BECH32` -> `wpkh(...)`
- `BECH32PQ` -> `wsh512(pk(...))`

## 11. Height-Gated Scheme Policy

Policy function: `pq::IsSchemeAllowedAtHeight(id, params, height)`.

Rules:

- if `height < nAuxpowStartHeight`: only Falcon-512 allowed
- otherwise: all known schemes allowed

Wallet uses target height `tip + 1` for output policy decisions
(`GetTargetHeightForOutputs`). If no chain context is available, target height
falls back to 0.

This policy is enforced in:

- default policy loading/clamping
- `setpqhdpolicy`
- descriptor generation and setup
- address/change scheme override validation

## 12. RPC Surface

Primary PQHD wallet RPCs:

- `setpqhdpolicy`
- `listpqhdseeds`
- `importpqhdseed`
- `setpqhdseed`
- `removepqhdseed`

Scheme parsing (`ParsePQSchemePrefix`) accepts:

- numeric ids (0-255, recognized only)
- normalized names: `falcon512`, `falcon1024`, `mldsa44`, `mldsa65`, `mldsa87`
  (hyphen/underscore/space-insensitive)

Related options:

- `getaddressinfo(..., {"include_pqhd_origin": bool})`
- `walletprocesspsbt(..., include_pqhd_origins=true)`

## 13. PSBT Proprietary PQHD Origin

Namespace (`src/psbt.h`):

- identifier: `"tidecoin"`
- subtype: `0x01` (`SUBTYPE_PQHD_ORIGIN`)

Data model (`psbt::tidecoin::PQHDOrigin`):

- `pubkey`: prefixed TidePubKey (`CPubKey`)
- `seed_id`: `uint256`
- `path_hardened`: vector of hardened `uint32`

Value encoding (`MakePQHDOriginValue`):

- `seed_id`
- compactsize `path_len`
- `path_len` serialized `uint32` elements

Decode checks (`DecodePQHDOrigin`):

- identifier and subtype must match
- pubkey must be valid non-hybrid CPubKey
- path length must be in `[3, 256]`
- every path element must be hardened
- scheme from `path[2]` must be recognized
- pubkey prefix must equal scheme in `path[2]`
- trailing bytes are rejected

Emission (`DescriptorScriptPubKeyMan::FillPSBT`):

- controlled by `include_pqhd_origins`
- records can be emitted on input and output proprietary maps
- only emitted for unambiguous single-key provider cases
- metadata source is `GetMetadata(dest)` (`pqhd_seed_id`, `pqhd_path`)

## 14. Address Metadata Exposure

`getaddressinfo` may include:

- `pqhd_seedid`
- `pqhd_path` (string form `m/...h/...`)

This is controlled by `include_pqhd_origin` (default `true`).

## 15. Compatibility and Invariants

The following are protocol-level wallet invariants and MUST be treated as
stable for PQHD v1:

- `PURPOSE = 10007`, `COIN_TYPE = 6868`
- hardened-only derivation model
- SeedID32 tag and KDF domain-separation strings
- path element layout and scheme-in-path semantics
- deterministic keygen retry model (up to 1024 counters)
- scheme activation gating semantics relative to `nAuxpowStartHeight`
- descriptor grammar for `pqhd(...)`
- PSBT proprietary identifier/subtype and validation rules

Any incompatible change requires an explicit new PQHD version and coordinated
migration logic.

## 16. Test Coverage Anchors

Current test files covering PQHD behavior include:

- `src/test/pqhd_kdf_tests.cpp`
- `src/test/pqhd_keygen_tests.cpp`
- `src/test/descriptor_tests.cpp`
- `src/test/psbt_pqhd_origin_tests.cpp`
- `src/wallet/test/psbt_wallet_tests.cpp`
- `src/wallet/test/scriptpubkeyman_tests.cpp`
- `src/wallet/test/wallet_tests.cpp`
- `test/functional/wallet_pqhd_seed_lifecycle.py`
- `test/functional/wallet_pqhd_lock_semantics.py`

