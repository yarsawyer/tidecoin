# Tidecoin Repository Confluence Audit

## Purpose

This document is a detailed, evidence-based assessment of the Tidecoin repository from the perspective of: (a) an AI agent performing due diligence, and (b) an investor or technical reviewer evaluating project maturity. Every finding includes the **exact files, line numbers, and reasoning** used to reach the conclusion.

**Audit date:** 2026-02-09
**Codebase state:** master branch, based on Bitcoin Core v30

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Part 1 - What's Genuinely Strong (Strengths)](#part-1---whats-genuinely-strong)
3. [Part 2 - Critical Identity / Branding Issues](#part-2---critical-identity--branding-issues)
4. [Part 3 - Technical Code Issues](#part-3---technical-code-issues)
5. [Part 4 - Documentation Gaps](#part-4---documentation-gaps)
6. [Part 5 - Repository Hygiene](#part-5---repository-hygiene)
7. [Part 6 - Contrarian Points (What Might NOT Need Changing)](#part-6---contrarian-points)
8. [Part 7 - Prioritized Action Plan](#part-7---prioritized-action-plan)

---

## Executive Summary

Tidecoin is a **technically legitimate post-quantum cryptocurrency** with real, non-stub NIST-standardized signature implementations (Falcon-512/1024, ML-DSA-44/65/87, ML-KEM-512), a custom PQHD deterministic wallet, and AuxPoW merged-mining infrastructure. The cryptographic engineering is solid.

However, **the repository's external presentation critically undermines its credibility**. An AI agent or investor scanning this repo would conclude it is an unmodified Bitcoin Core fork because:

- The README says "Bitcoin Core" and links to bitcoincore.org
- SECURITY.md directs vulnerability reports to Bitcoin Core developers
- CONTRIBUTING.md sends contributors to Bitcoin's IRC/mailing lists
- GitHub issue templates ask about "Bitcoin Core"
- 111 release notes are all Bitcoin Core's, with zero Tidecoin-branded notes
- The CMake project() is still named "BitcoinCore"
- The COPYING file has no Tidecoin copyright line

The core code is strong; the packaging is the problem.

---

## Part 1 - What's Genuinely Strong

### 1.1 Post-Quantum Cryptographic Implementation

**Verdict: PRODUCTION-QUALITY. Real implementations, not stubs.**

**How I verified this:**
- Read every file in `src/pq/` (18+ source files across Falcon, ML-DSA, ML-KEM subdirectories)
- Traced the full signing/verification path from RPC through consensus
- Checked for TODO/FIXME/HACK markers (found none in core PQ code)
- Verified memory management patterns

**Evidence:**

| Component | Files | Status | Detail |
|-----------|-------|--------|--------|
| Falcon-512 | `src/pq/falcon-512/`, `src/pq/falcon512.c` (262 lines) | Complete | Full PQClean integration + custom legacy wrapper with nonce format |
| Falcon-1024 | `src/pq/falcon-1024/`, `src/pq/falcon1024.c` (54 lines) | Complete | Standard PQClean wrapper |
| ML-DSA-44/65/87 | `src/pq/ml-dsa-{44,65,87}/`, `src/pq/mldsa{44,65,87}.c` | Complete | Full PQClean integration, three NIST security levels |
| ML-KEM-512 | `src/pq/ml-kem-512/`, `src/pq/kem.cpp` (83 lines) | Complete | Used for BIP324 v2 P2P transport (not consensus) |
| Scheme Registry | `src/pq/pq_scheme.h:1-178` | Complete | 5 schemes with constexpr metadata, prefix-based lookup, height-gated activation |
| C++ API | `src/pq/pq_api.h:1-362` | Complete | GenerateKeyPair, Sign, Sign64, Verify, VerifyPrefixed, KeyGenFromLeafMaterial |

**Consensus integration path** (verified by reading code):
```
EvalScript() → EvalChecksig() → CheckPostQuantumSignature()
  → VerifyPostQuantumSignature() → CPubKey::Verify() → pq::VerifyPrefixed()
```
- `src/script/interpreter.cpp:1445-1495`: `CheckPostQuantumSignature()` handles both 256-bit and 512-bit sighashes
- `src/pubkey.cpp:19-74`: `CPubKey::Verify()` and `Verify512()` wrap PQ verification
- `src/key.cpp`: `CKey::Sign()` and `Sign512()` delegate to `pq::Sign()` and `pq::Sign64()`

**Memory safety** (verified in code):
- `memory_cleanse()` used on all secret material (`src/pq/pqhd_kdf.cpp`, `src/pq/pqhd_keygen.cpp`, `src/pq/kem.cpp`)
- `secure_allocator<>` for CPrivKey (`src/key.h:25`)
- RAII destructors cleanse both PK and SK in `MLKEM512Keypair` (`src/pq/pq_api.h:80-83`)
- Move-only or deleted copy constructors for sensitive classes
- `KeygenStreamKey64` destructor cleanses material (`src/pq/pqhd_kdf.h:33`)

### 1.2 PQHD Deterministic Wallet

**Verdict: WELL-DESIGNED. Custom HD scheme with proper domain separation.**

**How I verified this:**
- Read `src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp` (162 lines), `src/pq/pqhd_keygen.cpp`
- Traced key derivation from master seed through to wallet descriptor
- Verified path validation logic

**Evidence:**
- `src/pq/pqhd_kdf.cpp:38`: `ComputeSeedID32()` uses SHA256("Tidecoin PQHD seedid v1" || seed) - proper domain separation
- `src/pq/pqhd_kdf.cpp:102-114`: Path validation enforces 6-element hardened-only paths
  - Element 0: PURPOSE = 0x80000000 | 10007
  - Element 1: COIN_TYPE = 0x80000000 | 6868
  - Elements 2-5: Scheme, Account, Change, Index (all hardened)
- `src/pq/pqhd_kdf.cpp:127-139`: HKDF-based stream key derivation with scheme-specific domain separation
- `src/pq/pqhd_keygen.cpp:87-104`: Scheme-specific key generation (Falcon uses 48-byte seed, ML-DSA uses 32-byte seed)
- Retry loop for encoding failures (up to 1024 attempts, line 70) with comprehensive memory cleansing per attempt (line 111-113)

**Wallet integration:**
- `src/wallet/pqhd.h:13-61`: Three serializable structures (PQHDSeed, PQHDCryptedSeed, PQHDPolicy)
- `src/script/descriptor.cpp:291-465`: `PQHDPubkeyProvider` class - full descriptor-based derivation
- `src/wallet/wallet.cpp:1817-1940`: Seed loading, encryption, policy management
- `src/wallet/rpc/wallet.cpp:348-391`: `setpqhdpolicy` RPC command
- `src/psbt.h:30-63`: PSBT proprietary fields for PQHD origin metadata (identifier: "tidecoin")

### 1.3 Consensus Differentiation

**Verdict: MEANINGFULLY DIFFERENT FROM BITCOIN. Not a trivial fork.**

**How I verified this:**
- Read `src/kernel/chainparams.cpp` (369 lines) for chain parameters
- Read `src/primitives/pureheader.cpp` for PoW algorithms
- Read `src/script/interpreter.h` for script flags
- Read `src/script/script.h` for opcodes
- Read `src/policy/policy.cpp` for PQ policy rules

**Evidence:**

| Feature | Bitcoin Core | Tidecoin | Evidence |
|---------|-------------|----------|----------|
| Signature Algo | secp256k1 ECDSA/Schnorr | Falcon-512/1024, ML-DSA-44/65/87 | `src/pq/pq_scheme.h:21-25` |
| PoW Algorithm | SHA256d | Yespower (+ scrypt for AuxPoW parents) | `src/primitives/pureheader.cpp:20-38` |
| Block Time | 10 minutes | 1 minute | `src/kernel/chainparams.cpp:100` |
| Halving Interval | 210,000 blocks | 262,800 blocks | `src/kernel/chainparams.cpp:86` |
| Witness Versions | v0 (segwit), v1 (taproot) | v0 (segwit), v1 (PQ 512-bit scripthash) | `src/script/interpreter.h:178-180` |
| Script Opcodes | Standard | + OP_SHA512 (0xb3) | `src/script/script.h:187` |
| HD Wallet | BIP32/BIP44 | PQHD with hardened-only paths | `src/pq/pqhd_kdf.h` |
| Address Prefix (bech32) | bc | tbc (mainnet), q (PQ) | `src/kernel/chainparams.cpp:153-154` |
| Network Magic | f9beb4d9 | ecfacea5 | `src/kernel/chainparams.cpp:125-128` |
| Default Port | 8333 | 8755 | `src/kernel/chainparams.cpp:129` |
| Taproot | Active | Removed (not PQ-secure) | `ai-docs/taproot-removal.md` |
| Merged Mining | None | AuxPoW (infrastructure ready, currently disabled) | `src/auxpow.h`, chainparams:93 |

**Genesis block** (`src/kernel/chainparams.cpp:72-77`):
- Timestamp: "spectrum.ieee.org 09/Dec/2020 Photonic Quantum Computer Displays 'Supremacy' Over Supercomputers."
- Time: 1609074580 (Dec 27, 2020)
- Hash: `480ecc7602d8989f32483377ed66381c391dda6215aeef9e80486a7fd3018075`

**DNS Seeds** (`src/kernel/chainparams.cpp:144-146`): Tidecoin-specific domains:
- seed.tidecoin.co
- tidecoin.ddnsgeek.com
- tidecoin.theworkpc.com

### 1.4 Test Coverage

**Verdict: SUBSTANTIAL. Both unit and functional tests with PQ-specific coverage.**

**How I verified this:**
- Counted test files via glob patterns
- Read PQ-specific test files
- Checked functional test framework for PQ support

**Evidence:**

| Category | Count | Location |
|----------|-------|----------|
| Unit test files (.cpp) | 135 | `src/test/*.cpp` |
| Functional test files (.py) | 255 | `test/functional/*.py` |
| PQ-specific unit tests | 10 files | `src/test/pq_*.cpp`, `src/test/pqhd_*.cpp`, `src/test/bip324_pq_tests.cpp`, `src/test/psbt_pqhd_origin_tests.cpp` |
| PQ fuzz tests | 1 file | `src/test/fuzz/bip324_pq.cpp` |
| ML-KEM Python lib | Complete | `test/functional/test_framework/crypto/kyber_py/ml_kem/` |

PQ unit test files (~1,760 lines total):
- `pqhd_kdf_tests.cpp` - KDF vectors, path validation
- `pqhd_keygen_tests.cpp` - Key generation from PQHD leaf material
- `pq_multisig_tests.cpp` - Multi-signature scenarios
- `pq_random_key_tests.cpp` - Random key generation
- `pq_pubkey_container_tests.cpp` - Serialization/deserialization
- `pq_txsize_tests.cpp` - Transaction size calculations
- `psbt_pqhd_origin_tests.cpp` - PSBT PQHD origin integration
- `bip324_pq_tests.cpp` - P2P v2 encryption with ML-KEM

### 1.5 Build System

**Verdict: MODERN. Correctly branded executable names.**

**How I verified this:** Read `CMakeLists.txt` lines 29-174, checked output target names.

**Evidence:**
- `CMakeLists.txt:29`: `CLIENT_NAME "Tidecoin"` - correct
- Build targets produce: `tidecoin`, `tidecoind`, `tidecoin-cli`, `tidecoin-tx`, `tidecoin-util`, `tidecoin-wallet`, `tidecoin-qt`, `test_tidecoin`, `bench_tidecoin`
- `src/clientversion.cpp:23`: `UA_NAME("Tidecoin")` - network user agent is correct
- `libtidecoinkernel.pc`: Correctly branded as "Tidecoin kernel library"

### 1.6 Script Verification Flags

**Verdict: WELL-DESIGNED. PQ-specific consensus flags.**

**Evidence** (`src/script/interpreter.h:116-122`):
- `SCRIPT_VERIFY_PQ_STRICT` (bit 13): Post-quantum strict signature validation
- `SCRIPT_VERIFY_WITNESS_V1_512` (bit 14): Witness v1 64-byte scripthash validation
- `SCRIPT_VERIFY_SHA512` (bit 15): Enable OP_SHA512 opcode

These are height-gated (post-AuxPoW activation), showing careful consensus upgrade design.

---

## Part 2 - Critical Identity / Branding Issues

These are the issues that cause an AI agent or investor to immediately classify this as "just another Bitcoin fork."

### 2.1 CRITICAL: README.md is 100% Bitcoin-Branded

**File:** `README.md` (80 lines)
**How I verified:** Read the entire file.

**Every line references Bitcoin Core:**
- Line 1: "Bitcoin Core integration/staging tree"
- Line 4: "https://bitcoincore.org"
- Line 9: "What is Bitcoin Core?"
- Line 12: "Bitcoin Core connects to the Bitcoin peer-to-peer network..."
- Line 21: "Bitcoin Core is released under the terms of the MIT license"
- Lines 29-34: Links to `github.com/bitcoin/bitcoin` and `github.com/bitcoin-core/gui`
- Line 73: "Bitcoin Core's Transifex page"

**Zero mentions of Tidecoin, post-quantum, Falcon, ML-DSA, PQHD, or any differentiator.**

**Impact:** This is the single most damaging issue. README.md is the first file any agent or human reads. It completely defines first impression. Currently it tells the reader this project is Bitcoin Core.

**Required action:** Complete rewrite. See suggested structure in Part 7.

### 2.2 CRITICAL: SECURITY.md Directs Reports to Bitcoin Core

**File:** `SECURITY.md` (21 lines)
**How I verified:** Read the entire file.

**Content:**
- Line 5: "See our website for versions of Bitcoin Core that are currently supported"
- Line 6: Links to `https://bitcoincore.org/en/lifecycle/#schedule`
- Line 10: "send an email to security@bitcoincore.org"
- Lines 16-18: GPG keys for Pieter Wuille, Michael Ford, Ava Chow (Bitcoin Core devs)

**Impact:** If someone finds a vulnerability in Tidecoin's PQ crypto, they'd report it to Bitcoin Core developers who have nothing to do with this project. This is both a security risk (reports go to wrong team) and a credibility disaster (no independent security process).

**Required action:** Replace with Tidecoin security contact, GPG keys, and supported version policy.

### 2.3 CRITICAL: CONTRIBUTING.md (445 lines, all Bitcoin)

**File:** `CONTRIBUTING.md` (445 lines)
**How I verified:** Read the entire file, grep'd for "bitcoin".

**Problematic references (sample):**
- Line 1: "Contributing to Bitcoin Core"
- Line 4: "The Bitcoin Core project operates an open contributor model..."
- Line 33: Links to `https://github.com/bitcoin/bitcoin` issues
- Line 39: "Bitcoin Core PR Review Club"
- Lines 57-62: "#bitcoin-core-dev channel on Libera Chat"
- Lines 68-71: Bitcoin developer mailing list (bitcoindev@groups.google.com)
- Line 88: "https://github.com/bitcoin/bitcoin node repository should be used"
- Line 293: "Patches that change Bitcoin consensus rules..."

**Impact:** Contributors are directed entirely to Bitcoin project infrastructure. No mention of Tidecoin contribution process.

### 2.4 CRITICAL: GitHub Issue Templates Reference Bitcoin Core

**Files and evidence:**

1. `.github/ISSUE_TEMPLATE/bug.yml:8`: "This issue tracker is only for technical issues related to Bitcoin Core."
2. `.github/ISSUE_TEMPLATE/bug.yml:11`: "reporting security issues...https://bitcoincore.org/en/contact/"
3. `.github/ISSUE_TEMPLATE/bug.yml:53`: Links to `github.com/bitcoin/bitcoin/blob/master/doc/files.md`
4. `.github/ISSUE_TEMPLATE/bug.yml:60-73`: "How did you obtain Bitcoin Core", "What version of Bitcoin Core"
5. `.github/ISSUE_TEMPLATE/config.yml:3-7`: Links to Bitcoin Core Security Policy and bitcoincore.org
6. `.github/ISSUE_TEMPLATE/good_first_issue.yml:31`: "basic understanding of Bitcoin mining and the Bitcoin Core RPC interface"
7. `.github/ISSUE_TEMPLATE/good_first_issue.yml:43`: Links to `github.com/bitcoin/bitcoin/blob/master/CONTRIBUTING.md`

**How I verified:** Read all 5 template files in `.github/ISSUE_TEMPLATE/`.

**Impact:** Bug reports ask users about "Bitcoin Core" versions. Security issues link to Bitcoin Core. This actively confuses users and makes bug triage impossible.

### 2.5 CRITICAL: PR Template References Bitcoin Core

**File:** `.github/PULL_REQUEST_TEMPLATE.md` (44 lines)
**How I verified:** Read the entire file.

- Line 8: Links to `https://github.com/bitcoin-core/gui`
- Line 14: "Bitcoin Core user experience or Bitcoin Core developer experience"
- Line 27: "building the system outside of Bitcoin Core"
- Line 39: "Bitcoin Core has a thorough review process"

### 2.6 CRITICAL: CMake project() Still Named "BitcoinCore"

**File:** `CMakeLists.txt:53-57`
**How I verified:** Read the file.

```cmake
project(BitcoinCore
  VERSION ${CLIENT_VERSION_MAJOR}.${CLIENT_VERSION_MINOR}.${CLIENT_VERSION_BUILD}
  DESCRIPTION "Bitcoin client software"
  HOMEPAGE_URL "https://bitcoincore.org/"
  LANGUAGES NONE
)
```

While `CLIENT_NAME` is "Tidecoin" (line 29), the CMake project identifier, description, and homepage URL are all Bitcoin Core. This affects:
- CMake's PROJECT_NAME variable
- Generated pkg-config descriptions
- IDE project identification

**Required action:** Change to `project(Tidecoin ... DESCRIPTION "Post-quantum cryptocurrency" HOMEPAGE_URL "https://tidecoin.org/" ...)`

### 2.7 CRITICAL: COPYING Has No Tidecoin Copyright

**File:** `COPYING:1-5`
**How I verified:** Read the file.

```
The MIT License (MIT)
Copyright (c) 2009-2025 The Bitcoin Core developers
Copyright (c) 2009-2025 Bitcoin Developers
```

No Tidecoin copyright line. While Bitcoin Core's copyright must be preserved (MIT license requirement), Tidecoin's own copyright should be added.

**Required action:** Add `Copyright (c) 2020-2026 The Tidecoin developers` while keeping Bitcoin Core's copyright.

### 2.8 CRITICAL: clientversion.cpp Has Bitcoin Source URL

**File:** `src/clientversion.cpp:86`
**How I verified:** Read the file.

```cpp
const std::string URL_SOURCE_CODE = "<https://github.com/bitcoin/bitcoin>";
```

This URL is shown in the `--version` output of every Tidecoin binary. Users running `tidecoind --version` see a link to Bitcoin's repo.

**Required action:** Change to Tidecoin's GitHub URL.

### 2.9 HIGH: All 111 Release Notes Are Bitcoin Core's

**File:** `doc/release-notes/` (111 files)
**How I verified:** Listed all files, grep'd for "Tidecoin" in all files (zero matches), read `release-notes-25.0.md` (opens with "Bitcoin Core version 25.0 is now available from: https://bitcoincore.org/bin/bitcoin-core-25.0/").

**No release note in the entire directory mentions Tidecoin.** Even the v25.0-v29.1 notes (which correspond to the Tidecoin era) are verbatim Bitcoin Core release notes with zero PQ content.

**Impact:** There is no documented history of any Tidecoin-specific release. An agent checking release notes sees only Bitcoin Core versions.

**Required action:**
- Move Bitcoin notes to `doc/historical/bitcoin-core-release-notes/`
- Create Tidecoin-specific release notes for each actual Tidecoin release (documenting PQ features added, consensus changes, etc.)

### 2.10 HIGH: doc/README.md is 100% Bitcoin

**File:** `doc/README.md`
**How I verified:** Read the file, counted 95+ Bitcoin references.

- Line 1: "Bitcoin Core"
- Line 4: "Bitcoin Core is the original Bitcoin client..."
- Line 8: "To download Bitcoin Core, visit [bitcoincore.org]..."
- Line 18: "`bin/bitcoin-qt` (GUI)"
- Line 19: "`bin/bitcoind` (headless)"
- Line 34: "[Bitcoin Wiki](https://en.bitcoin.it/wiki/Main_Page)"
- Line 59: "[doxygen.bitcoincore.org]"

**Zero mentions of Tidecoin, PQ signatures, PQHD, or any differentiating feature.**

### 2.11 HIGH: doc/ Directory Pervasively Bitcoin-Branded

**How I verified:** Grep'd `doc/*.md` for "Bitcoin Core" - found 200+ matches across 40+ files.

**Most affected files (sample):**

| File | Bitcoin Core Mentions | Key Issue |
|------|----------------------|-----------|
| `doc/fuzzing.md` | 23 | "Bitcoin Core" throughout |
| `doc/developer-notes.md` | 15+ | Developer guidelines reference Bitcoin |
| `doc/tor.md` | 9 | "Bitcoin Core Tor support" |
| `doc/files.md` | 11 | `$HOME/.bitcoin/` data directory |
| `doc/psbt.md` | 8+ | "PSBT Howto for Bitcoin Core" |
| `doc/tracing.md` | 8 | Title and references |
| `doc/build-osx.md` | 10+ | Build instructions reference Bitcoin |
| `doc/build-windows.md` | Multiple | Source path references |
| `doc/build-unix.md` | Multiple | Build references |
| `doc/dependencies.md:3` | 1 | "These are the dependencies used by Bitcoin Core" |
| `doc/release-process.md` | Multiple | Release process references |

### 2.12 HIGH: Bitcoin-Branded Icons

**How I verified:** Glob'd for `bitcoin.ico`, `bitcoin.icns`, `bitcoin.png`, `bitcoin.svg` in `share/` and `src/qt/res/`.

**Files found:**
- `share/pixmaps/bitcoin.ico` - Windows system icon
- `src/qt/res/icons/bitcoin.icns` - macOS app icon
- `src/qt/res/icons/bitcoin.ico` - Windows app icon
- `src/qt/res/icons/bitcoin.png` - Generic icon
- `src/qt/res/icons/bitcoin_testnet.ico` - Testnet icon
- `src/qt/res/src/bitcoin.svg` - SVG source
- `src/qt/res/bitcoin-qt-res.rc` - Windows resource file

**Only one Tidecoin asset exists:** `src/qt/res/icons/tidecoin_splash.png`

**Impact:** The GUI application shows Bitcoin branding on all platforms.

### 2.13 MEDIUM: contrib/ Documentation Bitcoin-Branded

**Files and evidence:**
- `contrib/guix/README.md:1`: "Bootstrappable Bitcoin Core Builds"
- `contrib/macdeploy/README.md:9`: "produced `Bitcoin-Core.zip`"
- `contrib/macdeploy/README.md:32,75`: References to "bitcoin-core" GitHub organization

### 2.14 MEDIUM: CI Pipeline Has Bitcoin Hardcoding

**File:** `.github/workflows/ci.yml`
**How I verified:** Read the file (564 lines).

- Line 23: `REPO_USE_CIRRUS_RUNNERS: 'bitcoin/bitcoin'` - hardcoded to Bitcoin repo
- Lines 266-294: Environment variables use `BITCOIN_BIN`, `BITCOIND`, `BITCOINCLI`, etc.
- Line 308: `BITCOINFUZZ`
- 27 total references to "bitcoin" in executable/variable names

**Impact:** CI works correctly (executables are built as `tidecoin*`), but the workflow file reveals its Bitcoin Core origin and uses confusing variable names.

---

## Part 3 - Technical Code Issues

These are code-level findings that affect technical credibility.

### 3.1 HIGH: Internal CMake Library Targets Use "bitcoin_" Prefix

**File:** `src/CMakeLists.txt`
**How I verified:** Read the file, searched for library target definitions.

Internal library targets:
- `bitcoin_clientversion`
- `bitcoin_consensus`
- `bitcoin_crypto`
- `bitcoin_quantum` (PQ library - but uses bitcoin_ prefix)
- `bitcoin_common`
- `bitcoin_node`
- `bitcoin_cli`

Executable CMake targets:
- `add_executable(bitcoin ...)` → produces `tidecoin`
- `add_executable(bitcoind ...)` → produces `tidecoind`
- `add_executable(bitcoin-cli ...)` → produces `tidecoin-cli`

**Impact:** While executables are correctly named in output, anyone reading the CMake build system sees "bitcoin" everywhere. Also affects IDE target listings and build logs.

**Risk assessment:** Low user impact but high developer confusion. Any contributor running `cmake --build build --target bitcoin_consensus` will wonder what project they're building.

### 3.2 MEDIUM: AuxPoW Is Currently Disabled

**File:** `src/kernel/chainparams.cpp:93`
**How I verified:** Read chainparams for all three networks.

```cpp
consensus.nAuxpowStartHeight = Consensus::AUXPOW_DISABLED;
```

AuxPoW is disabled on mainnet, testnet, and only configurable on regtest. The infrastructure exists (`src/auxpow.h`, `src/auxpow.cpp`) but is not active.

**Impact on perception:** Documentation and feature lists mention merged mining, but it's not actually enabled. An agent checking the code would flag this as "claimed but unimplemented."

**Recommendation:** Either document the timeline for enabling AuxPoW, or avoid listing it as a current feature.

### 3.3 MEDIUM: PQ Scheme Activation Is Height-Gated to Disabled AuxPoW

**File:** `src/pq/pq_scheme.h:170-174`
**How I verified:** Read the scheme validation logic.

```cpp
// Only FALCON_512 allowed before auxpow start height
inline bool SchemeAllowedAtHeight(SchemeId id, int height, const Consensus::Params& params) {
    if (height < params.nAuxpowStartHeight) return id == SchemeId::FALCON_512;
    return true;
}
```

Since AuxPoW is disabled (`AUXPOW_DISABLED` = MAX_INT), only Falcon-512 can ever be used on mainnet. ML-DSA-44/65/87 and Falcon-1024 are implemented but effectively locked out.

**Impact:** The project advertises 5 PQ signature schemes, but only 1 is usable. This could be seen as misleading.

**Recommendation:** Document this clearly. Either enable scheme activation independently of AuxPoW, or explain the roadmap for unlocking additional schemes.

### 3.4 MEDIUM: Falcon Signing Retry Loop

**File:** `src/pq/pq_api.h:350-362`
**How I verified:** Read the signing logic.

Falcon signing uses up to 10,000 retry attempts per signature operation. This is inherent to Falcon's probabilistic signing algorithm, but:
- No backoff or adaptive strategy
- No metrics/logging for retry counts in production
- Could impact performance under sustained load

**Assessment:** This is correct cryptographic behavior (Falcon needs retries), but should be documented for auditors who might flag it as a bug.

### 3.5 LOW: clientversion.cpp Still Credits Bitcoin Core Without Tidecoin

**File:** `src/clientversion.cpp:72-82`
**How I verified:** Read the file.

```cpp
std::string CopyrightHolders(const std::string& strPrefix) {
    // Make sure Bitcoin Core copyright is not removed by accident
    if (copyright_devs.find("Bitcoin Core") == std::string::npos) {
        strCopyrightHolders += "\n" + strPrefix + "The Bitcoin Core developers";
    }
    return strCopyrightHolders;
}
```

The function ensures "Bitcoin Core" always appears in copyright, but there's no equivalent check for "Tidecoin developers."

### 3.6 LOW: ML-KEM Present But Not In Consensus

**Files:** `src/pq/ml-kem-512/`, `src/pq/kem.cpp`, `src/pq/pq_api.h:69-109`
**How I verified:** Searched for ML-KEM usage in consensus code vs P2P code.

ML-KEM-512 is fully implemented but only used for BIP324 v2 P2P transport encryption, not for transaction signatures or consensus. This is correct design (KEM is for key exchange, not signing), but could confuse reviewers who see it listed alongside signature schemes.

**Recommendation:** Document clearly that ML-KEM is for P2P transport security, not transaction signing.

---

## Part 4 - Documentation Gaps

### 4.1 CRITICAL: No Whitepaper or Technical Overview

**How I verified:** Glob'd for `WHITEPAPER*`, `whitepaper*`, `doc/whitepaper*`. None found.

**Impact:** There is no single document explaining what Tidecoin is, why it exists, or how it works. The `ai-docs/pqhd.md` (67KB) is an excellent internal spec but is not a whitepaper.

**Required action:** Create `doc/whitepaper.md` or `WHITEPAPER.md` covering:
1. Problem statement (quantum threat to ECDSA)
2. Solution (NIST PQC standards integration)
3. Technical architecture
4. Security model
5. Economic parameters

### 4.2 CRITICAL: No CHANGELOG.md

**How I verified:** Glob'd for `CHANGELOG*`. Not found.

**Impact:** No way for anyone to understand what changed between versions. Combined with Bitcoin-branded release notes, there's zero version history.

### 4.3 CRITICAL: No ROADMAP.md

**How I verified:** Glob'd for `ROADMAP*`. Not found.

The `ai-docs/plan.md` exists with internal development phases, but it's not formatted for external audiences.

**Impact:** No visible project direction. Investors need to know where the project is heading.

### 4.4 HIGH: No AGENTS.md or CLAUDE.md

**How I verified:** Glob'd for `AGENTS.md`, `CLAUDE.md`. Neither found.

**Impact:** AI agents entering this codebase have no guidance. They default to reading README.md (which says "Bitcoin Core"), and conclude accordingly.

**Required action:** Create `CLAUDE.md` (or `AGENTS.md`) with:
- Project identity and purpose
- Key technical differentiators from Bitcoin
- Code organization guide
- Build and test commands
- List of PQ-specific directories and files

### 4.5 HIGH: No PQ-Specific User Documentation

**How I verified:** Searched `doc/` for PQ-related guides. Found none.

**Missing:**
- `doc/pq-signatures.md` - How PQ signatures work in Tidecoin
- `doc/pqhd-wallet.md` - PQHD wallet user guide
- `doc/auxpow-mining.md` - Merged mining setup guide (when enabled)
- `doc/migration-guide.md` - Migrating from legacy Tidecoin

The `ai-docs/pqhd.md` is an internal spec, not user documentation.

### 4.6 MEDIUM: No GOVERNANCE.md or CODE_OF_CONDUCT.md

**How I verified:** Glob'd for both. Neither found.

**Impact:** No visible governance structure. For a cryptocurrency project holding user funds, this matters.

### 4.7 MEDIUM: ai-docs/ Directory Exposes Internal Planning

**How I verified:** Listed all 18 files in `ai-docs/`.

Contents include:
- `plan.md` - Development migration plan with phase tracking
- `pqhd.md` - 67KB PQHD specification (valuable)
- `taproot-removal.md` - Internal planning
- `pqhd-removal-plan.md` - Confusingly named (was about removing old PQHD code)
- `op_sha512_plan.md` - Feature planning
- Various `*-plan.md` files with status tracking
- `notes.md` - Raw notes
- Audit and test reports

**Issues:**
1. The directory name "ai-docs" signals AI-assisted development
2. Planning documents with "TODO" and "WIP" markers look unfinished
3. Some filenames are confusing (e.g., "pqhd-removal-plan" sounds like removing PQ support)
4. The `pqhd.md` spec is buried alongside planning debris

**Recommendation:**
- Move `pqhd.md` to `doc/specs/pqhd-specification.md` as authoritative documentation
- Either gitignore `ai-docs/` or rename to `internal/` with a README explaining purpose
- Remove or archive completed planning documents

---

## Part 5 - Repository Hygiene

### 5.1 MEDIUM: Internal Library Naming Consistency

**How I verified:** Read `src/CMakeLists.txt` and traced target dependencies.

All internal CMake targets use `bitcoin_*` naming while outputs use `tidecoin*`. This creates confusion:
- Library targets: `bitcoin_consensus`, `bitcoin_common`, `bitcoin_node`, `bitcoin_crypto`, `bitcoin_quantum`
- Executable targets: `bitcoin` → `tidecoin`, `bitcoind` → `tidecoind`, etc.

**Assessment:** Renaming internal targets is a large refactor with risk of build breakage. This is lower priority than documentation/branding fixes, but should be on the long-term roadmap.

### 5.2 LOW: External Library CI Files

**How I verified:** Glob'd for CI config files in subdirectories.

Files found:
- `src/leveldb/.travis.yml`
- `src/leveldb/.appveyor.yml`
- `src/crc32c/.github/workflows/build.yml`
- `src/minisketch/.cirrus.yml`
- `src/ipc/libmultiprocess/.github/workflows/ci.yml`

These are from vendored dependencies and don't affect Tidecoin, but add noise.

### 5.3 LOW: Build Artifacts Not In Repository (Good)

**How I verified:** Read `.gitignore` (line 7: `/*build*`) and confirmed build directories are not tracked.

`build/`, `build_depends/`, `build_dev_mode/`, `Testing/` - all properly gitignored. This is correct.

---

## Part 6 - Contrarian Points

### 6.1 Bitcoin Core Heritage Is a STRENGTH

**Argument:** Keep the Bitcoin Core foundation visible and well-documented.

**Reasoning:**
- 15+ years of battle-tested consensus code
- Well-understood security model
- Extensive test coverage inherited
- Active upstream security patches can be cherry-picked
- Serious projects like Litecoin proudly document their Bitcoin Core base

**Recommendation:** Don't hide the Bitcoin Core base. Instead, clearly document: "Built on Bitcoin Core v30, with post-quantum cryptographic replacements for all signing operations."

### 6.2 ai-docs/ Transparency Is Valuable

**Argument:** Keep some form of internal documentation visible.

**Reasoning:**
- Shows systematic, documented development process
- The `pqhd.md` spec is genuinely excellent technical writing
- Demonstrates the project was built with deliberate architectural decisions

**Recommendation:** Rename to `specs/` or `architecture/`, clean out WIP tracking files, and keep the valuable specifications.

### 6.3 Single-Scheme (Falcon-512) Operation Is Actually Conservative and Good

**Argument:** Having only Falcon-512 active initially is security-conservative.

**Reasoning:**
- Falcon-512 is the most tested PQ signature in the codebase (has legacy support, most tests)
- Activating all 5 schemes at once would increase attack surface
- Gradual activation via consensus upgrade is standard practice (Bitcoin did this with SegWit, Taproot)

**Recommendation:** Document this as deliberate. The roadmap should show when additional schemes activate.

### 6.4 Code Comments Referencing "Bitcoin" in Source Files Are Fine

**Argument:** Don't mass-rename comments in C++ source files.

**Reasoning:**
- Bitcoin Core copyright headers are legally required under MIT license
- Internal variable names like `bitcoin_consensus` don't affect users
- Mass-renaming risks introducing bugs and makes upstream cherry-picking harder
- Focus branding effort on user-facing files (README, docs, templates, icons)

---

## Part 7 - Prioritized Action Plan

### P0: Immediate (Must-Fix for Credibility)

| # | Item | File(s) | Action | Effort |
|---|------|---------|--------|--------|
| 1 | README.md | `README.md` | Complete rewrite for Tidecoin identity | 2-3 hours |
| 2 | SECURITY.md | `SECURITY.md` | Replace with Tidecoin security contacts | 30 min |
| 3 | CONTRIBUTING.md | `CONTRIBUTING.md` | Update all references to Tidecoin | 1-2 hours |
| 4 | Issue Templates | `.github/ISSUE_TEMPLATE/*.yml` | Update all 5 templates | 1 hour |
| 5 | PR Template | `.github/PULL_REQUEST_TEMPLATE.md` | Update references | 15 min |
| 6 | COPYING | `COPYING` | Add Tidecoin copyright line | 5 min |
| 7 | CMake project() | `CMakeLists.txt:53-57` | Change project name, description, URL | 5 min |
| 8 | Version URL | `src/clientversion.cpp:86` | Change GitHub URL | 5 min |

### P1: Short-Term (Professional Polish)

| # | Item | File(s) | Action | Effort |
|---|------|---------|--------|--------|
| 9 | CLAUDE.md / AGENTS.md | New file | Create AI agent context file | 1 hour |
| 10 | WHITEPAPER.md | New file | Create technical whitepaper | 4-8 hours |
| 11 | CHANGELOG.md | New file | Create version history | 2-3 hours |
| 12 | ROADMAP.md | New file | Create public roadmap | 1-2 hours |
| 13 | Release Notes | `doc/release-notes/` | Move Bitcoin notes to `doc/historical/`, create Tidecoin notes | 2-3 hours |
| 14 | doc/README.md | `doc/README.md` | Rewrite for Tidecoin | 1 hour |
| 15 | Icons | `share/pixmaps/`, `src/qt/res/icons/` | Replace Bitcoin icons with Tidecoin | 2-4 hours (design) |
| 16 | doc/ Branding | `doc/*.md` (40+ files) | Replace "Bitcoin Core" with "Tidecoin" in user-facing docs | 3-4 hours |

### P2: Medium-Term (Completeness)

| # | Item | File(s) | Action | Effort |
|---|------|---------|--------|--------|
| 17 | PQ User Docs | `doc/pq-signatures.md` | Create PQ signatures guide | 2-3 hours |
| 18 | PQHD User Docs | `doc/pqhd-wallet.md` | Create PQHD wallet guide | 2-3 hours |
| 19 | Mining Docs | `doc/auxpow-mining.md` | Create merged mining guide (when enabled) | 1-2 hours |
| 20 | Specs Directory | `doc/specs/pqhd.md` | Move pqhd.md from ai-docs | 30 min |
| 21 | ai-docs/ Cleanup | `ai-docs/` | Reorganize or gitignore planning files | 1 hour |
| 22 | GOVERNANCE.md | New file | Create governance document | 1-2 hours |
| 23 | contrib/ Docs | `contrib/guix/README.md`, `contrib/macdeploy/README.md` | Update branding | 30 min |
| 24 | CI Variables | `.github/workflows/ci.yml` | Rename BITCOIN_* vars to TIDECOIN_* | 1-2 hours |

### P3: Long-Term (Technical Debt)

| # | Item | File(s) | Action | Effort |
|---|------|---------|--------|--------|
| 25 | CMake Target Names | `src/CMakeLists.txt` and children | Rename `bitcoin_*` to `tidecoin_*` | 4-8 hours (risky) |
| 26 | Performance Benchmarks | `doc/performance.md` | PQ signature/verification benchmarks | 4-8 hours |
| 27 | Multi-Scheme Activation | `src/pq/pq_scheme.h` | Document or implement independent scheme activation | Variable |
| 28 | Wallet Migration | `src/wallet/` | Legacy → PQHD migration path | Variable |

### Suggested README.md Structure

```markdown
# Tidecoin

**Post-Quantum Secure Cryptocurrency**

Tidecoin is a decentralized cryptocurrency built to withstand both classical and
quantum computing attacks. It uses NIST-standardized post-quantum signature
algorithms to protect every transaction.

## Why Tidecoin?

Quantum computers threaten all cryptocurrencies that rely on elliptic curve
cryptography (ECDSA, Schnorr). Tidecoin replaces these with NIST FIPS 204/206
post-quantum signatures, making it quantum-resistant today.

## Key Features

- **Post-Quantum Signatures**: Falcon-512/1024 (NIST), ML-DSA-44/65/87 (FIPS 204)
- **PQHD Wallet**: Post-quantum hierarchical deterministic wallet
- **ML-KEM Transport**: Quantum-secure peer-to-peer communication (FIPS 203)
- **OP_SHA512**: 512-bit witness scripts for PQ-native verification
- **Bitcoin Core v30 Foundation**: Battle-tested consensus and networking code
- **Merged Mining Ready**: AuxPoW infrastructure for merged mining with scrypt chains

## Technical Specifications

| Property | Value |
|----------|-------|
| Active Signature | Falcon-512 (NIST PQC Round 3 winner) |
| PoW Algorithm | Yespower |
| Block Time | 60 seconds |
| Max Supply | Geometric halving schedule |
| Address Format | Bech32 (tbc1...) / Bech32-PQ (q1...) |
| Network Port | 8755 |

## Building from Source

[Build instructions for Linux/macOS/Windows]

## Documentation

- [PQHD Wallet Specification](doc/specs/pqhd.md)
- [Post-Quantum Signatures](doc/pq-signatures.md)
- [Developer Notes](doc/developer-notes.md)

## Security

See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

Tidecoin is released under the MIT license. See [COPYING](COPYING).
Based on Bitcoin Core. Copyright (c) 2009-2025 The Bitcoin Core developers.
```

---

## Methodology Note

This audit was conducted by:

1. **Reading source files directly** - every claim is backed by a file path and line number
2. **Tracing code paths** - following function calls from RPC through consensus to crypto
3. **Pattern matching** - grep/glob searches for branding terms across the entire codebase
4. **Comparing structure** - checking what professional crypto projects include vs. what's present here
5. **Verifying implementations** - confirming PQ code is real (not stubs) by reading actual crypto operations

**Files analyzed:** 200+ source files across `src/pq/`, `src/wallet/`, `src/script/`, `src/kernel/`, `doc/`, `.github/`, `contrib/`, and root-level markdown files.

**Tools used:** File reading, content search (grep), pattern matching (glob), directory listing.

---

*Audit completed: 2026-02-09*
