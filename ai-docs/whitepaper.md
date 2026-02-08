# Tidecoin: A Post-Quantum Secure Peer-to-Peer Cryptocurrency

**Version 2.0 -- February 2026**

---

## Abstract

Tidecoin is a decentralized cryptocurrency engineered from genesis to resist attacks from both classical and quantum computers. While Bitcoin and virtually all major blockchains rely on the Elliptic Curve Digital Signature Algorithm (ECDSA) -- which Shor's algorithm will break once sufficiently powerful quantum computers exist -- Tidecoin replaces ECDSA entirely with NIST-standardized post-quantum signature schemes: Falcon-512/1024 and ML-DSA-44/65/87. Built on the battle-tested Bitcoin Core v30 codebase, Tidecoin preserves the UTXO model, scripting system, and 15+ years of peer-reviewed consensus logic while adding a custom Post-Quantum Hierarchical Deterministic (PQHD) wallet, a memory-hard proof-of-work algorithm (yespower), SHA-512-based witness scripts, ML-KEM-512 encrypted peer-to-peer transport, and infrastructure for Auxiliary Proof-of-Work (AuxPoW) merged mining with scrypt-based chains. The network has been in continuous operation since December 27, 2020 -- over five years of uninterrupted block production with zero security incidents.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [The Quantum Threat to Cryptocurrency](#2-the-quantum-threat-to-cryptocurrency)
3. [Design Philosophy](#3-design-philosophy)
4. [Post-Quantum Signature Schemes](#4-post-quantum-signature-schemes)
5. [PQHD: Post-Quantum Hierarchical Deterministic Wallet](#5-pqhd-post-quantum-hierarchical-deterministic-wallet)
6. [Consensus Mechanism and Proof-of-Work](#6-consensus-mechanism-and-proof-of-work)
7. [Script System Extensions](#7-script-system-extensions)
8. [Post-Quantum Peer-to-Peer Transport](#8-post-quantum-peer-to-peer-transport)
9. [Auxiliary Proof-of-Work (Merged Mining)](#9-auxiliary-proof-of-work-merged-mining)
10. [Economic Model](#10-economic-model)
11. [Network Parameters](#11-network-parameters)
12. [Security Analysis](#12-security-analysis)
13. [Comparison with Other Post-Quantum Projects](#13-comparison-with-other-post-quantum-projects)
14. [Operational Track Record](#14-operational-track-record)
15. [Roadmap](#15-roadmap)
16. [Conclusion](#16-conclusion)
17. [References](#17-references)
18. [Sources Consulted](#18-sources-consulted)

---

## 1. Introduction

The security of nearly every cryptocurrency in existence depends on the assumed hardness of the Elliptic Curve Discrete Logarithm Problem (ECDLP). Bitcoin, Ethereum, and the vast majority of blockchain systems use ECDSA or Schnorr signatures over the secp256k1 curve. In 1994, Peter Shor demonstrated a polynomial-time quantum algorithm that solves the discrete logarithm problem, which means a sufficiently powerful quantum computer could derive any ECDSA private key from its corresponding public key.

This is not a speculative concern. The U.S. National Institute of Standards and Technology (NIST) launched a formal Post-Quantum Cryptography (PQC) standardization process in 2016, selected its first winners in 2022, and published final standards (FIPS 203, 204, 205) in August 2024. NIST Interagency Report 8547 recommends that all systems migrate to post-quantum cryptography by 2030, with mandatory compliance by 2035. The U.S. Federal Reserve published a 2025 analysis specifically examining the "Harvest Now, Decrypt Later" threat to distributed ledger networks.

Tidecoin was conceived in direct response to these realities. Its genesis block, mined on December 27, 2020, carries the timestamp message:

> *"spectrum.ieee.org 09/Dec/2020 Photonic Quantum Computer Displays 'Supremacy' Over Supercomputers."*

This references the breakthrough by the University of Science and Technology of China, whose photonic quantum computer Jiuzhang demonstrated quantum computational advantage -- an event that underscored the urgency of quantum-safe cryptography.

Since that genesis block, Tidecoin has produced over 2.3 million blocks across more than five years of continuous operation, with every single transaction secured by post-quantum signatures. No security incident, consensus failure, or cryptographic vulnerability has been reported.

---

## 2. The Quantum Threat to Cryptocurrency

### 2.1 Shor's Algorithm and ECDSA

Shor's algorithm solves the ECDLP in polynomial time on a quantum computer. For the secp256k1 curve used by Bitcoin:

- **Classical best attack:** Requires approximately 2^128 operations (Pollard's rho)
- **Quantum attack:** Requires approximately 2,500 logical qubits, equivalent to roughly 10^5 to 10^6 physical qubits with current error-correction overhead (surface codes)

Current quantum hardware (Google Willow at 105 qubits, IBM Eagle at 127 qubits) is orders of magnitude away from this threshold. However, conservative timelines from NIST and academic research place cryptographically relevant quantum computers (CRQCs) at 10-20 years away, with some optimistic estimates suggesting 5-10 years.

### 2.2 The Harvest Now, Decrypt Later Problem

Blockchain data is uniquely vulnerable because it is public and immutable. An adversary can:

1. Download the entire blockchain today (all transaction data is public)
2. Record every public key exposed in transactions
3. Store this data indefinitely at negligible cost
4. Derive private keys once CRQCs become available

The Federal Reserve's 2025 paper, "Harvest Now Decrypt Later: Examining Post-Quantum Cryptography and the Data Privacy Risks for Distributed Ledger Networks," specifically analyzes this scenario. Their key finding: even after a blockchain migrates to PQC, **previously recorded transaction data remains permanently vulnerable**. The immutability of blockchains -- normally their greatest strength -- becomes their greatest weakness in the quantum context.

For Bitcoin specifically:

| Category | BTC Exposed | Risk Level |
|----------|-------------|------------|
| P2PK addresses (public key directly visible) | ~1.7-1.9 million BTC | Immediate on Q-Day |
| Reused addresses (public key exposed after first spend) | ~4 million BTC | Immediate on Q-Day |
| Total quantum-vulnerable | ~5.9 million BTC (~25% of supply) | Critical |

This includes the estimated 968,000 BTC in addresses attributed to Satoshi Nakamoto, all held in P2PK format with no possibility of migration.

### 2.3 Why Migration Is Hard

Bitcoin's BIP-360 (P2QRH) and QBIP proposals for post-quantum migration face severe obstacles:

- **Political inertia:** Bitcoin's conservative governance model requires global consensus. The SegWit activation took approximately two years; Taproot took three. Post-quantum migration is far more complex.
- **Block space pressure:** Post-quantum signatures are 10-100x larger than ECDSA (666 bytes for Falcon-512 vs. 64 bytes for ECDSA). Migration would consume significant block space for potentially years.
- **Unrecoverable funds:** Coins in P2PK addresses (including Satoshi's holdings) cannot migrate because the keys are presumably lost.
- **Timeline mismatch:** The Bitcoin community's estimated migration timeline is 5-10 years. If CRQCs arrive on the optimistic timeline, Bitcoin may not be ready.

Tidecoin eliminates this entire problem class by using post-quantum signatures from block zero.

---

## 3. Design Philosophy

Tidecoin's architecture follows four principles:

### 3.1 NIST Standards, Not Experiments

Every cryptographic primitive in Tidecoin is either a finalized NIST standard or a NIST competition winner in active standardization:

- **ML-DSA** (FIPS 204, August 2024) -- Digital signatures
- **ML-KEM** (FIPS 203, August 2024) -- Key encapsulation
- **Falcon** (Draft FIPS 206) -- Digital signatures with compact sizes
- **SHA-512** -- FIPS 180-4 hash function

We deliberately avoided exotic, unvetted algorithms. The NIST PQC competition ran for eight years (2016-2024), with 69 initial submissions narrowed to 4 winners through extensive cryptanalysis by the global academic community.

### 3.2 Bitcoin Heritage, Not Reinvention

Tidecoin is built on Bitcoin Core v30, preserving:

- The UTXO transaction model
- Script-based programmable spending conditions
- The peer-to-peer network protocol
- The validated block relay and mempool architecture
- Over 135 unit test files and 255 functional test files

This is 15+ years of battle-tested, peer-reviewed code. We replaced only what quantum computers break (ECDSA) and extended only what quantum security demands (witness versions, opcodes, HD wallet derivation).

### 3.3 Defense in Depth

Tidecoin applies post-quantum security at every layer:

| Layer | Classical (Bitcoin) | Post-Quantum (Tidecoin) |
|-------|-------------------|------------------------|
| Transaction signing | ECDSA (secp256k1) | Falcon-512/1024, ML-DSA-44/65/87 |
| Witness script hashing | SHA-256 (128-bit PQ security) | SHA-512 (256-bit PQ security) |
| Peer-to-peer encryption | ECDH (secp256k1) | ML-KEM-512 (FIPS 203) |
| Proof-of-work | SHA-256d (no memory barrier) | Yespower (memory-hard) |
| HD wallet derivation | BIP32 (ECDSA-based xpub) | PQHD (hardened-only, hash-based) |

### 3.4 Conservative Activation

New signature schemes are activated through height-gated consensus upgrades, not all at once. Falcon-512 has been active since genesis. Additional schemes (Falcon-1024, ML-DSA-44/65/87) activate at a defined consensus height, following the precedent of Bitcoin's SegWit and CSV activations. This approach minimizes risk while providing a clear upgrade path.

---

## 4. Post-Quantum Signature Schemes

### 4.1 Falcon-512 and Falcon-1024

Falcon (Fast-Fourier Lattice-based Compact Signatures over NTRU) is a NIST PQC Round 3 winner, designated for standardization as **FIPS 206 (FN-DSA)**. The draft standard was described as "basically written, awaiting approval" at the 6th PQC Standardization Conference in September 2025.

**Mathematical basis:** Falcon instantiates the Gentry-Peikert-Vaikuntanathan (GPV) framework for hash-and-sign lattice-based signatures. The underlying hard problem is the Short Integer Solution (SIS) problem over NTRU lattices, for which no efficient quantum algorithm is known. Security is proven in both the Random Oracle Model (ROM) and the Quantum Random Oracle Model (QROM).

**Why Falcon for cryptocurrency:** Falcon produces the smallest combined public-key-plus-signature size of any NIST PQC signature scheme. For bandwidth-constrained blockchain transactions, this is decisive:

| Parameter | Falcon-512 | Falcon-1024 | ML-DSA-44 | ML-DSA-65 |
|-----------|-----------|-------------|-----------|-----------|
| NIST Security Level | 1 (~AES-128) | 5 (~AES-256) | 2 (~AES-128) | 3 (~AES-192) |
| Public Key | 897 bytes | 1,793 bytes | 1,312 bytes | 1,952 bytes |
| Signature | ~666 bytes (avg) | ~1,280 bytes (avg) | 2,420 bytes | 3,309 bytes |
| **PK + Sig** | **~1,563 bytes** | **~3,073 bytes** | **3,732 bytes** | **5,261 bytes** |
| Verification speed | ~28,000 ver/s | ~13,700 ver/s | Fast | Fast |

Falcon-512 has been the active signature scheme on Tidecoin's mainnet since genesis (December 2020), making Tidecoin one of the earliest live blockchains to use this NIST-standardized lattice-based signature.

**Implementation details** (source: `src/pq/falcon512.c`, `src/pq/falcon-512/`):
- Full PQClean reference implementation integration
- Custom legacy signature format with nonce inclusion for backwards compatibility
- Verification is integer-only arithmetic (no floating-point dependency)

### 4.2 ML-DSA-44, ML-DSA-65, and ML-DSA-87

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is standardized as **FIPS 204**, finalized August 13, 2024. Formerly known as CRYSTALS-Dilithium.

**Mathematical basis:** Based on the hardness of the Module Learning With Errors (Module-LWE) and Module Short Integer Solution (Module-SIS) problems. Uses the Fiat-Shamir with Aborts paradigm.

**Advantages over Falcon:**
- **No floating-point arithmetic:** ML-DSA uses only integer operations, eliminating an entire class of side-channel vulnerabilities
- **Simpler constant-time implementation:** Easier to implement securely
- **NIST's recommended default:** NIST recommends ML-DSA as the primary choice for general-purpose post-quantum signatures
- **Already finalized:** FIPS 204 is effective since August 2024; Falcon's FIPS 206 is still in draft

**Key sizes** (source: `src/pq/pq_scheme.h:72-100`):

| Parameter | Public Key | Secret Key | Signature | NIST Level |
|-----------|-----------|------------|-----------|------------|
| ML-DSA-44 | 1,312 bytes | 2,560 bytes | 2,420 bytes | 2 |
| ML-DSA-65 | 1,952 bytes | 4,032 bytes | 3,309 bytes | 3 |
| ML-DSA-87 | 2,592 bytes | 4,896 bytes | 4,627 bytes | 5 |

Tidecoin supports all three ML-DSA security levels, activated via consensus upgrade. Users and applications can choose the security/size tradeoff appropriate to their needs.

### 4.3 Scheme Registry and Consensus Integration

All five signature schemes are registered in a compile-time scheme registry (source: `src/pq/pq_scheme.h:42-108`). Each scheme has:

- A unique one-byte prefix (0x07-0x0B) prepended to serialized public keys
- Fixed metadata: public key size, secret key size, maximum and fixed signature sizes
- A human-readable name

The verification path through consensus code is:

```
EvalScript() -> EvalChecksig() -> CheckPostQuantumSignature()
  -> VerifyPostQuantumSignature() -> CPubKey::Verify() -> pq::VerifyPrefixed()
```

(Source: `src/script/interpreter.cpp:1445-1495`, `src/pubkey.cpp:19-74`)

Three consensus script verification flags control PQ behavior (source: `src/script/interpreter.h:114-122`):

- `SCRIPT_VERIFY_PQ_STRICT` (bit 13): Reject legacy signature formats
- `SCRIPT_VERIFY_WITNESS_V1_512` (bit 14): Enable 64-byte witness v1 scripthash
- `SCRIPT_VERIFY_SHA512` (bit 15): Enable OP_SHA512 opcode

---

## 5. PQHD: Post-Quantum Hierarchical Deterministic Wallet

### 5.1 The BIP32 Problem

Bitcoin's BIP32 HD wallet standard relies on elliptic curve arithmetic for key derivation. The extended public key (xpub) mechanism enables watch-only wallets and gap-limit-free address generation by deriving child public keys from a parent public key without the private key.

In a quantum setting, this is catastrophic: Shor's algorithm can derive the private key from any public key, meaning an exposed xpub is equivalent to an exposed xpriv. Furthermore, no NIST post-quantum signature scheme supports the homomorphic public key derivation that BIP32's non-hardened derivation requires.

### 5.2 PQHD Design

Tidecoin implements a custom Post-Quantum Hierarchical Deterministic wallet (PQHD) that replaces BIP32 entirely. The design uses hardened-only derivation with hash-based key material generation.

**Path structure** (source: `src/pq/pqhd_kdf.cpp:102-114`):

```
m / purpose' / coin_type' / scheme' / account' / change' / index'
```

All path elements are hardened (high bit set), with fixed values:
- `purpose'` = 10007' (Tidecoin PQHD purpose)
- `coin_type'` = 6868' (Tidecoin coin type)
- `scheme'` = PQ scheme identifier
- `account'`, `change'`, `index'` = User-controlled derivation

### 5.3 Key Derivation

The derivation chain from master seed to leaf key (source: `src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp`, `src/pq/pqhd_keygen.cpp`):

1. **Seed ID computation:** `SeedID = SHA-256("Tidecoin PQHD seedid v1" || master_seed)` -- domain-separated identifier
2. **Master node derivation:** HMAC-SHA-512 based master node creation from 32-byte master seed
3. **Hardened child derivation (CKD):** HMAC-SHA-512 chained derivation using parent secret material
4. **Leaf material extraction:** HKDF-based stream key derivation with scheme-specific domain separation
5. **Deterministic key generation:** Scheme-specific conversion of leaf material to PQ keypair:
   - Falcon: Uses first 48 bytes as deterministic seed
   - ML-DSA: Uses first 32 bytes as deterministic seed

**Memory safety:** All secret material is cleansed via `memory_cleanse()` after use. RAII destructors ensure cleanup even on early returns. Secure allocators are used for private key storage.

### 5.4 Wallet Integration

PQHD is fully integrated with Bitcoin Core's descriptor wallet framework:

- **Descriptor format:** `wpkh(pqhd(SEEDID)/purpose'/cointype'/scheme'/account'/change'/index')`
- **PSBT support:** Proprietary fields (identifier: "tidecoin", subtype 0x01) carry PQHD origin metadata for offline signers (source: `src/psbt.h:30-63`)
- **Encrypted storage:** Seeds are encrypted with the wallet master key; decryption occurs only when spending (source: `src/wallet/pqhd.h:29-42`)
- **Policy management:** The `setpqhdpolicy` RPC command allows setting default receive and change signature schemes (source: `src/wallet/rpc/wallet.cpp:348-391`)

---

## 6. Consensus Mechanism and Proof-of-Work

### 6.1 YespowerTIDE

Tidecoin uses **yespower**, a memory-hard proof-of-work algorithm from the yespower/yescrypt family designed by Solar Designer (Alexander Peslyak) of the Openwall Project. Yespower is a PoW-focused fork of yescrypt, which itself builds on scrypt.

**Properties:**
- **Memory-hard:** Requires substantial RAM for each hash evaluation, making the algorithm inherently resistant to parallelization tricks used by GPUs and ASICs
- **CPU-friendly:** Optimized for general-purpose CPUs, promoting mining decentralization
- **GPU-unfriendly:** Heavy use of CPU L2 cache access patterns that map poorly to GPU architectures
- **ASIC-neutral:** While dedicated hardware can eventually be built, the advantage over CPUs is far smaller than Bitcoin's SHA-256d, where ASICs outperform CPUs by factors of 10^6+

### 6.2 Quantum Resistance of Memory-Hard PoW

Memory-hard proof-of-work provides inherent resistance to quantum speedup beyond what pure hash functions offer. The argument is structural:

**Grover's algorithm and PoW:** Grover's algorithm provides a quadratic speedup for unstructured search -- reducing a 2^n search to 2^(n/2). For Bitcoin's SHA-256d PoW, this halves the effective difficulty in bit terms. However, Grover's is the theoretical maximum; no quantum algorithm can do fundamentally better for unstructured search.

**The memory barrier:** Each iteration of Grover's algorithm requires a quantum oracle that evaluates the target function in superposition. For a memory-hard function like yespower, this oracle must:

1. Maintain the entire memory scratchpad (megabytes) in quantum superposition
2. Perform data-dependent memory lookups in superposition
3. Keep the quantum state coherent throughout the sequential access pattern

This requires **Quantum Random Access Memory (QRAM)** proportional to the function's memory parameter. QRAM at the scale of megabytes does not exist and faces fundamental physical challenges. As researchers have noted: "in the near future it remains a challenge to develop a QRAM capable of addressing millions or billions of individual memory elements."

**Proven optimality:** A 2017 EUROCRYPT paper by Alwen, Chen, Pietrzak, Reyzin, and Tessaro proved that **scrypt is maximally memory-hard** -- its cumulative memory complexity cannot be reduced below Omega(n^2 * w) even by adversaries with parallel resources. Yespower inherits this property with significantly larger memory parameters (1-16 MB vs. scrypt's 128 KB).

**Practical limitations of Grover on memory-hard functions:** A 2024 paper by Song and Seo, "Grover on Scrypt" (MDPI Electronics), presents optimized quantum circuits for attacking scrypt. Even with all optimizations applied, the resource requirements (qubits, circuit depth, QRAM) remain enormous -- far beyond any projected quantum hardware timeline.

### 6.3 Difficulty Adjustment

Tidecoin uses a DigiShield-variant difficulty adjustment algorithm (source: `src/kernel/chainparams.cpp:99-108`):

| Parameter | Value |
|-----------|-------|
| Target block time | 60 seconds |
| Averaging window | 17 blocks |
| Target timespan | 5 days (432,000 seconds) |
| Max adjustment down | 32% per period |
| Max adjustment up | 16% per period |
| Min difficulty blocks | Disabled on mainnet |

This provides responsive difficulty adjustment while resisting manipulation through time-warp attacks.

---

## 7. Script System Extensions

### 7.1 OP_SHA512

Tidecoin introduces `OP_SHA512` (opcode 0xb3, source: `src/script/script.h:187`), which computes the SHA-512 hash of the top stack element.

**Post-quantum justification:** Under Grover's algorithm:

| Hash Function | Classical Preimage Security | Post-Quantum Preimage Security (Grover) |
|--------------|---------------------------|---------------------------------------|
| SHA-256 | 256 bits | 128 bits |
| SHA-512 | 512 bits | 256 bits |

SHA-256 provides 128-bit post-quantum security -- sufficient by NIST standards (Category 1), but with no margin. SHA-512 provides 256-bit post-quantum security (NIST Category 5), offering the maximum security margin against future quantum algorithmic improvements.

NIST explicitly states that existing symmetric cryptography and hash functions "are less vulnerable to attacks by quantum computers" and "NIST does not expect to need to transition away from these standards." By choosing SHA-512, Tidecoin aligns with NIST's highest security category for hash-based security.

### 7.2 Witness Version 1 with 512-bit Script Hash

Tidecoin extends Bitcoin's witness program with a new witness version 1 type: **P2WSH-512** (Pay-to-Witness-Script-Hash-512). This uses a 64-byte (512-bit) SHA-512 hash of the witness script, compared to Bitcoin's 32-byte SHA-256 hash.

Defined in `src/script/interpreter.h:178-180`:

```
WITNESS_V0_SCRIPTHASH_SIZE = 32   // Bitcoin-compatible (SHA-256)
WITNESS_V0_KEYHASH_SIZE = 20      // Bitcoin-compatible (HASH160)
WITNESS_V1_SCRIPTHASH_512_SIZE = 64  // Tidecoin PQ (SHA-512)
```

The v1 witness is activated by the `SCRIPT_VERIFY_WITNESS_V1_512` consensus flag, height-gated for safe deployment.

### 7.3 Post-Quantum Address Formats

Tidecoin uses two bech32 address families (source: `src/kernel/chainparams.cpp:153-154`):

| Address Type | HRP | Witness Version | Use Case |
|-------------|-----|-----------------|----------|
| Standard | `tbc` | v0 | SegWit-compatible PQ addresses |
| Post-Quantum | `q` | v1 | PQ-native SHA-512 witness addresses |

Testnet uses `ttbc` and `tq`; regtest uses `rtbc` and `rq`.

---

## 8. Post-Quantum Peer-to-Peer Transport

### 8.1 ML-KEM-512 Key Encapsulation

Tidecoin's v2 peer-to-peer transport protocol replaces Bitcoin's ECDH-based key exchange with **ML-KEM-512** (FIPS 203), a Module-Lattice-Based Key-Encapsulation Mechanism.

ML-KEM-512 parameters (NIST Security Level 1):

| Parameter | Size |
|-----------|------|
| Encapsulation (public) key | 800 bytes |
| Decapsulation (private) key | 1,632 bytes |
| Ciphertext | 768 bytes |
| Shared secret | 32 bytes |

The ML-KEM handshake establishes a 256-bit shared secret that is then used for authenticated encryption of all subsequent peer-to-peer communication. This ensures that an adversary with a quantum computer cannot decrypt recorded network traffic to extract transaction data before it is confirmed in a block.

Implementation: `src/pq/kem.cpp` (83 lines), `src/pq/pq_api.h:69-109`, with Python functional test support via a vendored ML-KEM library at `test/functional/test_framework/crypto/kyber_py/ml_kem/`.

### 8.2 Why P2P Encryption Matters for PQ

In a classical setting, P2P encryption prevents passive eavesdropping but is less critical because transactions are broadcast publicly. In a post-quantum setting, P2P encryption prevents a quantum adversary from:

1. Intercepting transactions between broadcast and confirmation
2. Extracting public keys from unconfirmed transactions in the mempool
3. Correlating network metadata with quantum key-recovery attacks

---

## 9. Auxiliary Proof-of-Work (Merged Mining)

### 9.1 Design

Tidecoin includes full AuxPoW infrastructure (source: `src/auxpow.h`, `src/auxpow.cpp`) for merged mining with scrypt-based parent chains such as Litecoin. Merged mining allows miners working on a parent chain to simultaneously secure Tidecoin using the same computational work.

The protocol embeds a Tidecoin block hash in the parent chain's coinbase transaction (prefixed with magic bytes `0xfabe6d6d`), allowing the parent chain's proof-of-work to serve as valid proof for Tidecoin's consensus.

**Current status:** AuxPoW infrastructure is complete but activation is deferred (`consensus.nAuxpowStartHeight = Consensus::AUXPOW_DISABLED` in `src/kernel/chainparams.cpp:93`). Activation will occur via a consensus upgrade at a predetermined block height.

### 9.2 Quantum Resistance of Scrypt Merged Mining

Merged mining with a scrypt-based parent chain provides an additional layer of quantum resistance at the proof-of-work level:

- **Scrypt is maximally memory-hard** (proven, EUROCRYPT 2017), requiring QRAM for quantum oracle construction
- **Inherited hashrate:** Tidecoin would benefit from the combined hashrate of all Litecoin miners that opt into merged mining, dramatically increasing the cost of a 51% attack
- **Double barrier:** A quantum attacker must both overcome scrypt's memory-hardness in quantum computation and outcompete the parent chain's aggregate hashrate

The Dogecoin-Litecoin precedent demonstrates the effectiveness of AuxPoW: after Dogecoin enabled merged mining with Litecoin in 2014, its mining difficulty increased by approximately 1,500% within one month, with approximately 90% of its hashrate coming from Litecoin mining pools.

---

## 10. Economic Model

### 10.1 Supply Schedule

Tidecoin uses a doubling-interval halving schedule with quartering rewards, designed to converge to a total supply of approximately 21 million TDC (source: `src/validation.cpp:1946-1974`, `src/kernel/chainparams.cpp:86`).

**Initial parameters:**
- Initial block reward: 40 TDC
- Initial halving interval: 262,800 blocks (~6 months at 60-second blocks)

**Schedule:**

| Era | Interval (blocks) | Duration | Block Reward | Cumulative Supply |
|-----|-------------------|----------|-------------|-------------------|
| 1 | 262,800 | ~6 months | 40 TDC | 10,512,000 TDC |
| 2 | 525,600 | ~1 year | 10 TDC | 15,768,000 TDC |
| 3 | 1,051,200 | ~2 years | 2.5 TDC | 18,396,000 TDC |
| 4 | 2,102,400 | ~4 years | 0.625 TDC | 19,710,000 TDC |
| 5 | 4,204,800 | ~8 years | 0.15625 TDC | 20,367,000 TDC |
| 6 | 8,409,600 | ~16 years | 0.0390625 TDC | 20,695,500 TDC |
| ... | doubling | doubling | quartering | converges to ~21M |

**Key properties:**
- Each halving interval is twice the length of the previous one (geometric progression)
- The block reward is quartered (right-shifted by 2 bits) at each step, not halved
- This front-loads emission while maintaining a hard supply cap
- The schedule converges to approximately 21 million TDC total supply

**Implementation** (`src/validation.cpp:1970-1972`):

```cpp
CAmount nSubsidy = 40 * COIN;
nSubsidy >>= (halvings * 2);  // Quarter at each step
```

### 10.2 No Premine, No ICO

Tidecoin had no premine, no initial coin offering, and no developer allocation. All coins in circulation were earned through proof-of-work mining, beginning from block zero.

---

## 11. Network Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| **Ticker** | TDC | -- |
| **Genesis timestamp** | December 27, 2020, 13:09:40 UTC | `chainparams.cpp:134` |
| **Genesis hash** | `480ecc76...018075` | `chainparams.cpp:136` |
| **Block time target** | 60 seconds | `chainparams.cpp:100` |
| **Initial block reward** | 40 TDC | `validation.cpp:1970` |
| **Halving interval (initial)** | 262,800 blocks | `chainparams.cpp:86` |
| **Total supply** | ~21,000,000 TDC | Derived from schedule |
| **PoW algorithm** | YespowerTIDE (CPU-optimized, memory-hard) | `pureheader.cpp:20-27` |
| **Default port** | 8755 | `chainparams.cpp:129` |
| **Network magic** | 0xecfacea5 | `chainparams.cpp:125-128` |
| **Bech32 HRP** | `tbc` (mainnet), `q` (PQ witness) | `chainparams.cpp:153-154` |
| **Active signature scheme** | Falcon-512 | `pq_scheme.h:52-60` |
| **P2P encryption** | ML-KEM-512 | `pq/kem.cpp` |
| **DNS seeds** | seed.tidecoin.co, tidecoin.ddnsgeek.com, tidecoin.theworkpc.com | `chainparams.cpp:144-146` |
| **SegWit** | Active from block 1 | `chainparams.cpp:92` |
| **AuxPoW Chain ID** | 8 | `chainparams.cpp:94` |

---

## 12. Security Analysis

### 12.1 Signature Security

| Attack Vector | ECDSA (Bitcoin) | Falcon-512 (Tidecoin) |
|--------------|----------------|----------------------|
| Classical best attack | 2^128 (Pollard's rho) | 2^113+ (lattice reduction, provable) |
| Quantum attack (Shor) | Polynomial time -- **broken** | Not applicable (no ECDLP) |
| Quantum attack (Grover on hash) | N/A | Quadratic speedup on underlying hash |
| Underlying hard problem | ECDLP | SIS over NTRU lattices |
| NIST security level | N/A (deprecated) | Level 1 (AES-128 equivalent) |

Falcon-512's security is proven in the Quantum Random Oracle Model under the assumption that the SIS problem over NTRU lattices is hard. The NTRU lattice problem has been studied since 1996 (Hoffstein, Pipher, Silverman) with no known polynomial-time quantum algorithm.

### 12.2 Hash Security

| Component | Bitcoin | Tidecoin | PQ Security Level |
|-----------|---------|----------|-------------------|
| Block hash | SHA-256d | SHA-256d | 128-bit (NIST Cat 1) |
| Witness script hash (v0) | SHA-256 | SHA-256 | 128-bit (NIST Cat 1) |
| Witness script hash (v1) | N/A | SHA-512 | 256-bit (NIST Cat 5) |
| Address hash (P2PKH) | HASH160 | HASH160 | 80-bit (legacy compat) |

NIST confirms: "The existing algorithm standards for symmetric cryptography are less vulnerable to attacks by quantum computers. NIST does not expect to need to transition away from these standards as part of the PQC migration."

### 12.3 Proof-of-Work Security

| Property | SHA-256d (Bitcoin) | YespowerTIDE (Tidecoin) |
|----------|-------------------|------------------------|
| Memory requirement | ~0 (stateless) | 1-16 MB |
| Grover speedup | Full quadratic (sqrt) | Limited by QRAM requirement |
| QRAM needed | Minimal | Megabytes (does not exist at scale) |
| ASIC advantage | ~10^6x over CPU | Moderate over CPU |
| Mining decentralization | ASIC-dominated | CPU-accessible |

### 12.4 Transport Security

| Property | Bitcoin v2 | Tidecoin v2 |
|----------|-----------|-------------|
| Key exchange | ECDH (secp256k1) | ML-KEM-512 (FIPS 203) |
| Quantum security | Broken by Shor | NIST Level 1 |
| Shared secret | 32 bytes | 32 bytes |

### 12.5 Memory Safety

The PQ implementation applies defense-in-depth memory safety practices:

- `memory_cleanse()` on all secret material after use
- `secure_allocator<>` for private key storage
- RAII destructors with mandatory cleanup (including ML-KEM keypairs)
- Move-only or deleted copy constructors for sensitive objects
- No heap allocation for cryptographic temporaries where avoidable
- Retry loops for probabilistic operations (Falcon signing) with per-attempt cleanup

---

## 13. Comparison with Other Post-Quantum Projects

| Feature | Tidecoin | QRL | Algorand | Bitcoin (proposed) | Ethereum (proposed) |
|---------|----------|-----|----------|-------------------|-------------------|
| **PQ algorithms** | Falcon-512/1024, ML-DSA-44/65/87, ML-KEM-512 | XMSS (hash-based) | Falcon-1024 | BIP-360: Falcon, ML-DSA | Account abstraction |
| **PQ since genesis** | Yes (Dec 2020) | Yes (2018) | No (Nov 2025 first tx) | No (proposal stage) | No (devnet stage) |
| **NIST standards** | FIPS 203, 204, draft 206 | RFC 8391 | Draft FIPS 206 | Proposed only | Proposed only |
| **Stateless signatures** | Yes | No (XMSS is stateful) | Yes | Proposed | Proposed |
| **Consensus model** | PoW (memory-hard) | PoW -> PoS | Pure PoS | PoW (SHA-256d) | PoS |
| **HD wallet** | PQHD (custom, hardened-only) | N/A | N/A | BIP-360 proposal | N/A |
| **P2P encryption** | ML-KEM-512 | N/A | N/A | N/A | N/A |
| **Bitcoin heritage** | Full (v30 codebase) | Independent | Independent | Is Bitcoin | Independent |
| **Years of operation** | 5+ | 7+ | PQ: < 1 year | N/A | N/A |
| **Max supply** | ~21M TDC | 65M QRL | 10B ALGO | 21M BTC | Unlimited |
| **Compact signatures** | Yes (Falcon: 666 B) | No (XMSS: ~2.7 KB) | Yes (Falcon: 1.3 KB) | Proposed | Proposed |

### Key Differentiators

1. **Multi-scheme architecture:** Tidecoin supports five NIST-standardized signature schemes, allowing scheme agility. If a vulnerability is found in one lattice construction, alternative schemes are available through consensus upgrade.

2. **Full-stack PQ:** Unlike projects that add PQ at only one layer, Tidecoin secures signatures (Falcon/ML-DSA), script hashing (SHA-512), P2P transport (ML-KEM), and wallet derivation (PQHD) with post-quantum primitives.

3. **Bitcoin-compatible architecture:** Tidecoin preserves Bitcoin's UTXO model, enabling future compatibility with Bitcoin ecosystem tooling, while other PQ projects use custom transaction models.

4. **Stateless signatures:** Unlike QRL's XMSS (which is stateful and limits key reuse to 2^13 signatures), Falcon and ML-DSA are stateless -- keys can sign unlimited messages without tracking state.

---

## 14. Operational Track Record

Tidecoin has been in continuous operation since December 27, 2020:

| Metric | Value |
|--------|-------|
| Genesis date | December 27, 2020 |
| Years of operation | 5+ |
| Total blocks produced | ~2,380,000+ |
| Security incidents | 0 |
| Consensus failures | 0 |
| Hard forks | 0 (all changes via soft fork) |
| Network participants | 53+ connected nodes |
| Mining pools | 6+ active pools |
| Exchange listings | Dex-Trade, NonKyc.io, PancakeSwap V2 (wTDC) |

The project was first announced on BitcoinTalk on January 4, 2021, and has maintained continuous community presence on Discord (1,000+ members), Telegram, and X/Twitter.

Tidecoin was discussed on the official NIST Post-Quantum Cryptography mailing list (pqc-forum), which is notable recognition for a cryptocurrency project.

---

## 15. Roadmap

### Completed

- Falcon-512 signature scheme (active since genesis)
- PQHD deterministic wallet with encrypted seed storage
- SegWit activation from block 1
- YespowerTIDE CPU-friendly proof-of-work
- ML-KEM-512 P2P transport encryption
- OP_SHA512 and witness v1 512-bit script support (consensus rules)
- AuxPoW merged mining infrastructure
- 135 unit test files + 255 functional test files

### Planned

- **AuxPoW activation:** Enable merged mining with scrypt-based parent chains
- **Multi-scheme activation:** Unlock Falcon-1024, ML-DSA-44/65/87 at AuxPoW height
- **Hardware wallet integration:** Falcon-512 and ML-DSA support for Ledger/Trezor secure elements
- **Cross-chain bridges:** Quantum-secure bridge protocols using ML-KEM key exchange
- **Performance optimization:** SIMD-accelerated signature verification for high-throughput nodes

---

## 16. Conclusion

The quantum threat to cryptocurrency is not a question of *if* but *when*. NIST, the Federal Reserve, the NSA, and the UK NCSC all recommend migration to post-quantum cryptography within the next decade. Yet Bitcoin, Ethereum, and the vast majority of blockchain systems have not begun this migration, and face years of political and technical obstacles before they can.

Tidecoin took a different approach: build quantum resistance in from the start. Every transaction on the Tidecoin blockchain, from genesis to the present, is protected by NIST-standardized post-quantum signatures. The network has operated continuously for over five years without incident, demonstrating that post-quantum cryptocurrency is not merely theoretical -- it is operational, tested, and production-ready.

By combining the proven foundation of Bitcoin Core with NIST's post-quantum cryptographic standards, Tidecoin offers what no other project currently provides: a Bitcoin-architecture cryptocurrency that is quantum-safe today, not someday.

---

## 17. References

### NIST Standards and Publications

1. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM). August 2024. https://csrc.nist.gov/pubs/fips/203/final
2. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA). August 2024. https://csrc.nist.gov/pubs/fips/204/final
3. NIST FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA). August 2024. https://csrc.nist.gov/pubs/fips/205/final
4. NIST Draft FIPS 206: FFT over NTRU-Lattice-Based Digital Signature Standard (FN-DSA/Falcon). In preparation. https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon
5. NIST IR 8547: Transition to Post-Quantum Cryptography Standards. 2024. https://csrc.nist.gov/pubs/ir/8547/ipd
6. NIST Post-Quantum Cryptography Standardization Process. https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization

### Academic Papers

7. Shor, P. "Algorithms for Quantum Computation: Discrete Logarithms and Factoring." FOCS 1994.
8. Alwen, J., Chen, B., Pietrzak, K., Reyzin, L., Tessaro, S. "Scrypt Is Maximally Memory-Hard." EUROCRYPT 2017. https://eprint.iacr.org/2016/989
9. Gentry, C., Peikert, C., Vaikuntanathan, V. "Trapdoors for Hard Lattices and New Cryptographic Constructions." STOC 2008.
10. Hoffstein, J., Pipher, J., Silverman, J.H. "NTRU: A Ring-Based Public Key Cryptosystem." ANTS-III 1998.
11. Song, G., Seo, H. "Grover on Scrypt." MDPI Electronics, vol. 13, no. 16, article 3167, 2024. https://www.mdpi.com/2079-9292/13/16/3167
12. Roetteler, M., Naehrig, M., Svore, K.M., Lauter, K. "Quantum Resource Estimates for Computing Elliptic Curve Discrete Logarithms." 2017. https://eprint.iacr.org/2017/598
13. Mascelli, M.D., Rodden, T. "Harvest Now Decrypt Later: Examining Post-Quantum Cryptography and the Data Privacy Risks for Distributed Ledger Networks." Federal Reserve FEDS 2025-093, 2025. https://www.federalreserve.gov/econres/feds/harvest-now-decrypt-later-examining-post-quantum-cryptography-and-the-data-privacy-risks-for-distributed-ledger-networks.htm

### Tidecoin Sources

14. Tidecoin source code. https://github.com/tidecoin/tidecoin
15. Tidecoin original whitepaper. https://github.com/tidecoin-old/whitepaper/blob/master/tidecoin.pdf
16. Tidecoin official website. https://tidecoin.org/

### Cryptographic References

17. Falcon specification. https://falcon-sign.info/falcon.pdf
18. PQClean: Clean, portable implementations of post-quantum cryptography. https://github.com/PQClean/PQClean
19. Percival, C. "Stronger Key Derivation via Sequential Memory-Hard Functions." BSDCan'09. https://www.tarsnap.com/scrypt.html
20. Solar Designer. Yespower. https://www.openwall.com/yespower/

---

## 18. Sources Consulted

The following URLs were accessed during the research and preparation of this whitepaper. They are provided for transparency and verifiability.

### NIST and Government Sources

- https://csrc.nist.gov/pubs/fips/203/final
- https://csrc.nist.gov/pubs/fips/204/final
- https://csrc.nist.gov/pubs/fips/205/final
- https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon
- https://csrc.nist.gov/presentations/2024/navigating-floating-point-challenges-in-falcon
- https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization
- https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)
- https://csrc.nist.gov/projects/post-quantum-cryptography/workshops-and-timeline
- https://csrc.nist.gov/projects/post-quantum-cryptography/faqs
- https://csrc.nist.gov/pubs/ir/8547/ipd
- https://csrc.nist.gov/Presentations/2024/practical-cost-of-grover-for-aes-key-recovery
- https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
- https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
- https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
- https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption
- https://www.federalreserve.gov/econres/feds/harvest-now-decrypt-later-examining-post-quantum-cryptography-and-the-data-privacy-risks-for-distributed-ledger-networks.htm
- https://www.federalreserve.gov/econres/feds/files/2025093pap.pdf
- https://www.federalregister.gov/documents/2024/08/14/2024-17956/announcing-issuance-of-federal-information-processing-standards-fips-fips-203-module-lattice-based

### Falcon and ML-DSA Technical Sources

- https://falcon-sign.info/
- https://falcon-sign.info/falcon.pdf
- https://eprint.iacr.org/2024/1709.pdf
- https://eprint.iacr.org/2024/1769.pdf
- https://csrc.nist.gov/csrc/media/Events/2022/fourth-pqc-standardization-conference/documents/papers/falcon-down-pqc2022.pdf
- https://openquantumsafe.org/liboqs/algorithms/sig/ml-dsa.html
- https://github.com/itzmeanjan/ml-kem
- https://github.com/PQClean/PQClean

### Quantum Computing and Cryptography Analysis

- https://eprint.iacr.org/2017/598.pdf
- https://eprint.iacr.org/2021/967.pdf
- https://eprint.iacr.org/2021/292.pdf
- https://eprint.iacr.org/2016/989
- https://eprint.iacr.org/2023/062.pdf
- https://kudelskisecurity.com/research/quantum-attack-resource-estimate-using-shors-algorithm-to-break-rsa-vs-dh-dsa-vs-ecc/
- https://a16zcrypto.com/posts/article/quantum-computing-misconceptions-realities-blockchains-planning-migrations/
- https://pmc.ncbi.nlm.nih.gov/articles/PMC8946996/
- https://arxiv.org/pdf/1711.04235
- https://www.sciencedirect.com/science/article/pii/S2096720923000167
- https://www.schneier.com/blog/archives/2022/02/breaking-245-bit-elliptic-curve-encryption-with-a-quantum-computer.html

### Memory-Hard Functions and PoW Quantum Resistance

- https://www.mdpi.com/2079-9292/13/16/3167
- https://www.mdpi.com/2079-9292/12/21/4485
- https://quantum-safeinternet.com/project/quantum-security-of-memory-hard-functions/
- https://link.springer.com/chapter/10.1007/978-3-319-56617-7_2
- https://link.springer.com/chapter/10.1007/978-981-99-8727-6_1
- https://dl.acm.org/doi/fullHtml/10.1145/3613424.3614270
- https://pmc.ncbi.nlm.nih.gov/articles/PMC10490729/
- https://sites.cs.ucsb.edu/~rich/class/old.cs290/papers/scrypt.pdf
- https://www.rfc-editor.org/rfc/rfc7914.html
- https://www.tarsnap.com/scrypt.html
- https://www.openwall.com/yespower/
- https://www.openwall.com/yescrypt/
- https://github.com/openwall/yespower
- https://en.wikipedia.org/wiki/Solar_Designer
- https://openwall.info/wiki/people/solar/bio

### SHA-512 and Hash Security

- https://bitcoinops.org/en/topics/quantum-resistance/
- https://www.gopher.security/post-quantum/is-sha-256-secure-against-quantum-attacks
- https://bip360.org/bip360.html
- https://postquantum.com/post-quantum/nist-pqc-security-categories/
- https://postquantum.com/post-quantum/grovers-algorithm/
- https://postquantum.com/post-quantum/brassard-hoyer-tapp-bht/
- https://postquantum.com/post-quantum/quantum-cryptocurrencies-bitcoin/

### Bitcoin Quantum Vulnerability and Migration

- https://bip360.org/
- https://qbip.org/
- https://delvingbitcoin.org/t/proposing-a-p2qrh-bip-towards-a-quantum-resistant-soft-fork/956
- https://delvingbitcoin.org/t/post-quantum-hd-wallets-silent-payments-key-aggregation-and-threshold-signatures/1854
- https://chaincode.com/bitcoin-post-quantum.pdf
- https://blog.projecteleven.com/posts/a-look-at-post-quantum-proposals-for-bitcoin
- https://blog.projecteleven.com/posts/hd-wallets--quantum-risk-does-reusing-one-address-endanger-the-rest
- https://river.com/learn/will-quantum-computing-break-bitcoin/
- https://hrf.org/latest/the-quantum-threat-to-bitcoin/
- https://bitcoinmagazine.com/news/new-bitcoin-improvement-proposal-aims-to-solve-future-quantum-security-risks
- https://bitbo.io/news/quantum-resistant-bip-360-debate/
- https://thebitcoinmanual.com/articles/qramp/
- https://bitcoinist.com/bitcoins-post-quantum-shift-could-take-a-decade-crypto-exec-says/
- https://www.ainvest.com/news/bitcoin-quantum-migration-decade-long-transition-investment-implications-2512/
- https://www.coindesk.com/tech/2025/12/20/bitcoin-s-quantum-debate-is-resurfacing-and-markets-are-starting-to-notice
- https://www.cointribune.com/en/bip-360-bitcoin-divides-over-quantum-challenge/
- https://finance.yahoo.com/news/coinshares-says-only-10-200-170531015.html
- https://thequantuminsider.com/2025/10/06/federal-reserve-warns-quantum-computers-could-expose-bitcoins-hidden-past/
- https://crypto.news/bitcoin-investors-face-harvest-now-decrypt-later-quantum-threat/
- https://forklog.com/en/secret-harvesters-why-quantum-computers-threaten-bitcoin-privacy/
- https://en.wikipedia.org/wiki/Harvest_now,_decrypt_later
- https://conduition.io/cryptography/quantum-hbs/

### Post-Quantum Cryptocurrency Projects

- https://www.theqrl.org/
- https://docs.theqrl.org/what-is-qrl/
- https://www.theqrl.org/blog/techniques-for-efficient-post-quantum-finance-part-4-reducing-storage-requirements/
- https://algorand.co/technology/post-quantum
- https://algorand.co/blog/technical-brief-quantum-resistant-transactions-on-algorand-with-falcon-signatures
- https://algorand.co/blog/pioneering-falcon-post-quantum-technology-on-blockchain
- https://www.biometricupdate.com/202510/iota-adds-post-quantum-cryptography-to-its-identity-framework
- https://ethereum.org/roadmap/future-proofing/
- https://www.btq.com/blog/ethereums-roadmap-post-quantum-cryptography
- https://cointelegraph.com/news/why-vitalik-believes-quantum-computing-could-break-ethereum-s-cryptography-sooner-than-expected
- https://cointelegraph.com/news/ethereum-post-quantum-resilience-interview
- https://blockmanity.com/news/5-quantum-resistant-blockchain-projects-worth-watching-in-2026/
- https://www.webopedia.com/crypto/learn/post-quantum-crypto-projects/
- https://medium.com/mochimo-official/mcm-post-quantum-security-in-blockchain-820b3758fa83
- https://cellframe.net/
- https://www.amarchenkova.com/posts/quantum-secure-cryptocurrencies-qrl-mochimo-iota-cardano
- https://thequantumspace.org/2025/11/11/post-quantum-wallets/
- https://www.encryptionconsulting.com/how-ml-dsa-replaces-ecc-and-rsa-for-digital-signatures/
- https://www.encryptionconsulting.com/overview-of-fips-203/
- https://www.encryptionconsulting.com/decoding-nist-pqc-standards/

### HD Wallet and PQ Key Derivation

- https://link.springer.com/article/10.1186/s42400-024-00216-w
- https://www.sciencedirect.com/science/article/abs/pii/S0304397524002895

### Merged Mining

- https://en.bitcoin.it/wiki/Merged_mining_specification
- https://tlu.tarilabs.com/mining/MergedMiningIntroduction
- https://www.binance.com/en/research/analysis/merged-mining
- https://www.litecoinpool.org/news?id=59
- https://litecoin.com/news/how-litecoin-and-dogecoin-created-one-of-the-most-robust-pow-networks
- https://coincub.com/mining/merge-mining/
- https://www.coinspect.com/blog/merged-mining-security/
- https://earnednotgifted.medium.com/my-take-on-merged-mining-why-merged-mining-doesnt-increase-security-of-the-auxiliary-chain-ccd3bbc978b5
- https://blog.thirdweb.com/understanding-merged-mining-a-comprehensive-guide/

### Tidecoin-Specific Sources

- https://tidecoin.org/
- https://tdc-next.vercel.app/
- https://tidecoin.pqcsf.com/
- https://explorer.tidecoin.org/
- https://pool.tidecoin.exchange/
- https://github.com/tidecoin/tidecoin
- https://github.com/tidecoin-old/whitepaper
- https://github.com/tidecoin-old/whitepaper/blob/master/tidecoin.pdf
- https://github.com/tidecoin/tidecoin-android-miner
- https://bitcointalk.org/index.php?topic=5306694.0
- https://bitcourier.co.uk/news/tidecoin-interview
- https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/GZKDF25GYc8
- https://setcoinkr.medium.com/tidecoin-a-post-quantum-security-peer-to-peer-crypto-cash-4c181f55f753
- https://skybaseja.medium.com/tidecoin-a-post-quantum-security-peer-to-peer-crypto-cash-74cbca584140
- https://en.namu.wiki/w/%ED%83%80%EC%9D%B4%EB%93%9C%EC%BD%94%EC%9D%B8
- https://en.everybodywiki.com/Tidecoin
- https://tideidle.com/Tide_specifications/
- https://miningpoolstats.stream/tidecoin
- https://www.coingecko.com/en/coins/tidecoin
- https://coincodex.com/crypto/tidecoin/exchanges/
- https://coinpaprika.com/coin/tdc-tidecoin/
- https://www.livecoinwatch.com/price/Tidecoin-TDC
- https://bscscan.com/token/0x0e182bd5c8703632c4c1761e0496c66c2b5d3385
- https://disboard.org/server/796853997259849728
- https://x.com/tidecoin
- https://x.com/Tidecoin_go
- https://cputest.ru/store/yespower/tidecoin_yespowertide/33

### Industry and Standards Analysis

- https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist
- https://utimaco.com/news/blog-posts/nists-final-pqc-standards-are-here-what-you-need-know
- https://hacken.io/insights/ml-dsa-crystals-dilithium/
- https://cloudsecurityalliance.org/blog/2024/08/15/nist-fips-203-204-and-205-finalized-an-important-step-towards-a-quantum-safe-future
- https://www.jbs.cam.ac.uk/2025/why-quantum-matters-now-for-blockchain/
- https://en.wikipedia.org/wiki/NIST_Post-Quantum_Cryptography_Standardization
- https://en.wikipedia.org/wiki/Grover's_algorithm
- https://arxiv.org/pdf/2505.02239
- https://arxiv.org/pdf/2510.09271
- https://arxiv.org/pdf/2409.01358
- https://blog.cloudflare.com/another-look-at-pq-signatures/
- https://ceur-ws.org/Vol-3460/papers/DLT_2023_paper_19.pdf
- https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1457000/full
- https://github.com/veracrypt/VeraCrypt/issues/1271
- https://www.binance.com/en/square/post/2024-10-29-vitalik-buterin-outlines-quantum-resistant-future-for-ethereum-in-new-roadmap-update-15509117799834
- https://www.mexc.com/price/tidecoin
- https://coinmarketcap.com/cmc-ai/quantum-resistant-ledger/what-is/

### Codebase Source Files Analyzed

- `src/pq/pq_scheme.h` -- PQ scheme registry (5 schemes, constexpr metadata)
- `src/pq/pq_api.h` -- C++ API for PQ operations (KeyGen, Sign, Verify)
- `src/pq/pqhd_kdf.h`, `src/pq/pqhd_kdf.cpp` -- PQHD key derivation function
- `src/pq/pqhd_keygen.cpp` -- PQHD deterministic key generation
- `src/pq/kem.cpp` -- ML-KEM-512 wrapper
- `src/pq/falcon512.c`, `src/pq/falcon1024.c` -- Falcon signature wrappers
- `src/pq/mldsa44.c`, `src/pq/mldsa65.c`, `src/pq/mldsa87.c` -- ML-DSA wrappers
- `src/script/interpreter.cpp` -- CheckPostQuantumSignature consensus logic
- `src/script/interpreter.h` -- PQ script verification flags
- `src/script/script.h` -- OP_SHA512 opcode definition
- `src/script/descriptor.cpp`, `src/script/descriptor.h` -- PQHD descriptor provider
- `src/pubkey.cpp`, `src/pubkey.h` -- PQ-aware public key verification
- `src/key.h`, `src/key.cpp` -- PQ-aware private key operations
- `src/kernel/chainparams.cpp` -- Chain parameters (genesis, ports, seeds, consensus)
- `src/validation.cpp` -- Block subsidy schedule (doubling-interval quartering)
- `src/primitives/pureheader.cpp` -- Yespower and scrypt PoW hash functions
- `src/auxpow.h`, `src/auxpow.cpp` -- AuxPoW merged mining
- `src/wallet/pqhd.h` -- PQHD seed/policy data structures
- `src/wallet/wallet.cpp` -- PQHD seed loading and policy management
- `src/wallet/scriptpubkeyman.cpp` -- PQHD descriptor integration
- `src/wallet/rpc/wallet.cpp` -- setpqhdpolicy RPC command
- `src/psbt.h` -- PSBT PQHD proprietary fields
- `src/clientversion.cpp` -- "Tidecoin" user agent name
- `src/policy/policy.cpp` -- PQ-aware dust threshold and witness recognition
- `CMakeLists.txt` -- CLIENT_NAME "Tidecoin", version 30.0.0

---

*Tidecoin is open-source software released under the MIT license.*
*Copyright (c) 2020-2026 The Tidecoin developers.*
*Copyright (c) 2009-2025 The Bitcoin Core developers.*
