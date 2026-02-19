# Tidecoin (TDC)

Tidecoin is a post-quantum cryptocurrency that replaces ECDSA entirely with NIST-standardized FALCON-512 digital signatures, securing every transaction against quantum computing attacks since genesis (December 2020). Built on Bitcoin Core v30 with a 21 million TDC supply, CPU-mineable via YespowerTIDE.

## What is Tidecoin?

Tidecoin is a decentralized peer-to-peer cryptocurrency engineered from block zero to resist attacks from both classical and quantum computers. While Bitcoin and virtually all major blockchains rely on ECDSA — which Shor's algorithm will break once sufficiently powerful quantum computers exist — Tidecoin replaces ECDSA entirely with NIST-standardized post-quantum signature schemes.

The network has been in continuous operation since December 27, 2020, with over 2.3 million blocks produced and zero security incidents. Every cryptographic primitive in Tidecoin is either a finalized NIST standard or a NIST competition winner in active standardization.

| | |
|---|---|
| **Ticker** | TDC |
| **Algorithm** | YespowerTIDE (CPU-friendly, memory-hard) |
| **Block time** | 60 seconds |
| **Max supply** | ~21,000,000 TDC |
| **Premine/ICO** | None — all coins earned through mining |
| **Genesis date** | December 27, 2020 |
| **Default port** | 8755 |
| **License** | MIT |

## Why Does Post-Quantum Matter?

NIST Interagency Report 8547 recommends that all systems migrate to post-quantum cryptography by 2030, with mandatory compliance by 2035. Blockchain data is uniquely vulnerable due to the "Harvest Now, Decrypt Later" threat — the Federal Reserve's 2025 analysis (FEDS 2025-093) specifically examines this risk for distributed ledger networks.

The core problem: an adversary can record today's public blockchain data and derive private keys once cryptographically relevant quantum computers (CRQCs) become available. For Bitcoin, approximately 5.9 million BTC (~25% of supply) sits in quantum-vulnerable address formats, including Satoshi's estimated 968,000 BTC in P2PK addresses with no possibility of migration.

Tidecoin eliminates this entire problem class by using post-quantum signatures from block zero.

## What Post-Quantum Cryptography Does Tidecoin Use?

Tidecoin uses exclusively NIST-standardized cryptographic primitives — no ECDSA anywhere in the protocol:

| Layer | Algorithm | Standard | Purpose |
|-------|-----------|----------|---------|
| Signatures (default) | FALCON-512 | NIST Draft FIPS 206 (FN-DSA) | 666-byte lattice signatures, active since genesis |
| Signatures (higher security) | FALCON-1024 | NIST Draft FIPS 206 (FN-DSA) | 1,280-byte signatures, NIST Level 5 |
| Signatures (alternatives) | ML-DSA-44/65/87 | NIST FIPS 204 | Module-lattice digital signatures |
| P2P transport encryption | ML-KEM-512 | NIST FIPS 203 | Post-quantum key encapsulation |
| Witness script hashing | SHA-512 | NIST FIPS 180-4 | 256-bit security under Grover's algorithm |
| Wallet key derivation | PQHD | Custom, hardened-only | Hash-based HD wallet for PQ schemes |

FALCON-512's security is proven in the Quantum Random Oracle Model under the assumption that the SIS problem over NTRU lattices is hard — a problem studied since 1996 (Hoffstein, Pipher, Silverman) with no known efficient quantum algorithm.

## How Does Tidecoin Compare to Other Post-Quantum Projects?

| Feature | Tidecoin | QRL | Bitcoin (BIP-360) |
|---------|----------|-----|-------------------|
| PQ since genesis | Yes (Dec 2020) | Yes (Jun 2018) | No (proposal stage) |
| Signature schemes | FALCON-512/1024, ML-DSA-44/65/87 | XMSS (stateful, hash-based) | Proposes ML-DSA, SLH-DSA |
| Stateless signatures | Yes (unlimited signing) | No (limited OTS key reuse) | Proposed |
| Signature size | FALCON-512: 666 bytes | XMSS: ~2,500 bytes (RFC 8391) | N/A |
| PQ P2P transport encryption | ML-KEM-512 (FIPS 203) | No (plain TCP) | No |
| PQ HD wallet | PQHD (custom, hardened-only) | No | Proposed |
| Multi-scheme agility | 5 NIST schemes | XMSS only | Proposed |
| Bitcoin codebase | Yes (Core v30) | Independent | Is Bitcoin |
| Max supply | ~21M TDC | 105M QRL | ~21M BTC |

Sources: QRL documentation (theqrl.org), BIP-360 specification (bip360.org), NIST FIPS 203/204/206.

## Key Features

- **Full-stack post-quantum security** — Signatures, P2P transport, script hashing, and wallet derivation all use post-quantum primitives. Unlike projects that add PQ at only one layer, Tidecoin secures every cryptographic surface.
- **NIST standards, not experiments** — Every algorithm is a NIST standard or competition winner from the 8-year PQC standardization process (2016-2024, 69 initial submissions narrowed to 4 winners).
- **Multi-scheme cryptographic agility** — Five NIST-standardized signature schemes. If a vulnerability is found in one lattice construction, alternative schemes are available through consensus upgrade.
- **Bitcoin Core v30 foundation** — Preserves the UTXO model, scripting system, peer-to-peer network, and 15+ years of peer-reviewed consensus logic. 135 unit test files and 255 functional test files.
- **CPU-friendly mining** — YespowerTIDE memory-hard algorithm for fair distribution without specialized hardware.
- **No premine, no ICO** — All coins earned through proof-of-work mining from block zero.
- **Merged mining ready** — AuxPoW infrastructure for scrypt-based merged mining with Litecoin (Phase 2), increasing 51% attack cost by 10,000x.

## What Is Tidecoin's Track Record?

| Metric | Value |
|--------|-------|
| Years of operation | 5+ (since December 2020) |
| Blocks produced | ~2,380,000+ |
| Security incidents | 0 |
| Consensus failures | 0 |

Tidecoin was discussed on the official NIST Post-Quantum Cryptography mailing list (pqc-forum).

## How Do I Build Tidecoin?

Tidecoin uses CMake. See the platform-specific build guides:

| Platform | Guide |
|----------|-------|
| Linux/Unix | [doc/build-unix.md](doc/build-unix.md) |
| macOS | [doc/build-osx.md](doc/build-osx.md) |
| Windows | [doc/build-windows.md](doc/build-windows.md) |
| Windows (MSVC) | [doc/build-windows-msvc.md](doc/build-windows-msvc.md) |
| FreeBSD | [doc/build-freebsd.md](doc/build-freebsd.md) |
| OpenBSD | [doc/build-openbsd.md](doc/build-openbsd.md) |
| NetBSD | [doc/build-netbsd.md](doc/build-netbsd.md) |

### Quick Build (Linux)

```bash
git clone https://github.com/tidecoin/tidecoin.git
cd tidecoin
cmake -B build
cmake --build build
```

### Running

```bash
# Start the Tidecoin daemon
./build/src/tidecoind

# Start with the GUI
./build/src/qt/tidecoin-qt

# CLI interface
./build/src/tidecoin-cli getblockchaininfo
```

## How Do I Run Tests?

```bash
# Unit tests
ctest --test-dir build

# Functional tests
build/test/functional/test_runner.py
```

See [src/test/README.md](src/test/README.md) for unit test details and [test/](test/) for functional and regression tests.

## Development Process

The `master` branch is regularly built and tested but is not guaranteed to be completely stable. See the build guides above for compilation instructions.

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code and submit new unit tests for old code. There are also [regression and integration tests](test/) written in Python.

Further developer documentation is available in the [doc folder](doc/).

## Frequently Asked Questions

### What makes Tidecoin quantum-resistant?

Tidecoin replaces Bitcoin's ECDSA with FALCON-512, a lattice-based digital signature scheme selected by NIST for post-quantum standardization (Draft FIPS 206 / FN-DSA). The underlying hard problem — Short Integer Solution (SIS) over NTRU lattices — has no known efficient quantum algorithm. All five supported signature schemes (FALCON-512, FALCON-1024, ML-DSA-44, ML-DSA-65, ML-DSA-87) are NIST-standardized.

### How does FALCON-512 compare to Bitcoin's ECDSA?

FALCON-512 produces 666-byte signatures versus ECDSA's 71 bytes, but provides security against both classical and quantum attacks. The classical security level is 2^113+ (lattice reduction) compared to ECDSA's 2^128 (Pollard's rho), while ECDSA is completely broken by Shor's quantum algorithm. FALCON-512 has the smallest signature size of any lattice-based post-quantum scheme.

### Can I mine Tidecoin with a CPU?

Yes. Tidecoin uses the YespowerTIDE algorithm, a memory-hard proof-of-work specifically designed for CPU mining. No specialized hardware (ASICs or GPUs) is required, enabling fair distribution.

### Is FALCON the same as NIST's FN-DSA?

Yes. FALCON (Fast Fourier Lattice-based Compact Signatures over NTRU) is the algorithm selected by NIST and being standardized as FN-DSA under Draft FIPS 206. Tidecoin is the only production blockchain using FALCON-512 as its primary signature scheme since genesis.

### What is PQHD?

PQHD (Post-Quantum Hierarchical Deterministic) is Tidecoin's custom wallet key derivation system. It extends Bitcoin's BIP-32 HD wallet concept to post-quantum signature schemes using hardened-only key derivation with hash-based KDF, ensuring quantum-resistant wallet generation.

### What happens when FIPS 206 is finalized?

NIST's finalization of FIPS 206 (FN-DSA/FALCON) validates Tidecoin's cryptographic foundation. Tidecoin has used FALCON-512 since genesis in December 2020, making it the longest-running production implementation of this NIST-selected algorithm.

## Documentation

- [Whitepaper](doc/whitepaper.md) — Tidecoin: A Post-Quantum Secure Peer-to-Peer Cryptocurrency v2.0
- [doc/](doc/) — Developer documentation, build guides, and design notes

## Network

| Resource | Link |
|----------|------|
| Website | https://tidecoin.org |
| Explorer | https://explorer.tidecoin.org |
| Source code | https://github.com/tidecoin/tidecoin |

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow. Useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).
Community standards and enforcement are described in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

If you discover a security vulnerability, please report it responsibly. Do **not** open a public issue.

See [SECURITY.md](SECURITY.md) for reporting instructions.

## License

Tidecoin is released under the MIT License. See [COPYING](COPYING) for details.

## References

- NIST FIPS 203: ML-KEM Standard. August 2024. https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204: ML-DSA Standard. August 2024. https://csrc.nist.gov/pubs/fips/204/final
- NIST Draft FIPS 206: FN-DSA (FALCON). https://csrc.nist.gov/pubs/fips/206/ipd
- NIST IR 8547: Transition to Post-Quantum Cryptography Standards. 2024.
- Federal Reserve FEDS 2025-093: Harvest Now Decrypt Later. 2025.
- Shor, P. "Algorithms for Quantum Computation." FOCS 1994.
- Hoffstein, J., Pipher, J., Silverman, J.H. "NTRU: A Ring-Based Public Key Cryptosystem." ANTS-III 1998.
