# Dependencies

These are the dependencies used by Tidecoin.
You can find installation instructions in the `/doc/build-*.md` file for your platform, or self-compile
them using [depends](/depends/README.md).

## Compiler

Tidecoin requires one of the following compilers.

| Dependency | Minimum required |
| --- | --- |
| [Clang](https://clang.llvm.org) | 16.0 |
| [GCC](https://gcc.gnu.org) | 11.1 |

## Required

### Build

| Dependency | Releases | Minimum required |
| --- | --- | --- |
| [Boost](../depends/packages/boost.mk) | [link](https://www.boost.org/users/download/) | 1.74.0 |
| CMake | [link](https://cmake.org/) | 3.22 |
| [libevent](../depends/packages/libevent.mk) | [link](https://github.com/libevent/libevent/releases) | 2.1.8 |

### Runtime

| Dependency | Releases | Minimum required |
| --- | --- | --- |
| glibc | [link](https://www.gnu.org/software/libc/) | 2.31 |

## Optional

### Build

| Dependency | Releases | Minimum required |
| --- | --- | --- |
| [Cap'n Proto](../depends/packages/capnp.mk) | [link](https://capnproto.org) | 0.7.1 |
| Python (scripts, tests) | [link](https://www.python.org) | 3.10 |
| [Qt](../depends/packages/qt.mk) (gui) | [link](https://download.qt.io/archive/qt/) | 6.2 |
| [qrencode](../depends/packages/qrencode.mk) (gui) | [link](https://fukuchi.org/works/qrencode/) | N/A |
| [SQLite](../depends/packages/sqlite.mk) (wallet) | [link](https://sqlite.org) | 3.7.17 |
| [systemtap](../depends/packages/systemtap.mk) ([tracing](tracing.md)) | [link](https://sourceware.org/systemtap/) | N/A |
| [ZeroMQ](../depends/packages/zeromq.mk) (notifications) | [link](https://github.com/zeromq/libzmq/releases) | 4.0.0 |

### Runtime

| Dependency | Releases | Minimum required |
| --- | --- | --- |
| [Fontconfig](../depends/packages/fontconfig.mk) (gui) | [link](https://www.freedesktop.org/wiki/Software/fontconfig/) | 2.6 |
| [FreeType](../depends/packages/freetype.mk) (gui) | [link](https://freetype.org) | 2.3.0 |

## Dependency Review Policy

Pinned versions are intentionally conservative for reproducible builds, but they
must be reviewed on a fixed cadence and with security-first escalation.

### Cadence

- Perform a dependency review at least once per quarter.
- Perform a full dependency review before each Tidecoin release branch cut.
- Track each review in an issue or PR that records what was checked and why
  versions were or were not updated.

### Security escalation

- High or critical security advisories affecting runtime or build-time
  dependencies must trigger an out-of-band review within 7 days.
- If remediation is available and compatible, prioritize version bumps or
  patches ahead of non-security feature work.
- If immediate upgrade is not possible, document compensating controls and
  target timeline in the tracking issue/PR.

### Scope

- Dependencies tracked in `depends/packages/*.mk`.
- Toolchain baselines listed in this document.
- CI/lint tool versions that can affect correctness or supply-chain risk.
