# Install and Build Tidecoin

`INSTALL.md` is a quick-start entrypoint. For platform-specific instructions,
see the build guides in `doc/`.

## Quick Start (Unix-like systems)

1. Install prerequisites:
   - GCC >= 11.1 or Clang >= 16.0
   - CMake >= 3.22
   - Python 3
   - `pkgconf` / `pkg-config`
2. Configure:

```bash
cmake -B build
```

3. Build:

```bash
cmake --build build -j"$(nproc)"
```

4. Optional install:

```bash
cmake --install build
```

## Optional Components

- Wallet: SQLite
- GUI: Qt6, qrencode
- ZMQ notifications: ZeroMQ
- IPC: Cap'n Proto

See `doc/dependencies.md` for the full matrix.

## Platform Guides

- `doc/build-unix.md`
- `doc/build-osx.md`
- `doc/build-windows.md`
- `doc/build-windows-msvc.md`
- `doc/build-freebsd.md`
- `doc/build-openbsd.md`
- `doc/build-netbsd.md`

## Deterministic / Pinned Dependencies

For self-hosted dependencies and reproducible builds, see:
- `depends/README.md`
