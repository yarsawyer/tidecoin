# Tidecoin End-to-End Naming Cleanup Runbook

## Status Update (2026-02-11)

- PR-1: Completed
- PR-2: Completed (runtime/user-facing naming migrated; behavior unchanged)
- PR-3: Completed for active operator docs (historical exceptions preserved)
- PR-4: Completed (manpages/completions renamed and regenerated)
- PR-5: Completed (init/service templates renamed and rewritten)
- PR-6: Completed for active contrib tooling/docs
- PR-7: Completed (test framework helper/property names migrated and validated)
- PR-8: Completed (naming guard lint integrated in lint runner/CI path and policy documented)

## Verification Snapshot (2026-02-11)

- Gate A checks passed:
  - `bash -n contrib/guix/guix-build contrib/guix/guix-codesign contrib/guix/libexec/build.sh contrib/guix/libexec/codesign.sh contrib/guix/libexec/prelude.bash`
  - `python3 -m py_compile contrib/macdeploy/macdeployqtplus`
- Additional syntax checks passed for renamed scripts and modified Python test framework files.
- Targeted functional tests passed after migration:
  - `feature_config_args.py`
  - `feature_includeconf.py`
  - `feature_framework_startup_failures.py`
  - `feature_init.py`
  - `feature_filelock.py`
  - `interface_bitcoin_cli.py`
- Naming guard check passed:
  - `test/lint/lint-tidecoin-naming.py`
- Full functional suite passed:
  - `./build/test/functional/test_runner.py --extended --jobs=8`
  - Result: `278/278` test scripts completed successfully (with expected environment-dependent skips only).
- Gate B status:
  - macOS-host Guix smoke (`guix-build` for `x86_64-apple-darwin` + `arm64-apple-darwin`) remains pending as final pre-merge validation.

## Objective
Perform a repo-wide cleanup so active code, packaging, tools, and docs are consistent with Tidecoin naming:

- Config file: `tidecoin.conf` (not `bitcoin.conf`)
- Daemon binary: `tidecoind` (not `bitcoind`)
- CLI/tools: `tidecoin-*`
- Default datadir naming on all OSes: Tidecoin paths

This plan assumes a hard cut with no legacy aliases/fallbacks for active paths.

## Guix Non-Regression Contract
These constraints are mandatory for every PR in this runbook:

- Do not change Guix host triples, SDK resolution, or build graph behavior.
- Preserve Guix output naming contracts unless explicitly coordinated:
  - `${DISTNAME}-${HOST}-codesigning.tar.gz`
  - `${DISTNAME}-${HOST}-unsigned.zip` (darwin)
  - signed outputs produced by `guix-codesign` unchanged in shape
- If config artifact names change (`bitcoin.conf` -> `tidecoin.conf`), update all packaging copy points in the same PR (never split across PRs).
- Keep `contrib/guix` shell scripts syntactically valid at all times.

## Mandatory Guix Gates Per PR

### Gate A (required on every PR)
- Shell syntax check:
  - `bash -n contrib/guix/guix-build contrib/guix/guix-codesign contrib/guix/libexec/build.sh contrib/guix/libexec/codesign.sh contrib/guix/libexec/prelude.bash`
- Python syntax check for deploy tooling touched by darwin Guix path:
  - `python3 -m py_compile contrib/macdeploy/macdeployqtplus`
- Static contract grep:
  - verify `Tidecoin-Qt`/codesigning artifact strings remain consistent in:
    - `contrib/guix/libexec/build.sh`
    - `contrib/guix/libexec/codesign.sh`
    - `contrib/macdeploy/detached-sig-create.sh`
    - `doc/release-process.md`

### Gate B (required before merging PR-1 and before final PR-8)
- Real Guix macOS-host build smoke (Linux builder):
  - `env SDK_PATH=<valid-sdk-parent> HOSTS="x86_64-apple-darwin arm64-apple-darwin" JOBS=8 ADDITIONAL_GUIX_COMMON_FLAGS="--max-jobs=8" ./contrib/guix/guix-build`
- Validate expected darwin outputs exist for both hosts:
  - `*-unsigned.zip`
  - `*-codesigning.tar.gz`
- For PR-8 finalization, also run deterministic reassembly smoke with detached signatures available:
  - `./contrib/guix/guix-codesign`

## Current State Snapshot (as of 2026-02-11)

### Already correct
- Runtime default config filename is already `tidecoin.conf` in `src/common/args.cpp`.
- Default datadir is already Tidecoin-branded on all supported OSes in `src/common/args.cpp`:
  - Linux: `~/.tidecoin`
  - macOS: `~/Library/Application Support/Tidecoin`
  - Windows: `%LOCALAPPDATA%\\Tidecoin` (with old roaming migration path support)
- Built daemon/CLI output names are already Tidecoin-branded via `OUTPUT_NAME` in CMake.
- Example config artifact and generator have been migrated to `tidecoin.conf`.
- Packaging references for example config were migrated (`contrib/guix/libexec/build.sh`, `share/setup.nsi.in`).
- Completion entrypoints and manpages were migrated to Tidecoin binary names.
- Init/system service templates in `contrib/init/` were migrated to Tidecoin naming/paths.
- macOS bundle metadata was aligned with Tidecoin naming (`Tidecoin-Qt`).

### Still inconsistent
- Some upstream wording remains in low-impact comments/test descriptions that do not affect behavior.
- Final Gate B Guix macOS smoke/reassembly validation remains pending before declaring full completion.

## Out Of Scope
- Historical release notes (`doc/release-notes/**`) and upstream attribution text are not migration targets.
- Third-party URLs, quoted upstream project names, and protocol history references are not migration targets.

## PR Plan (Concrete, Reviewable Slices)

## PR-1: Config Artifact Canonicalization (`bitcoin.conf` -> `tidecoin.conf`)

### Scope
- Rename and regenerate example config artifact:
  - `share/examples/bitcoin.conf` -> `share/examples/tidecoin.conf`
- Update generator tooling:
  - `contrib/devtools/gen-bitcoin-conf.sh` -> `contrib/devtools/gen-tidecoin-conf.sh`
  - update script internals (`BITCOIND` path default, output filename, header text)
  - update references in `contrib/devtools/README.md`
- Update packaging inputs to ship `tidecoin.conf`:
  - `contrib/guix/libexec/build.sh`
  - `share/setup.nsi.in`

### Verification
- `rg -n "share/examples/bitcoin\\.conf|Generating example bitcoin\\.conf|bitcoin\\.conf configuration file" contrib/devtools share/examples contrib/guix share/setup.nsi.in` returns zero active hits.
- `contrib/devtools/gen-tidecoin-conf.sh` generates `share/examples/tidecoin.conf`.
- Built release payload contains `tidecoin.conf` and not `bitcoin.conf`.

### Checklist
- [x] Rename example config file in `share/examples/`
- [x] Rename generator script and update internal defaults/messages
- [x] Update Guix packaging copy path
- [x] Update NSIS installer add/remove paths
- [x] Update devtools README references
- [x] Regenerate and commit `share/examples/tidecoin.conf`

## PR-2: Runtime/User-Facing Config Naming Consistency

### Scope
- Remove active user-facing mentions of `bitcoin.conf` in runtime/help text/comments where it affects operator UX:
  - `src/init.cpp`
  - `src/common/init.cpp`
  - `src/qt/bitcoin.cpp`
  - `src/qt/intro.cpp`
  - other runtime-facing strings in `src/**`
- Keep behavior unchanged (already points to `tidecoin.conf`).

### Verification
- `./build/bin/tidecoind -help | rg "default: tidecoin\\.conf"` passes.
- `./build/bin/tidecoin-cli -help | rg "default: tidecoin\\.conf"` passes.
- `rg -n "bitcoin\\.conf" src | rg -v "release-notes|historical|upstream"` returns only intentionally allowed comments or zero.

### Checklist
- [x] Audit and patch runtime/help strings in `src/`
- [x] Confirm no behavior change in args parsing
- [x] Re-run targeted args/config tests (`feature_config_args.py`, `feature_includeconf.py`)

## PR-3: Active Documentation Migration (Operator Docs)

### Scope
- Update non-historical docs to Tidecoin names and paths:
  - `doc/tidecoin-conf.md` (renamed from `doc/bitcoin-conf.md`)
  - `doc/files.md`
  - `doc/init.md`
  - `doc/build-osx.md`
  - `doc/release-process.md`
  - `doc/managing-wallets.md`
  - `doc/README.md` links and labels
- Ensure all datadir examples are Tidecoin paths on Linux/macOS/Windows.

### Verification
- `rg -n "bitcoin\\.conf|/Bitcoin/|\\.bitcoin|bitcoind\\b|bitcoin-cli\\b|bitcoin-qt\\b" doc` returns only historical/release-note contexts.
- Docs build/lint (if configured) passes.

### Checklist
- [x] Migrate operator-facing docs to Tidecoin naming
- [x] Preserve historical sections untouched
- [x] Update intra-doc links after filename changes
- [x] Recheck command examples for `tidecoind`/`tidecoin-cli`

## PR-4: Manpages + Completion Assets Rename

### Scope
- Update manpage generation inputs and outputs:
  - `contrib/devtools/gen-manpages.py`
  - regenerate `doc/man/*` for Tidecoin binaries
- Rename/update shell completions:
  - `contrib/completions/bash/*`
  - `contrib/completions/fish/*`
  - commands should target `tidecoind`, `tidecoin-cli`, `tidecoin-qt`

### Verification
- `doc/man/tidecoind.1`, `doc/man/tidecoin-cli.1`, `doc/man/tidecoin-qt.1` exist and mention Tidecoin defaults.
- completion scripts complete Tidecoin command names.
- no active references to old command names in completion entry points.

### Checklist
- [x] Update manpage generator binary list
- [x] Regenerate and commit Tidecoin manpages
- [x] Rename/patch completion scripts for Tidecoin command names
- [x] Remove old command registrations

## PR-5: Init/System Service Templates Migration

### Scope
- Rename and rewrite `contrib/init/*` templates from Bitcoin naming/paths to Tidecoin:
  - service names (`bitcoind` -> `tidecoind`)
  - config paths (`/etc/bitcoin/bitcoin.conf` -> `/etc/tidecoin/tidecoin.conf`)
  - state/runtime dirs (`/var/lib/bitcoind` -> `/var/lib/tidecoind`)
  - plist identifiers (`org.bitcoin.bitcoind` -> `org.tidecoin.tidecoind`)
- Update `contrib/init/README.md`.

### Verification
- `rg -n "/etc/bitcoin|/var/lib/bitcoind|org\\.bitcoin\\.bitcoind|\\bbitcoind\\b" contrib/init` returns zero active hits.
- Service templates are internally consistent with Tidecoin binary names and paths.

### Checklist
- [x] Rename init file set to Tidecoin naming
- [x] Update service/unit internals and defaults
- [x] Update init README
- [x] Confirm no stale paths/identifiers remain

## PR-6: Contrib Tooling and Script Command Migration

### Scope
- Update active contrib tools/scripts that invoke Bitcoin command names or paths:
  - `contrib/tracing/**`
  - `contrib/linearize/**`
  - `contrib/message-capture/**`
  - `contrib/asmap/**`
  - `contrib/utxo-tools/**`
  - `contrib/qos/**`
  - other non-historical contrib docs/scripts

### Verification
- `rg -n "\\bbitcoind\\b|\\bbitcoin-cli\\b|\\bbitcoin-qt\\b|\\.bitcoin" contrib` returns only intentionally historical text.
- Spot-check script invocation examples execute with Tidecoin binary names.

### Checklist
- [x] Migrate command examples to Tidecoin binaries
- [x] Migrate default datadir examples to Tidecoin paths
- [x] Patch hardcoded tracing probes (`./build/bin/bitcoind` -> `./build/bin/tidecoind`)
- [x] Re-run script help/examples for syntax sanity

## PR-7: Functional/Test Framework Naming Cleanup (Internal API Hygiene)

### Scope
- Rename internal test framework identifiers from `bitcoin*` to `tidecoin*` where this is pure naming cleanup:
  - `test/functional/test_framework/**`
  - affected tests consuming those attributes/helpers
- Keep behavior identical.

### Verification
- Full functional suite passes with renamed internals.
- No stale internal attribute names left for config file path and binary path properties.

### Checklist
- [x] Rename test framework properties/helpers (`bitcoinconf`, `bitcoind_path`, etc.)
- [x] Update all user-facing references in core test framework and test docs
- [x] Run full functional tests

## PR-8: Final Guardrail + Policy Check

### Scope
- Add a lightweight lint/check script to prevent reintroduction of Bitcoin naming in active surfaces.
- Define allowlist for historical locations (`doc/release-notes/**`, upstream attribution, etc.).
- Add check to CI or pre-merge workflow.

### Verification
- Lint fails on newly introduced forbidden terms in active paths.
- Lint passes on current tree after cleanup.

### Checklist
- [x] Implement naming guard script
- [x] Define allowlist patterns
- [x] Wire into CI
- [x] Document policy in contributor docs

## Execution Order
1. PR-1 config artifact canonicalization
2. PR-2 runtime/user-facing naming consistency
3. PR-3 active docs migration
4. PR-4 manpages/completions
5. PR-5 init/service templates
6. PR-6 contrib tooling/scripts
7. PR-7 functional framework naming hygiene
8. PR-8 guardrail/lint policy

## Global Acceptance Criteria (Project Completion)
- `tidecoin.conf` is the only active config filename shipped, generated, and documented.
- `tidecoind`/`tidecoin-*` are the only active command names in non-historical docs/scripts.
- Default datadir docs/examples are Tidecoin-named on Linux/macOS/Windows.
- Guix, NSIS, and release flow artifacts contain Tidecoin names only.
- Full unit + functional + packaging smoke checks pass.

## Suggested Verification Command Set (Final Sweep)

```bash
rg -n "bitcoin\\.conf|\\bbitcoind\\b|\\bbitcoin-cli\\b|\\bbitcoin-qt\\b|\\.bitcoin|/Bitcoin/" \
  src contrib doc share test \
  -g '!doc/release-notes/**'
```

```bash
cmake -B build -DBUILD_TESTS=ON
cmake --build build -j8
ctest --test-dir build -j8
python3 test/functional/test_runner.py --jobs=8
```
