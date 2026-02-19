# PQClean Vendor Governance Plan

Goal: establish auditable, repeatable, CI-enforced governance for vendored PQClean code in `src/pq/`, including components with Tidecoin local patches.

## Why this is needed
- `src/pq/` contains vendored PQ implementations plus Tidecoin-specific integrations.
- Some vendored components are locally modified (deterministic keygen/derand APIs, RNG wiring, include path adaptations).
- Without a pinned manifest + checks, upstream divergence and undocumented local changes are hard to detect.

## Current state summary
- Vendored component directories in build scope:
  - `src/pq/falcon-512/`
  - `src/pq/falcon-1024/`
  - `src/pq/ml-dsa-44/`
  - `src/pq/ml-dsa-65/`
  - `src/pq/ml-dsa-87/`
  - `src/pq/ml-kem-512/`
- Tidecoin-native wrappers/adapters exist outside vendor dirs (`src/pq/falcon512.c`, `src/pq/falcon1024.c`, `src/pq/mldsa*.c`, `src/pq/kem.cpp`, `src/pq/pq_api.h`, `src/pq/pqhd_*`).
- Vendor dirs are mostly pristine, with a known subset locally patched.

## Non-goals
- Do not rewrite or remove PQClean code as part of this plan.
- Do not force pure-subtree workflow for `src/pq/`.
- Do not block Tidecoin-specific patches; instead, formalize and track them.

## Deliverables
1. `src/pq/VERSIONS.toml` manifest with pinned provenance and patch metadata.
2. `src/pq/patches/` directory (or equivalent structured patch references) for local deltas in vendored components.
3. `contrib/devtools/check_pq_vendor.py` to validate local source vs pinned upstream + approved patchset.
4. `test/lint/lint-pq-vendor.py` lint gate for schema/consistency checks.
5. `doc/developer-notes.md` update procedure section for PQ vendor updates.
6. CI integration via lint test runner.

## Manifest design (`src/pq/VERSIONS.toml`)
Required top-level fields:
- `schema_version`
- `upstream.pqclean_repo`

Required per-component fields:
- `name` (e.g., `falcon-512`)
- `status` (`pristine` or `patched`)
- `local_path` (repo path)
- `upstream_path` (PQClean path at source)
- `upstream_commit` (40-hex)
- `import_commit` (Tidecoin commit that imported/synced component)
- `local_patch_set` (empty for pristine, non-empty for patched)
- `notes` (short rationale)

Patch-set entry fields:
- `id` (stable identifier)
- `files` (explicit list)
- `reason` (one sentence)
- `owner` (team/person)
- `consensus_impact` (`none|indirect|direct`)

## Verification model

### 1) Lint-level checks (`lint-pq-vendor.py`)
- Ensure `src/pq/VERSIONS.toml` exists.
- Validate schema and required keys.
- Validate commit hash formats.
- Ensure every component referenced exists on disk.
- Ensure `patched` components declare non-empty `local_patch_set`.
- Ensure `pristine` components do not declare local patches.

### 2) Deep vendor checks (`check_pq_vendor.py`)
- Fetch/clone PQClean at each component's `upstream_commit`.
- Compare local tree vs upstream tree per component.
- Rules:
  - `pristine`: exact match required (except allowed path normalization where explicitly defined).
  - `patched`: diff must be fully explained by declared patch set.
- Output:
  - pass/fail summary
  - unexplained file diffs
  - missing/extra patch declarations

## Decision matrix (pre-implementation)
These decisions should be explicitly confirmed before full rollout. Defaults below are recommended for Tidecoin.

| Decision | Recommended default | Must decide by | Rationale |
|---|---|---|---|
| Upstream pin strategy | One `upstream_commit` per component (not global) | Phase 0 | Allows controlled upgrades when components diverge in cadence. |
| Upstream path mapping | Store exact `upstream_path` per component in manifest | Phase 0 | PQClean layout/naming can vary over time. |
| Import baseline | Record current sync/import commit as `import_commit` per component | Phase 0 | Creates audit anchor for local history. |
| Shared code ownership (`fips202.c`) | Track as separate manifest component (`shared-fips202`) | Phase 0 | Avoids ambiguous ownership across signatures/KEM. |
| RNG adaptation (`randombytes`) | Treat as Tidecoin-native adapter, not vendor component | Phase 0 | Local integration layer should not be forced into upstream diff checks. |
| `pristine` definition | Byte-for-byte match only | Phase 1 | Keeps rule simple and objective. |
| Include-path rewrites in vendor dirs | Classify as `patched` (no special pristine exceptions) | Phase 1 | Prevents hidden drift through implicit allowlists. |
| Local extension placement | Keep existing local extensions temporarily; track via patch metadata | Phase 1 | Minimizes migration risk; allows later extraction to wrappers. |
| Patch representation | Both: manifest metadata + patch files in `src/pq/patches/` | Phase 1 | Human-readable intent plus reproducible diffs. |
| Patch approval owner | Security/code-owner approval required for `patched` component changes | Phase 1 | Crypto supply-chain changes need explicit accountability. |
| CI scope for deep checks | Run deep check on PRs touching `src/pq/**`; nightly scheduled full scan | Phase 2 | Balances coverage with CI runtime. |
| Network dependency in CI | Use cached PQClean mirror/artifact in CI, not ad-hoc internet fetch | Phase 2 | Improves determinism and build reliability. |
| Emergency override policy | Temporary bypass allowed only with explicit incident tag + follow-up deadline | Phase 2 | Supports urgent fixes without weakening baseline governance. |
| Release gate policy | Deep vendor check required for release candidates/tags | Phase 3 | Prevents shipping undocumented crypto drift. |
| Backfill policy | No full historical backfill required; enforce from governance adoption point onward | Phase 3 | Keeps rollout practical while improving forward controls. |

Decision log location:
- Add an appendix or changelog section in this document that records final values, approver, and date for each row above.

## Rollout phases

### Phase 0: Baseline inventory
- Create first `VERSIONS.toml` with all six components.
- Classify each as `pristine` or `patched`.
- Document currently known local patch categories.

### Phase 1: Lightweight enforcement
- Add `lint-pq-vendor.py` and wire into `test/lint/test_runner/src/main.rs`.
- CI fails on missing/invalid manifest metadata.

### Phase 2: Full divergence checks
- Add `contrib/devtools/check_pq_vendor.py`.
- Run in CI for PRs touching `src/pq/**` and for scheduled security jobs.

### Phase 3: Operational hardening
- Add release checklist item: verify PQ vendor status before tagging.
- Add periodic upstream drift report cadence (e.g., monthly or per release branch cut).

## Contributor workflow
When changing vendored PQ files:
1. Update `src/pq/VERSIONS.toml`.
2. If new/changed local patch, update patch metadata under `src/pq/patches/` (or patch references).
3. Run:
   - `python3 test/lint/lint-pq-vendor.py`
   - `python3 contrib/devtools/check_pq_vendor.py` (if component diff changed)
4. Include a PR note:
   - affected component(s)
   - upstream commit baseline
   - patch reason and risk assessment

When bumping upstream PQClean:
1. Update `upstream_commit` and resync source.
2. Rebase/reconcile local patch set.
3. Re-run lint + deep checks.
4. Record migration notes in PR.

## CI policy
- Hard fail if:
  - vendored PQ files changed without manifest update
  - unexplained divergence from upstream
  - malformed or incomplete provenance metadata
- Soft signal (optional): report available upstream updates without failing.

## Acceptance criteria
- All six components appear in `VERSIONS.toml` with pinned upstream commit.
- Vendor components are explicitly classified (`pristine|patched`).
- Lint gate is active in test runner.
- Deep checker can reproduce and validate local state from manifest.
- Developer docs describe end-to-end update process.

## Risks and mitigations
- Risk: upstream path/layout differences across PQClean revisions.
  - Mitigation: keep `upstream_path` explicit per component.
- Risk: local patch list drifts from actual diffs.
  - Mitigation: CI deep check against upstream commit.
- Risk: process overhead for routine changes.
  - Mitigation: separate fast lint checks from deeper checks; run deep checks conditionally.

## Suggested first implementation PR scope
- Add `src/pq/VERSIONS.toml` (initial inventory).
- Add `test/lint/lint-pq-vendor.py`.
- Wire lint in `test/lint/test_runner/src/main.rs`.
- Add docs section in `doc/developer-notes.md`.

Follow-up PR:
- Add `contrib/devtools/check_pq_vendor.py` and CI job integration.
