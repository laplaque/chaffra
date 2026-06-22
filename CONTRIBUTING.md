# Contributing to chaffra

## Tests

Every PR that introduces or changes functional code must satisfy these gates before merge. Scaffold-only PRs (empty stubs, config, CI, docs) are exempt from coverage gates but must still pass CI and review.

### Coverage

Applies when the PR contains functional (non-stub) Rust code. CI enforces the
four thresholds below via `scripts/coverage_check.py`, run by the `coverage`
job in `.github/workflows/ci.yml`. The versioned source of truth for both the
thresholds and the trust-boundary path list is
[`.github/coverage-policy.toml`](.github/coverage-policy.toml).

- **85%** overall line coverage (enforced on pull requests and on pushes to `main`; feature-branch pushes skip the coverage job).
- **95%** aggregate changed-line coverage across all changed Rust files on a PR.
- **90%** changed-line coverage in every individual changed Rust file on a PR.
- **100%** changed-line coverage for trust-boundary paths (configuration
  parsing, telemetry audience/privacy projection, validation, suppression
  handling, persistence boundaries, and gRPC/proto conversion).

Changed lines are obtained from `git diff --unified=0 <base>...<head>`.
A changed line counts only when it is also represented in the LCOV report
as an executable line. Changed lines that do not appear in LCOV are reported
as **non-instrumented** — they are never silently counted as covered, and a
trust-boundary file with executable changed lines but no LCOV records fails
the trust-boundary gate.

When a covered trust boundary moves or new trust-boundary code lands, update
`.github/coverage-policy.toml` in the same PR. The checker fails the build if
a configured glob matches no current file. Carve-outs must never lower a
threshold; document an owner and removal issue inline if a temporary
exclusion is unavoidable.

#### Multi-target instrumentation

The checker treats the LCOV DA records as the authority on which changed lines
are executable, so code the coverage build does not compile is not enforced by
the changed-line gates. Two mechanisms close that gap:

- **Feature gates are enumerated by name in CI.** The coverage build passes
  `--features` listing every non-default feature in the workspace (today only
  `chaffra-telemetry/cloudwatch`) so feature-gated executable code does reach
  the DA records. When a new non-default feature is added, the contributor
  MUST add it to both the local command and the CI command in the same PR; a
  test (`test_ci_coverage_command_enumerates_every_non_default_feature`)
  enforces it. We do not pass `--all-features` because the workspace test
  suite is not `--all-features`-clean (see
  [chaffra#51](https://github.com/laplaque/chaffra/issues/51)).
- **Target `cfg` gates are covered by a per-target matrix.** Code reachable
  only under a `#[cfg(target_os = "...")]` / `#[cfg(target_arch = "...")]`
  attribute cannot be instrumented by any single build. The
  `coverage-instrument` matrix in `.github/workflows/ci.yml` therefore runs
  `cargo llvm-cov` once per target — linux+x86_64 (`ubuntu-latest`),
  macos+aarch64 (`macos-latest`), windows+x86_64 (`windows-latest`) — and the
  `coverage` job merges the per-target LCOV before the gate (a line is
  instrumented if any target compiled it and covered if any target exercised
  it). Target-`cfg`-gated trust-boundary code is thus enforced on the leg
  whose target matches. Each matrix leg declares the target tokens it builds
  in a `covers:` field; the test
  `test_trust_boundary_target_cfg_is_covered_by_matrix` fails the build if a
  trust-boundary file gates code on a target NO leg builds, forcing the matrix
  to be widened (or the `cfg` split) in the same PR. This resolves
  [chaffra#49](https://github.com/laplaque/chaffra/issues/49); there is no
  longer an inactive-`cfg` carve-out in the policy.

#### Running coverage locally

A local run uses a single LCOV from your own platform; CI runs the full
per-target matrix and merges the results. The checker accepts one or more
`--lcov` files and merges them, so you can reproduce the matrix locally by
generating an LCOV per target you can build and passing them all.

```bash
# 1. Generate the same LCOV the CI matrix uses (your host target):
cargo llvm-cov --workspace --features chaffra-telemetry/cloudwatch --lcov --output-path coverage/lcov.info

# 2. Reproduce a PR comparison against an explicit base/head SHA pair. Pass
#    multiple --lcov files (one per target) to mirror the CI merge:
python3 scripts/coverage_check.py \
    --lcov coverage/lcov.info \
    --policy .github/coverage-policy.toml \
    --base-sha "$(git merge-base origin/main HEAD)" \
    --head-sha "$(git rev-parse HEAD)" \
    --json-out coverage/result.json \
    --markdown-out coverage/result.md \
    --mode pr

# 3. Run the checker test suite:
python3 -m unittest discover -s scripts/tests

# 4. Enforce the checker's own coverage (the Rust `coverage` job is
#    Rust-only and does not measure this Python tool):
python3 -m pip install --no-deps "coverage==7.14.2"
python3 -m coverage run --rcfile=scripts/tests/.coveragerc \
    -m unittest discover -s scripts/tests
python3 -m coverage report --rcfile=scripts/tests/.coveragerc   # fails under 100%
```

The `coverage` job uploads each target's `lcov.info`, plus `result.json` and
`result.md`, as the `coverage-<head-sha>` artifact on every run, including
failed runs. The Markdown summary is also appended to the workflow's
`GITHUB_STEP_SUMMARY`.

**The checker is gated on its own coverage at 100%.**
`scripts/coverage_check.py` is security/validation/trust-boundary code in
its entirety, so the policy's **100%** trust-boundary rule applies to it —
not the 95% delta rule for ordinary new code. The Rust `coverage` job does
not measure Python, so the `coverage-checker-tests` job runs `coverage.py`
(line + branch) over the checker and fails below 100%. The configuration
and threshold live in
[`scripts/tests/.coveragerc`](scripts/tests/.coveragerc).

### Style

- **Table-driven.** When a function has more than one interesting input, express the cases as a data table — `#[test_case]`, a local `Vec` of `(input, expected)` pairs, or a macro-generated suite. One assertion loop, N rows.
- **Fixture-based for integration tests.** Small self-contained source files under `tests/fixtures/` that represent known-good and known-bad codebases. Never generate fixture content at runtime.
- **Deterministic.** No test may depend on wall-clock time, randomness, network, or filesystem ordering. If a test needs ordering, sort explicitly.

### Prohibited patterns

- `#[ignore]` without a linked issue number in the attribute comment.
- `#[allow(...)]` to suppress a warning the test is supposed to catch.
- Hardcoded magic values inserted solely to make an assertion pass — the expected value must be derivable from the test setup.
- Snapshot files committed without review — snapshot updates require the same scrutiny as code changes.

### Running

```bash
cargo test                     # all tests
cargo test -p chaffra-core     # single crate
cargo clippy -- -D warnings    # lint (must pass before merge)
cargo fmt -- --check           # format check
```

## Code

- No `unsafe` unless justified with a `// SAFETY:` comment explaining the invariant.
- `thiserror` for library crate errors, `anyhow` in the CLI crate only.
- Public types that cross crate boundaries derive `Serialize` + `Deserialize` where appropriate.
- Prefer `&str` / `&[u8]` over owned types in function signatures unless ownership transfer is required.
- Dependencies: security scan + license check before adding anything new. Prefer `std` over third-party when the functionality is comparable. Document the scan result in the PR body when adding new direct dependencies.

## Commits

- Conventional Commits: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `ci:`.
- One logical change per commit.
- No AI attribution in commit messages or PR descriptions.

## Branches

- Never commit directly to `main`.
- Feature branches: `feat/<slug>`, fixes: `fix/<slug>`, CI / build infrastructure: `ci/<slug>`.
- PRs are squash-merged.
