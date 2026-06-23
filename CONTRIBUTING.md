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
the changed-line gates. Two exhaustiveness mechanisms close that gap, each
sourced from an authority rather than a hand-maintained list:

- **Features — the full powerset is instrumented.** Each coverage leg drives
  `cargo llvm-cov` through `cargo hack --feature-powerset`, which runs the
  test suite once per feature combination of each workspace crate and
  accumulates the per-combo coverage; `cargo llvm-cov report` then merges it.
  Both `cfg(feature = "x")` and `cfg(not(feature = "x"))` — and every
  combination once a crate has more than one feature — therefore reach the DA
  records by construction, with nothing to hand-enumerate. A new feature
  needs no workflow edit; the powerset picks it up from `Cargo.toml`.
- **Targets — one leg per supported target, cfg derived from rustc.** Code
  reachable only under a target-`cfg` cannot be instrumented by a build for a
  different target. The `coverage-instrument` matrix in
  `.github/workflows/ci.yml` runs `cargo llvm-cov` once per target the
  workspace compiles on — `x86_64-unknown-linux-gnu` (`ubuntu-latest`) and
  `aarch64-apple-darwin` (`macos-latest`) — and the `coverage` job merges the
  per-target LCOV before the gate (a line is instrumented if any built target
  compiled it, covered if any built target exercised it). Windows is
  intentionally NOT in the matrix: `chaffra-autofix` uses `std::os::unix`
  unconditionally, so a `windows-latest` leg would fail to compile and produce
  no LCOV (verified empirically in chaffra#52). The H4 guard
  (`test_trust_boundary_target_cfg_is_covered_by_matrix`) structurally parses
  every `#[cfg(...)]` predicate in every trust-boundary file (after expanding
  the policy's fnmatch globs against the immutable head tree) and asks whether
  it is satisfiable on some matrix leg under some feature combination — using
  each leg's authoritative cfg from `rustc --print cfg --target <triple>` and
  treating the crate's defined features as free. It fails closed on any
  conditional form it cannot parse, so a trust-boundary addition gated on
  `target_os = "windows"` (or any cfg no leg can reach) fails the build until
  the matrix is widened or the cfg removed. This resolves
  [chaffra#49](https://github.com/laplaque/chaffra/issues/49); there is no
  longer an inactive-`cfg` carve-out in the policy.

#### Running coverage locally

A local run instruments your host target only; CI runs the full per-target
matrix (linux + macos) and merges the results. The checker accepts multiple
`--lcov` files and merges them, so you can add LCOVs from other targets you
build locally. `cargo hack` (`cargo install cargo-hack`) drives the feature
powerset exactly as CI does.

```bash
# 1. Instrument the full feature powerset for your host target (the same
#    recipe CI runs per leg):
cargo llvm-cov clean --workspace
cargo hack --feature-powerset --workspace llvm-cov --no-report
cargo llvm-cov report --lcov --output-path coverage/lcov.info

# 2. Reproduce a PR comparison against an explicit base/head SHA pair. Pass
#    every LCOV you generated (add other targets' LCOVs here to mirror the
#    CI merge):
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
