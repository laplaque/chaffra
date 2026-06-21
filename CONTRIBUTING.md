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

#### Documented residual

The checker treats the LCOV DA records as the authority on which changed lines
are executable, so code the coverage build does not compile is not enforced by
the changed-line gates. To minimise this gap:

- **Feature gates are enumerated by name in CI.** The `coverage` job passes
  `--features` listing every non-default feature in the workspace (today only
  `chaffra-telemetry/cloudwatch`) so feature-gated executable code does reach
  the DA records. When a new non-default feature is added, the contributor
  MUST add it to both the local command and the CI command in the same PR; the
  reviewer verifies it. We do not pass `--all-features` because the workspace
  test suite is not `--all-features`-clean (see
  [chaffra#51](https://github.com/laplaque/chaffra/issues/51)).
- **Inactive target `cfg` is the one residual.** Code reachable only under a
  non-active `#[cfg(target_os = "...")]` / `#[cfg(target_arch = "...")]` on
  the coverage runner cannot be instrumented by any single build. No
  trust-boundary file currently contains such a gate; the exception in
  `.github/coverage-policy.toml` is the documented mechanism for the next
  time one is introduced. Tracked in
  [chaffra#49](https://github.com/laplaque/chaffra/issues/49), which proposes
  a multi-target coverage matrix or a tree-sitter-rust classifier.

Reviewers must flag any trust-boundary change whose only added lines are
gated by an inactive target `cfg`, until #49 closes.

#### Running coverage locally

```bash
# 1. Generate the same LCOV file the CI job uses:
cargo llvm-cov --workspace --features chaffra-telemetry/cloudwatch --lcov --output-path coverage/lcov.info

# 2. Reproduce a PR comparison against an explicit base/head SHA pair:
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
```

The CI job uploads `coverage/lcov.info`, `coverage/result.json`, and
`coverage/result.md` as the `coverage-<head-sha>` artifact on every run,
including failed runs. The Markdown summary is also appended to the
workflow's `GITHUB_STEP_SUMMARY`.

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
