# Contributing to chaffra

## Tests

Every PR that introduces or changes functional code must satisfy these gates before merge. Scaffold-only PRs (empty stubs, config, CI, docs) are exempt from coverage gates but must still pass CI and review.

### Coverage

Applies when the PR contains functional (non-stub) Rust code:

- **95%** on new or changed code (delta coverage).
- **85%** overall.
- **100%** on security-sensitive and validation paths (config parsing, suppression handling, trust boundaries).

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
- Feature branches: `feat/<slug>`, fixes: `fix/<slug>`.
- PRs are squash-merged.
