# chaffra

Codebase intelligence for Go, Python, and beyond. Rust workspace, tree-sitter parsing, gRPC plugin architecture.

## Crate map

| Crate | Purpose |
|-------|---------|
| chaffra-core | Diagnostic types, config, severity model |
| chaffra-parse | tree-sitter integration, per-language AST walkers |
| chaffra-deadcode | Dead code detection engine |
| chaffra-complexity | Cyclomatic + cognitive complexity metrics |
| chaffra-health | Composite 0-100 health scoring |
| chaffra-duplication | Clone detection (suffix tree, 4 modes) |
| chaffra-arch | Architecture boundary validation + presets |
| chaffra-hotspot | Churn x complexity ranking (git via gix) |
| chaffra-audit | PR risk assessment, baselines, verdicts |
| chaffra-output | Formatters (JSON, SARIF, markdown, PR comments) |
| chaffra-mcp | MCP server |
| chaffra-plugin | gRPC plugin host + protocol |
| chaffra-cli | CLI entry point (clap) |

## Commands

```
cargo check                    # type check
cargo test                     # run all tests
cargo clippy -- -D warnings    # lint
cargo fmt -- --check           # format check
cargo run -p chaffra-cli -- health .   # run CLI
```

## Conventions

- Rust 2024 edition, stable toolchain
- All public types derive Serialize/Deserialize where appropriate
- Error handling: thiserror for library crates, anyhow in CLI
- No unsafe unless justified with a safety comment
