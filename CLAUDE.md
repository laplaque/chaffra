# chaffra

Codebase intelligence for Go, Python, and beyond. Rust workspace, tree-sitter parsing, gRPC module architecture.

## Setup (cloud / fresh environment)

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"

# protobuf compiler (for gRPC proto generation)
apt-get update && apt-get install -y protobuf-compiler || brew install protobuf

# verify
rustc --version && cargo --version && protoc --version
```

## Architecture

Core + modules. The core handles orchestration, telemetry, config, output formatting, MCP/LSP, and watch mode. ALL analysis is done by modules implementing the universal gRPC `AnalysisModule` service.

### Core (always in the binary)

| Crate | Purpose |
|-------|---------|
| chaffra-core | Diagnostic types, config, telemetry, module host, API docs framework |
| chaffra-output | Formatters (JSON, SARIF, CodeClimate, markdown, PR comments, badge) |
| chaffra-cli | CLI entry point, command routing, orchestration |
| chaffra-mcp | MCP server — dispatches to modules |
| chaffra-types | Published crate — typed output contract for downstream consumers |

### Module interface

Every analysis capability implements the `AnalysisModule` gRPC service defined in `proto/chaffra/module/v1/module.proto`. Built-in modules run in-process (same trait, zero network overhead). External modules communicate via real gRPC transport.

### Built-in modules

| Module | Purpose |
|--------|---------|
| parse | tree-sitter parsing, symbol resolution, import graph (shared service) |
| dead-code | Unused functions, types, imports, files |
| complexity | Cyclomatic + cognitive complexity, health scoring |
| duplication | Token-based clone detection (4 modes) |
| architecture | Boundary validation, presets, circular dependency detection |
| audit | PR risk assessment, baselines, verdicts |
| hotspot | Churn x complexity ranking (git via gix) |
| security | SAST (taint analysis), secret scanning, dependency CVEs |
| cicd-security | GitHub Actions, GitLab CI, Dockerfile, systemd config analysis |
| ai-quality | Hallucinated APIs, phantom security, unfinished stubs |
| llm-defense | Prompt injection exposure, unsafe tool use, missing output validation |
| autofix | Automated cleanup orchestration, pre-commit hooks |

### External modules (gRPC containers)

Framework-specific: gin, echo, cobra (Go), FastAPI, Django, Flask (Python), Spring Boot (Java). Written in their framework's language, containerized, community-contributable.

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
- No unsafe unless justified with a `// SAFETY:` comment
- All code conforms to [Rust Design Patterns](https://rust-unofficial.github.io/patterns/)
- Each module generates API documentation at `docs/api/modules/<id>.md`
- No AI attribution in commits or PRs
