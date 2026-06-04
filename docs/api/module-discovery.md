# Module Discovery

How chaffra discovers and loads analysis modules.

## Built-in Modules

Built-in modules are compiled directly into the chaffra binary and registered at startup. They implement the `AnalysisModule` trait and run in-process with zero network overhead.

Registration happens in the CLI entry point:

```rust
fn build_module_host() -> ModuleHost {
    let mut host = ModuleHost::new();
    host.register(Box::new(DeadCodeModule::new())).unwrap();
    host.register(Box::new(ComplexityModule::new())).unwrap();
    host
}
```

### Phase 1 Built-in Modules

| Module ID | Crate | Description |
|-----------|-------|-------------|
| `dead-code` | `chaffra-deadcode` | Unused functions, types, imports, files |
| `complexity` | `chaffra-complexity` | Cyclomatic/cognitive complexity, health scoring |

### Future Built-in Modules

| Module ID | Crate | Phase |
|-----------|-------|-------|
| `duplication` | `chaffra-duplication` | 2 |
| `architecture` | `chaffra-arch` | 3 |
| `hotspot` | `chaffra-hotspot` | 3 |
| `audit` | `chaffra-audit` | 4 |
| `security` | `chaffra-security` | 5 |

## External Modules (Future)

External modules communicate via gRPC using the `AnalysisModule` service. They are discovered through configuration in `.chaffra.toml`:

```toml
[[plugins]]
name = "gin"
command = "chaffra-plugin-gin"  # binary in PATH

[[plugins]]
name = "fastapi"
grpc = "localhost:50051"  # running container
```

### Discovery Process

1. Load `.chaffra.toml` and read the `[[plugins]]` sections.
2. For each plugin with a `command`, spawn the binary as a subprocess and connect via gRPC.
3. For each plugin with a `grpc` address, connect directly to the running service.
4. Call `Describe()` on each connected module to register its capabilities.

## Module Host API

The `ModuleHost` provides the following operations:

- `register(module)` -- Register a module instance.
- `get(id)` -- Retrieve a module by ID.
- `list()` -- List all registered modules with their metadata.
- `analyze(id, files, config)` -- Run analysis on a specific module.
- `explain(rule_id)` -- Explain a rule, routing to the correct module.

## Listing Modules

Use `chaffra modules` to list all registered modules:

```
$ chaffra modules
dead-code v0.1.0 - Dead Code Detection
  Languages: go, python
  Capabilities: analyze, explain, fix
  Rules: unused-function, unused-type, unused-import, unused-file, stale-suppression

complexity v0.1.0 - Complexity & Health Scoring
  Languages: go, python
  Capabilities: analyze, explain, health
  Rules: high-cyclomatic, high-cognitive, low-health-score
```
