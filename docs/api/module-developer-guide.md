# Module Developer Guide

How to write, test, package, and distribute a chaffra analysis module.

## Overview

Every chaffra analysis capability is a module implementing the `AnalysisModule` trait (for built-in Rust modules) or the `AnalysisModule` gRPC service (for external modules in any language).

## Writing a Built-in Module (Rust)

### 1. Create the crate

```bash
cargo new crates/chaffra-mymodule --lib
```

Add to `Cargo.toml` workspace members and add dependencies:

```toml
[dependencies]
chaffra-core = { workspace = true }
chaffra-parse = { workspace = true }
```

### 2. Implement the trait

```rust
use chaffra_core::diagnostic::*;
use chaffra_core::error::Result;
use chaffra_core::module::AnalysisModule;
use std::collections::HashMap;

pub struct MyModule;

impl AnalysisModule for MyModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "my-module".to_owned(),
            name: "My Analysis Module".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec!["go".to_owned()],
            capabilities: vec!["analyze".to_owned()],
            rules: vec![Rule {
                id: "my-rule".to_owned(),
                name: "My Rule".to_owned(),
                description: "Detects something".to_owned(),
                default_severity: Severity::Warning,
                category: "my-module".to_owned(),
            }],
        }
    }

    fn analyze(
        &self,
        files: &[FileInfo],
        config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        // Your analysis logic here.
        let findings = vec![];
        Ok(AnalysisResult {
            findings,
            metrics: ModuleMetrics {
                files_analyzed: files.len() as u64,
                duration_ms: 0,
                counters: HashMap::new(),
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        // Return explanation for each rule.
        todo!()
    }

    fn fix(
        &self,
        _findings: &[Finding],
        _dry_run: bool,
    ) -> Result<Vec<FixResult>> {
        Ok(vec![])
    }
}
```

### 3. Register the module

In the CLI wiring (`crates/chaffra-cli/src/main.rs`), register your module:

```rust
host.register(Box::new(MyModule::new())).unwrap();
```

### 4. Test

Write unit tests in your crate and integration tests using fixture files:

```rust
#[test]
fn test_my_module() {
    let module = MyModule;
    let files = vec![FileInfo {
        path: "test.go".to_owned(),
        content: b"package main".to_vec(),
    }];
    let result = module.analyze(&files, &HashMap::new()).unwrap();
    assert!(result.findings.is_empty());
}
```

## Writing an External Module (gRPC)

External modules implement the `AnalysisModule` gRPC service defined in `proto/chaffra/module/v1/module.proto`. They can be written in any language with gRPC support.

### Python Example

```python
import grpc
from chaffra.module.v1 import module_pb2, module_pb2_grpc

class MyPlugin(module_pb2_grpc.AnalysisModuleServicer):
    def Describe(self, request, context):
        return module_pb2.ModuleInfo(
            id="my-plugin",
            name="My Plugin",
            version="0.1.0",
            languages=["python"],
        )

    def Analyze(self, request, context):
        # Analysis logic
        return module_pb2.AnalysisResponse()
```

## Testing

- Use table-driven tests with fixture files under `tests/fixtures/`.
- Test each rule independently.
- Verify suppression comments are respected.
- Test explain and fix RPCs.

## Packaging

Built-in modules are compiled into the chaffra binary. External modules are distributed as container images or standalone binaries.
