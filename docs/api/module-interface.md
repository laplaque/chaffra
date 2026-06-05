# AnalysisModule gRPC Interface

The `AnalysisModule` service is defined in `proto/chaffra/module/v1/module.proto` and is the universal interface for all chaffra analysis modules.

## Transport Architecture

All module dispatch -- both built-in and external -- uses gRPC as the transport layer.

### Built-in modules (in-process gRPC)

Built-in modules implement the Rust `AnalysisModule` trait. Each trait impl is wrapped in a `GrpcModuleService` (a tonic gRPC server) and connected to a tonic `AnalysisModuleClient` via the server's `tower::Service` implementation directly -- no TCP socket, no network. All calls go through full proto serialization (prost encode/decode) with sub-microsecond transport overhead.

Key components:
- `GrpcModuleService` -- implements the tonic server trait by delegating to `Arc<dyn AnalysisModule>`
- `GrpcModuleHandle` -- wraps the tonic client connected to the in-process server
- `GrpcModuleHost` -- the central registry; stores handles by module ID and dispatches analyze/explain/fix calls through gRPC

### External modules (networked gRPC)

Framework-specific modules (gin, FastAPI, Django, etc.) run as separate containers and communicate over real gRPC transport on configured ports. They implement the same proto service definition.

### Why gRPC everywhere?

Using a single dispatch mechanism simplifies the architecture: there is one code path for analyze/explain/fix regardless of whether the module is in-process or remote. The in-process path pays a small serialization cost (validated to be under 10ms/call in benchmarks) but gains full proto contract validation on every call.

## Service Definition

```protobuf
service AnalysisModule {
  rpc Describe(DescribeRequest) returns (ModuleInfo);
  rpc Analyze(AnalysisRequest) returns (AnalysisResponse);
  rpc Explain(ExplainRequest) returns (ExplainResponse);
  rpc Fix(FixRequest) returns (FixResponse);
}
```

## RPCs

### Describe

Returns metadata about the module: its ID, name, version, supported languages, capabilities, and the rules it provides.

**Request:** `DescribeRequest` (empty)

**Response:** `ModuleInfo`

| Field | Type | Description |
|-------|------|-------------|
| id | string | Unique module identifier (e.g. "dead-code") |
| name | string | Human-readable name |
| version | string | SemVer version |
| languages | repeated string | Supported languages (e.g. "go", "python") |
| capabilities | repeated string | What the module can do ("analyze", "explain", "fix") |
| rules | repeated RuleInfo | Rules provided by this module |

### Analyze

Run analysis on a set of files and return findings.

**Request:** `AnalysisRequest`

| Field | Type | Description |
|-------|------|-------------|
| files | repeated FileInfo | Files to analyze (path, content, optional AST nodes) |
| config | map<string,string> | Per-module configuration key-value pairs |
| enabled_rules | repeated string | Subset of rules to enable (empty = all) |
| language | string | Target language hint |

**Response:** `AnalysisResponse`

| Field | Type | Description |
|-------|------|-------------|
| findings | repeated Finding | Diagnostic findings |
| metrics | ModuleMetrics | Analysis metrics (files analyzed, duration, counters) |

### Explain

Return a detailed explanation of a rule.

**Request:** `ExplainRequest` with `rule_id`

**Response:** `ExplainResponse` with description, rationale, severity, suppression syntax, and examples.

### Fix

Apply or preview fixes for findings.

**Request:** `FixRequest` with findings and `dry_run` flag.

**Response:** `FixResponse` with per-finding results indicating whether the fix was applied and what edits were made.

## Key Types

### Finding

A diagnostic finding produced by analysis.

| Field | Type | Description |
|-------|------|-------------|
| rule_id | string | Which rule produced this finding |
| message | string | Human-readable message |
| severity | string | "info", "warning", or "error" |
| location | Location | Source location |
| confidence | float | 0.0 to 1.0 confidence score |
| actions | repeated Action | Available auto-fix actions |
| metadata | map<string,string> | Additional key-value metadata |

### Location

| Field | Type | Description |
|-------|------|-------------|
| file | string | File path relative to analysis root |
| start_line | uint32 | 1-based start line |
| end_line | uint32 | 1-based end line |
| start_column | uint32 | 0-based start column |
| end_column | uint32 | 0-based end column |

### TextEdit

| Field | Type | Description |
|-------|------|-------------|
| file | string | File to edit |
| start_line | uint32 | Start line of the edit range |
| end_line | uint32 | End line of the edit range |
| new_text | string | Replacement text (empty = delete) |
