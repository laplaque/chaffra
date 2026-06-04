# Parse Module

**Crate:** `chaffra-parse`

The parse module is a shared service used by analysis modules. It is NOT an `AnalysisModule` itself -- it provides tree-sitter parsing, symbol extraction, import graph construction, and suppression scanning.

## Supported Languages

| Language | Extension | tree-sitter Grammar |
|----------|-----------|-------------------|
| Go | `.go` | `tree-sitter-go` |
| Python | `.py` | `tree-sitter-python` |

## Components

### Parser (`parser.rs`)

Wraps tree-sitter to parse source code into syntax trees.

```rust
use chaffra_parse::parser;
use chaffra_core::diagnostic::Language;

let tree = parser::parse(source_bytes, Language::Go)?;
```

### File Discovery (`discovery.rs`)

Walks directories to find source files, detecting language from extensions and respecting ignore patterns.

```rust
use chaffra_parse::discovery;

let files = discovery::discover_files(root_path, &ignore_patterns);
```

Respects:
- Default ignore directories: `.git`, `node_modules`, `vendor`, `__pycache__`, `target`, etc.
- `.gitignore` patterns
- `.chafframeignore` patterns
- Custom ignore patterns from config

### Symbol Extraction (`symbols.rs`)

Extracts functions, types/classes, imports, and references from parsed trees.

**Go:**
- `function_declaration`, `method_declaration` -> `SymbolKind::Function`
- `type_declaration` / `type_spec` -> `SymbolKind::Type`
- Exported = name starts with uppercase
- Import paths from `import_declaration`

**Python:**
- `function_definition` -> `SymbolKind::Function`
- `class_definition` -> `SymbolKind::Type`
- Exported = name does not start with `_`
- `import_statement`, `import_from_statement` for imports

### Import Graph (`graph.rs`)

Builds a cross-file reference graph tracking which files define and reference which symbols.

```rust
use chaffra_parse::graph::ImportGraph;

let mut graph = ImportGraph::new();
graph.add_file("main.go", symbols, imports, references);
let unreferenced = graph.unreferenced_symbols();
```

### Suppression Scanning (`suppression.rs`)

Scans for `// chaffra:ignore` (Go) and `# chaffra:ignore` (Python) comments.

```rust
use chaffra_parse::suppression;

let suppressions = suppression::scan_suppressions(source, language);
let suppressed = suppression::is_suppressed(&suppressions, line, "unused-function");
```

Syntax:
- `// chaffra:ignore` -- suppress all rules on the next line
- `// chaffra:ignore unused-function,unused-type` -- suppress specific rules
- `# chaffra:ignore` -- Python equivalent
