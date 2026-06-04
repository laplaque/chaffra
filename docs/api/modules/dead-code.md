# Dead Code Module

**Module ID:** `dead-code`
**Crate:** `chaffra-deadcode`
**Languages:** Go, Python

Detects unused symbols -- functions, types, imports, and files -- by building a reference graph and performing reachability analysis from entry points.

## Rules

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `unused-function` | Unused function | warning | Function is defined but never called or referenced |
| `unused-type` | Unused type | warning | Type is defined but never used |
| `unused-import` | Unused import | warning | Import is declared but no imported name is used |
| `unused-file` | Unused file | info | File contains no symbols referenced by any other file |
| `stale-suppression` | Stale suppression | info | Suppression comment no longer applies to any finding |

## Entry Points

Symbols are considered alive if they are entry points or reachable from an entry point.

### Go Entry Points

- `main()` and `init()` functions
- `Test*` and `Benchmark*` functions (test files)
- Exported names (uppercase) in any package

### Python Entry Points

- All symbols in `__init__.py` files
- `test_*` functions
- Public symbols (names not starting with `_`)

## Reachability Analysis

1. **Seed:** Mark all entry point symbols as alive.
2. **Trace:** From each alive symbol's file, follow all references to other symbols.
3. **Fixed-point:** Repeat until no new symbols become alive.
4. **Report:** Any symbol not in the alive set is unused.

## Confidence Scoring

| Scenario | Confidence |
|----------|-----------|
| Symbol not referenced anywhere | 1.0 |
| Symbol referenced but transitively unreachable | 0.8 |

## Suppression

```go
// chaffra:ignore unused-function
func helper() {}
```

```python
# chaffra:ignore unused-function
def helper():
    pass
```

## Auto-fix

The module generates `TextEdit` actions to remove unused symbols. Use `chaffra fix` or the Fix RPC to apply them.

## CLI Usage

```bash
chaffra dead-code .                    # Analyze current directory
chaffra dead-code ./src --format json  # JSON output
chaffra explain dead-code:unused-function  # Explain a rule
```
