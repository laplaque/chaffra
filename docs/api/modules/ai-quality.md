# AI Quality Module

**Module ID:** `ai-quality`
**Crate:** `chaffra-ai-quality`
**Languages:** Go, Python

Detects common defects introduced by AI code generators: hallucinated API calls, phantom security functions, missing decorators, unfinished stubs, disabled controls, impossible dependency versions, and inconsistent error handling patterns.

## Rules

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `phantom-api-call` | Phantom API call | error | Call to a function that does not exist in the codebase or known standard library |
| `phantom-security-call` | Phantom security call | error | Call to a nonexistent security or authentication function |
| `missing-decorator` | Missing decorator | warning | Security decorator mentioned in comment but not applied to the function |
| `unfinished-stub` | Unfinished stub | warning | Function body contains only pass, todo!(), TODO comments, or placeholder content |
| `disabled-control` | Disabled security control | error | Security check is commented out or gated behind `if false` / `if False` |
| `impossible-dependency-version` | Impossible dependency version | warning | Dependency specifies a version constraint that cannot be satisfied |
| `inconsistent-error-handling` | Inconsistent error handling | info | File mixes different error handling patterns indicating mechanical generation |

## Detection Strategy

### Phantom API Calls

1. **Symbol collection:** Extract all defined symbols across all files in scope.
2. **Known set:** Build a set of known names from definitions, imports, standard library, and builtins.
3. **Reference check:** Flag function calls where the callee name is not in the known set.

### Phantom Security Calls

Same as phantom API calls, but specifically targets security-related function names (auth, CSRF, token validation, etc.) with higher confidence.

### Missing Decorators

Scans comments for mentions of security decorators (`@login_required`, `@csrf_protect`, etc.) and checks whether the decorator is actually applied to the next function definition.

For Go, checks for comments like `// requires authentication` and verifies that auth middleware is applied in the function body.

### Unfinished Stubs

Analyzes function bodies for placeholder patterns:
- Python: `pass`, `...`, `# TODO`, `raise NotImplementedError`
- Go: `// TODO`, `panic("not implemented")`, bare `return nil`

### Disabled Controls

- Commented-out security code (e.g., `// validate_token(user)`)
- `if false { ... }` or `if False:` gating security checks

### Impossible Dependency Versions

- `requirements.txt`: Major version >= 90, conflicting constraints
- `go.mod`: Module versions with major >= 90

### Inconsistent Error Handling

- Go: mixing `if err != nil` with `panic()` or `log.Fatal`
- Python: mixing bare `except:` with typed `except SomeError:`

## Confidence Scoring

| Rule | Confidence |
|------|-----------|
| phantom-api-call | 0.7 |
| phantom-security-call | 0.9 |
| missing-decorator | 0.7-0.8 |
| unfinished-stub | 0.9 |
| disabled-control | 0.8-0.9 |
| impossible-dependency-version | 0.8 |
| inconsistent-error-handling | 0.6 |

## Suppression

```python
# chaffra:ignore phantom-api-call
result = external_api_call(data)
```

```go
// chaffra:ignore unfinished-stub
func Placeholder() {}
```

## CLI Usage

```bash
chaffra ai-quality .                        # Analyze current directory
chaffra ai-quality ./src --format json      # JSON output
chaffra explain ai-quality:phantom-api-call # Explain a rule
```
