# Security Module

**Module ID:** `security`
**Crate:** `chaffra-security`
**Languages:** Go, Python

Detects security vulnerabilities through SAST (taint analysis), secret scanning, and dependency CVE checking.

## Rules

| Rule ID | Name | Default Severity | Category | Description |
|---------|------|-------------------|----------|-------------|
| `sql-injection` | SQL injection | error | sast | Tainted data flows into a SQL query without parameterization |
| `command-injection` | Command injection | error | sast | Tainted data flows into an OS command execution call |
| `xss` | Cross-site scripting (XSS) | error | sast | Tainted data flows into HTML output without escaping |
| `ssrf` | Server-side request forgery (SSRF) | error | sast | Tainted data controls the URL of an outbound HTTP request |
| `path-traversal` | Path traversal | error | sast | Tainted data flows into a file path without validation |
| `unsafe-deserialization` | Unsafe deserialization | error | sast | Untrusted data is deserialized using an unsafe method |
| `hardcoded-secret` | Hardcoded secret | error | secrets | API key, password, or credential embedded in source code |
| `high-entropy-string` | High-entropy string | warning | secrets | String with high Shannon entropy that may be a secret |
| `vulnerable-dependency` | Vulnerable dependency | warning | deps | Dependency has a known CVE in its version range |

## SAST -- Taint Analysis

Intraprocedural taint analysis tracks data flow from user-controlled sources to dangerous sinks within individual functions.

### Sources

| Language | Source | Description |
|----------|--------|-------------|
| Go | `r.FormValue()`, `r.URL`, `r.Body`, `r.Header` | HTTP request data |
| Python | `request.args`, `request.form`, `request.data`, `request.json` | Flask/Django request data |
| Python | `input()`, `sys.argv` | User input via stdin and CLI args |

### Sinks

| Rule | Go Sinks | Python Sinks |
|------|----------|--------------|
| sql-injection | `db.Query`, `db.Exec`, `db.QueryRow` | `cursor.execute`, `raw()` |
| command-injection | `exec.Command` | `os.system`, `subprocess.call/run/Popen` |
| xss | `fmt.Fprintf`, `w.Write` | `render_template_string`, `Markup()` |
| ssrf | `http.Get`, `http.Post` | `requests.get/post`, `urllib.request.urlopen` |
| path-traversal | `os.Open`, `os.ReadFile` | `open()`, `os.path.join` |
| unsafe-deserialization | `json.Unmarshal`, `yaml.Unmarshal` | `pickle.loads/load`, `yaml.load`, `marshal.loads` |

### Taint Propagation

1. **Parameter taint:** Function parameters matching common patterns (e.g., `*http.Request`) are marked tainted.
2. **Source taint:** Assignments from taint sources mark the assigned variable as tainted.
3. **Propagation:** Assignments where the RHS references a tainted variable propagate taint to the LHS.
4. **Sink check:** Sink call sites are checked for tainted variable references.

### Confidence Scoring

| Scenario | Confidence |
|----------|-----------|
| Tainted variable in string concatenation at sink | 0.9 |
| Direct tainted variable reference at sink | 0.85 |
| Indirect or uncertain taint | 0.7 |

## Secret Scanning

Pattern-based detection of hardcoded credentials plus Shannon entropy analysis for unstructured secrets.

### Supported Secret Types

- AWS Access Key ID / Secret Access Key
- GCP Service Account Key / API Key
- Azure Storage Account Key
- GitHub Personal Access Token / OAuth Token
- Slack Bot Token / Webhook URL
- Stripe Secret / Publishable Key
- SendGrid API Key
- Twilio Account SID
- Heroku API Key
- Private Keys (PEM format)
- JSON Web Tokens
- Generic API keys, passwords, tokens

### Entropy Detection

Strings with Shannon entropy >= 4.5 bits/char that are 16-256 characters long are flagged as potential secrets. Strings that look like URLs, file paths, SQL queries, sentences, or format strings are excluded.

### Test File Exclusion

Files matching test patterns (`*_test.go`, `test_*`, `tests/`, `testdata/`, `fixtures/`, `examples/`) are skipped to avoid false positives from test fixtures.

## Dependency CVE Scanning

Offline vulnerability checking against a curated database of known-bad version ranges.

### Supported Manifests

| File | Ecosystem |
|------|-----------|
| `go.mod` | Go modules |
| `requirements.txt` | Python (pip) |
| `Cargo.lock` | Rust (Cargo) |
| `package-lock.json` | Node.js (npm) |

### Version Comparison

Versions are compared using semver-like logic. A dependency is flagged if its version falls within `[min_version, max_version)` of a known vulnerability.

## Suppression

```go
// chaffra:ignore sql-injection
func handler(w http.ResponseWriter, r *http.Request) { ... }
```

```python
# chaffra:ignore hardcoded-secret
API_KEY = os.environ["API_KEY"]  # actually safe
```

## Auto-fix

Security findings require manual review and cannot be auto-fixed. The module returns `FixResult` with `applied: false` and a reason indicating manual remediation is needed.

## CLI Usage

```bash
chaffra security .                          # Analyze current directory
chaffra security ./src --format json        # JSON output
chaffra explain security:sql-injection      # Explain a rule
chaffra explain security:hardcoded-secret   # Explain secret scanning
```
