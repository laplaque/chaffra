# frameworks

Built-in module for detecting framework-specific entry points in Go and Python
codebases. Entry points identified by this module are marked as "alive" to
prevent false positives in dead-code analysis.

## Supported Frameworks

### Go

| Framework | Import | Patterns Detected |
|-----------|--------|-------------------|
| **gin** | `github.com/gin-gonic/gin` | `r.GET("/path", handler)`, `r.POST(...)`, etc. |
| **echo** | `github.com/labstack/echo` | `e.GET("/path", handler)`, `e.POST(...)`, etc. |
| **cobra** | `github.com/spf13/cobra` | `&cobra.Command{Use: "name", Run: func...}` |

### Python

| Framework | Import | Patterns Detected |
|-----------|--------|-------------------|
| **FastAPI** | `fastapi` | `@app.get("/path")`, `@router.post(...)` decorators |
| **Django** | `django` | `path("url", view)` URL patterns, class-based views |
| **Flask** | `flask` | `@app.route("/path")`, `@app.get(...)` decorators |

## Rules

### `framework-entry-point`

- **Severity:** info
- **Description:** A function or method serves as a framework entry point
  (HTTP handler, CLI command, route decorator).
- **Suppress:** `// chaffra:ignore framework-entry-point`

### `framework-detected`

- **Severity:** info
- **Description:** A framework was detected in the project.
- **Suppress:** `// chaffra:ignore framework-detected`

## Configuration

Framework selection is **auto-detected** from project imports and dependencies.
There is no manual configuration required. Config-based framework selection
(to restrict or override detection) is planned for a future release.

## Integration with Dead-Code Module

The frameworks module exposes `get_alive_entry_points()` which returns all
detected entry points. The dead-code module can use this to exclude framework
handlers from unused-function reports.

## Output

Each finding includes metadata:

| Key | Value |
|-----|-------|
| `framework` | Framework name (e.g. "gin", "fastapi") |
| `entry_kind` | Entry point type (e.g. "handler", "route", "command") |
| `alive` | Always "true" -- signals this symbol is reachable |
