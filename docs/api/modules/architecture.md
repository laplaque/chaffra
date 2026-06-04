# Architecture Module

**Module ID:** `architecture`
**Crate:** `chaffra-arch`
**Languages:** Go, Python, TypeScript, JavaScript, Java

Enforces architectural boundaries by validating imports against zone-based dependency rules. Includes four built-in presets for common architectural patterns and detects circular dependencies using Tarjan's strongly connected components algorithm.

## Rules

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `boundary-violation` | Boundary violation | error | An import crosses a declared architectural boundary |
| `circular-dependency` | Circular dependency | error | A cycle exists in the import graph between files or zones |

## Architecture Presets

### Layered (`--preset layered`)

Three-tier architecture where each layer may only depend on the layer directly below it.

| Zone | Patterns | Allowed Dependencies |
|------|----------|---------------------|
| `presentation` | `**/handler/**`, `**/api/**`, `**/controller/**` | `business` |
| `business` | `**/service/**`, `**/domain/**`, `**/usecase/**` | `data` |
| `data` | `**/repo/**`, `**/repository/**`, `**/store/**`, `**/db/**` | (none -- denies `presentation`, `business`) |

### Hexagonal (`--preset hexagonal`)

Ports-and-adapters architecture where the core domain has no outward dependencies.

| Zone | Patterns | Allowed Dependencies |
|------|----------|---------------------|
| `adapter` | `**/adapter/**`, `**/adapters/**` | `port` |
| `port` | `**/port/**`, `**/ports/**` | `core` |
| `core` | `**/core/**`, `**/domain/**` | (none -- denies `adapter`, `port`) |

### Feature-Sliced (`--preset feature-sliced`)

Layer hierarchy where each slice may only depend on layers below it.

| Zone | Patterns | Allowed Dependencies |
|------|----------|---------------------|
| `app` | `**/app/**` | `pages`, `features`, `entities`, `shared` |
| `pages` | `**/pages/**` | `features`, `entities`, `shared` |
| `features` | `**/features/**` | `entities`, `shared` |
| `entities` | `**/entities/**` | `shared` |
| `shared` | `**/shared/**` | (unrestricted) |

### Clean Architecture (`--preset clean`)

Concentric ring architecture with the dependency rule pointing inward.

| Zone | Patterns | Allowed Dependencies |
|------|----------|---------------------|
| `framework` | `**/framework/**`, `**/infra/**`, `**/infrastructure/**` | `interface` |
| `interface` | `**/interface/**`, `**/controller/**`, `**/presenter/**` | `usecase` |
| `usecase` | `**/usecase/**`, `**/interactor/**` | `entity` |
| `entity` | `**/entity/**`, `**/entities/**`, `**/domain/**` | (none -- denies `framework`, `interface`, `usecase`) |

## Custom Zones

Define zones and rules in `.chaffra.toml`:

```toml
[modules.architecture]
"zone.web" = "web/**,frontend/**"
"zone.api" = "api/**"
"zone.core" = "core/**,lib/**"
"rule.web.allow" = "api"
"rule.api.allow" = "core"
"rule.core.deny" = "web,api"
```

## Cycle Detection

Circular dependencies are detected using Tarjan's strongly connected components (SCC) algorithm. Any SCC containing two or more files is reported as a cycle. The finding includes the full cycle path in the `cycle` metadata field.

## Metadata

### Boundary Violation

| Key | Description |
|-----|-------------|
| `from_zone` | Zone of the importing file |
| `to_zone` | Zone of the imported target |
| `import_path` | The import path that crosses the boundary |

### Circular Dependency

| Key | Description |
|-----|-------------|
| `cycle` | Full cycle path as `A -> B -> C` |
| `cycle_length` | Number of files in the cycle |

## Suppression

```go
// chaffra:ignore boundary-violation
import "myapp/infrastructure/db"
```

```python
# chaffra:ignore circular-dependency
from myapp.models import User
```

## CLI Usage

```bash
chaffra boundaries .                          # Analyze with custom config
chaffra boundaries . --preset layered         # Use layered preset
chaffra boundaries . --preset hexagonal       # Use hexagonal preset
chaffra boundaries . --format sarif           # SARIF output
chaffra explain architecture:boundary-violation   # Explain a rule
```
