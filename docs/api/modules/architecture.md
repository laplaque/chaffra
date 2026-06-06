# Architecture Module

**Module ID:** `architecture`
**Crate:** `chaffra-arch`
**Languages:** Go, Python, JavaScript, TypeScript, Java

Validates architectural boundaries between zones (groups of files) and detects circular dependencies using Tarjan's strongly connected components algorithm.

## Rules

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `boundary-violation` | Boundary violation | error | An import crosses a forbidden architectural boundary |
| `circular-dependency` | Circular dependency | warning | A group of files form a circular import dependency |

## Built-in Presets

### `layered`

Classic layered architecture: presentation -> application -> domain <- infrastructure.

| Zone | Patterns |
|------|----------|
| presentation | `presentation/**`, `api/**`, `handler/**`, `controller/**`, `cmd/**`, `ui/**` |
| application | `application/**`, `service/**`, `usecase/**` |
| domain | `domain/**`, `model/**`, `entity/**`, `core/**` |
| infrastructure | `infrastructure/**`, `infra/**`, `db/**`, `repository/**`, `adapter/**` |

Rules: domain cannot import from infrastructure, presentation, or application. Application cannot import from presentation. Infrastructure cannot import from presentation. Presentation cannot import from infrastructure (must go through application).

### `hexagonal`

Ports and adapters: core has no outbound dependencies to adapters.

| Zone | Patterns |
|------|----------|
| core | `core/**`, `domain/**`, `model/**` |
| ports | `port/**`, `ports/**`, `interface/**` |
| adapters | `adapter/**`, `adapters/**`, `infrastructure/**`, `driven/**`, `driving/**` |

Rules: core and ports cannot import from adapters.

### `feature-sliced`

Feature-sliced design: features are isolated, shared layer at bottom.

| Zone | Patterns |
|------|----------|
| app | `app/**` |
| features | `features/**`, `feature/**`, `modules/**` |
| shared | `shared/**`, `common/**`, `lib/**`, `pkg/**` |

Rules: shared cannot import from features or app.

### `clean`

Clean architecture: entities -> use cases -> interface adapters -> frameworks.

| Zone | Patterns |
|------|----------|
| entities | `entity/**`, `domain/**`, `model/**` |
| usecases | `usecase/**`, `application/**`, `service/**` |
| adapters | `adapter/**`, `controller/**`, `presenter/**`, `gateway/**` |
| frameworks | `framework/**`, `infrastructure/**`, `db/**`, `web/**` |

Rules: inner layers cannot import from outer layers.

## Configuration

```toml
[modules.architecture]
preset = "layered"    # Use a built-in preset

# Or define custom zones and rules:
# zone.domain = "src/domain/**"
# zone.infra = "src/infra/**"
# deny.domain.infra = "true"
```

## CLI Usage

```bash
# Default preset (layered)
chaffra boundaries .

# Hexagonal architecture
chaffra boundaries --preset hexagonal .

# JSON output
chaffra boundaries --format json .
```

## Circular Dependency Detection

The module builds an import graph from parsed source files and runs Tarjan's SCC algorithm. Any strongly connected component with more than one file is reported as a circular dependency, showing the full cycle path.

## Auto-fix

Architecture violations are not auto-fixable. Resolving boundary violations requires restructuring imports or moving code between zones.
