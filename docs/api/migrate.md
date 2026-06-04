# Migrate Command

Convert configuration from other analysis tools to `.chaffra.toml`.

## Supported tools

| Tool | Config file | Mapped to |
|------|------------|-----------|
| knip | `knip.json`, `package.json` | dead-code rules, entry/ignore patterns |
| jscpd | `.jscpd.json` | duplication settings (min-tokens, mode) |
| golangci-lint | `.golangci.yml` | rules, health thresholds, ignore patterns |
| ruff | `ruff.toml`, `pyproject.toml` | rules, health thresholds, exclude patterns |
| import-linter | `.importlinter` | boundary zones and dependency rules |

## CLI usage

### Preview migration

```bash
chaffra migrate --from knip .
chaffra migrate --from golangci-lint .
chaffra migrate --from ruff .
```

### Write config

```bash
chaffra migrate --from knip --write .
```

### From a specific directory

```bash
chaffra migrate --from ruff /path/to/project
```

## Mapping details

### knip

- `entry` -> `[project] entry`
- `ignore` -> `[project] ignore`
- `ignoreDependencies` -> noted, appended to ignore
- `workspaces` -> manual review note

### jscpd

- `minTokens` -> `[duplication] min-tokens`
- `minLines` -> approximate `min-tokens` (x10)
- `threshold` -> noted (use `mode` instead)
- `ignore` -> `[project] ignore`

### golangci-lint

- `enable` linters -> `[rules]` severity overrides
- `skip-dirs` -> `[project] ignore`
- `max-complexity` -> `[health] max-cyclomatic`
- Unmapped linters -> noted for review

### ruff

- `select` F/C90 rules -> dead-code and complexity rules
- `exclude` -> `[project] ignore`
- `mccabe.max-complexity` -> `[health] max-cyclomatic`
- Style rules (E, I) -> noted as not mapped

### import-linter

- `layers` contracts -> `[boundaries] zones` and ordered `rules`
- `forbidden` contracts -> `[boundaries] rules` with deny lists
- Other contract types -> noted for review

## Migration notes

Each migration produces human-readable notes for:
- Settings that have no direct chaffra equivalent
- Approximate conversions (e.g. lines to tokens)
- Sections requiring manual review
