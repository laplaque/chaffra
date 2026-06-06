# Duplication Module

**Module ID:** `duplication`
**Crate:** `chaffra-duplication`
**Languages:** Go, Python, JavaScript, TypeScript, Java

Detects duplicate code blocks using a token-based sliding window algorithm with configurable normalization modes. Produces clone pair findings with family IDs for grouping related clones.

## Rules

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `duplicate-block` | Duplicate code block | warning | A contiguous block of code is duplicated in another location |
| `duplicate-function` | Duplicate function | warning | An entire function body is duplicated in another function |

## Detection Modes

| Mode | Description |
|------|-------------|
| `strict` | Exact token match after stripping comments and whitespace |
| `mild` | Normalize string and number literals to placeholders (`$STR`, `$NUM`) |
| `weak` | Normalize identifiers to `$ID` (keywords preserved) |
| `semantic` | Normalize control flow keywords to `$CTRL`, identifiers to `$ID` |

## Configuration

```toml
[modules.duplication]
mode = "strict"      # Detection mode: strict, mild, weak, semantic
min-tokens = 50      # Minimum token count for a clone to be reported
```

## CLI Usage

```bash
# Default: strict mode, 50 token minimum
chaffra dupes .

# Weak mode with lower threshold
chaffra dupes --mode weak --min-tokens 30 .

# SARIF output
chaffra dupes --format sarif .
```

## Clone Families

Each clone pair receives a family ID (`dup:<8hex>`) computed as the SHA-256 hash of the normalized token sequence. Clones with the same family ID share the same normalized structure and should be reviewed together for extraction into a shared utility.

## Finding Metadata

Each finding includes:
- `family_id` -- clone family fingerprint
- `similarity` -- similarity score (1.0 for strict, lower for normalized modes)
- `token_count` -- number of matched tokens
- `mode` -- detection mode used
- `other_file` -- path of the other clone location
- `other_start_line` / `other_end_line` -- line range of the other clone

## Auto-fix

Duplication findings are not auto-fixable. Resolving clones requires human judgment about the right abstraction (extract function, create shared module, introduce a template, etc.).
