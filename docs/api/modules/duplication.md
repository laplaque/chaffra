# Duplication Module

**Module ID:** `duplication`
**Crate:** `chaffra-duplication`
**Languages:** Go, Python, JavaScript, TypeScript, Java

Detects duplicate code blocks using a token-based sliding window algorithm with configurable normalization modes. Results are aggregated into clone families with coalesced ranges to keep output bounded and meaningful.

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
max-families = 200   # Maximum clone families reported (default 200)
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

Raw sliding-window matches are aggregated into clone families. Overlapping or adjacent ranges within the same file are coalesced, and families that share overlapping locations across file pairs are merged using union-find. This produces one finding per logical clone family rather than one per sliding-window match.

Each family receives a deterministic ID (`dup:<8hex>`) computed from its coalesced occurrence locations. Families with multiple locations in different files should be reviewed together for extraction into a shared utility.

When the same code block appears in three or more files, all file pairs are merged into a single family with all locations listed.

## Result Limits

The `max-families` config option (default 200) caps the number of reported families. When truncated, the `truncated_families` metric records how many families were dropped.

## Finding Metadata

Each finding (one per clone family) includes:
- `family_id` -- deterministic clone family fingerprint
- `similarity` -- similarity score (1.0 for strict, lower for normalized modes)
- `token_count_min` / `token_count_max` -- token count range across matches in the family
- `mode` -- detection mode used
- `clone_locations` -- compact JSON array of all locations: `[{"file":"...","start":N,"end":N},...]`
- `raw_pair_count` -- number of raw sliding-window pairs before coalescing
- `reported_location_count` -- number of coalesced locations in this family

## Metrics

| Counter | Description |
|---------|-------------|
| `raw_clone_pairs` | Total sliding-window matches before aggregation |
| `clone_families` | Total families after aggregation (before cap) |
| `reported_findings` | Findings emitted (after cap) |
| `collapsed_matches` | Raw pairs absorbed by coalescing |
| `truncated_families` | Families dropped by the cap (only present when truncated) |

## Auto-fix

Duplication findings are not auto-fixable. Resolving clones requires human judgment about the right abstraction (extract function, create shared module, introduce a template, etc.).
