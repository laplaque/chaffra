# Duplication Module

**Module ID:** `duplication`
**Crate:** `chaffra-duplication`
**Languages:** Go, Python, TypeScript, JavaScript, Java

Identifies duplicate code blocks using a suffix-array algorithm with token-level comparison. Supports four sensitivity modes so teams can tune how aggressively near-copies and structurally equivalent blocks are reported.

## Rules

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `duplicate-block` | Duplicate code block | warning | A sequence of tokens appears in two or more locations, exceeding the minimum token threshold |
| `duplicate-function` | Duplicate function | warning | A function body is substantially identical to another function |

## Detection Modes

| Mode | Normalization | Use Case |
|------|--------------|----------|
| `strict` | Exact tokens (only whitespace/comments stripped) | Find exact copies |
| `mild` | String and numeric literals replaced with `$STR` / `$NUM` | Find copies that differ only in literal values |
| `weak` | All identifiers also replaced with `$ID` | Find structurally identical code with different names |
| `semantic` | Control-flow keywords replaced with `$CF` | Find algorithmically equivalent blocks |

## Algorithm

1. **Tokenize:** Parse each file with tree-sitter, extract leaf tokens, strip comments.
2. **Normalize:** Apply mode-specific normalization to each token.
3. **Hash windows:** Slide a window of `min-tokens` length across each file's token stream, computing SHA-256 fingerprints.
4. **Match:** Find windows with identical fingerprints across files or non-overlapping regions of the same file.
5. **Extend:** Grow each match beyond `min-tokens` while tokens continue to agree.
6. **Deduplicate:** Remove overlapping or subsumed clone pairs.

## Fingerprinting

Each clone family is assigned a deterministic SHA-256-based identifier in the format `dup:XXXXXXXX` (8 hex characters from the first 4 bytes of the hash). This allows tracking clone families across runs.

## Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `min-tokens` | integer | 50 | Minimum token count for a match |
| `mode` | string | `mild` | Detection mode: `strict`, `mild`, `weak`, `semantic` |

Configuration via `.chaffra.toml`:

```toml
[modules.duplication]
min-tokens = "30"
mode = "weak"
```

## Confidence Scoring

| Scenario | Confidence |
|----------|-----------|
| Exact token match (strict or mild) | 1.0 |
| Identifier-normalized match (weak) | 1.0 |
| Semantic match | 1.0 |

## Metadata

Each finding includes the following metadata fields:

| Key | Description |
|-----|-------------|
| `family_id` | SHA-256-based clone family identifier (`dup:XXXXXXXX`) |
| `token_count` | Number of tokens in the clone |
| `similarity` | Similarity score (0.0 to 1.0) |
| `other_file` | Path to the other file in the clone pair |
| `other_start_line` | Start line in the other file |
| `other_end_line` | End line in the other file |

## Suppression

```go
// chaffra:ignore duplicate-block
func handleRequest() { ... }
```

```python
# chaffra:ignore duplicate-block
def handle_request():
    ...
```

## CLI Usage

```bash
chaffra dupes .                           # Analyze with defaults (mild mode)
chaffra dupes . --mode strict             # Exact copies only
chaffra dupes . --mode weak --format json # JSON output with weak matching
chaffra explain duplication:duplicate-block   # Explain a rule
```
