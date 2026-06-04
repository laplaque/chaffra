# LLM Defense Module

**Module ID:** `llm-defense`
**Crate:** `chaffra-llm-defense`
**Languages:** Go, Python

Detects security risks in code that integrates with large language models: unsafe tool use, prompt injection exposure, missing output validation, missing rate limiting, excessive tool permissions, and unguarded agent loops.

## Rules

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `unsafe-tool-use` | Unsafe tool use | error | LLM tool definition allows execution of arbitrary code or commands |
| `prompt-injection-exposure` | Prompt injection exposure | error | User input is concatenated directly into an LLM prompt without sanitization |
| `missing-output-validation` | Missing output validation | error | LLM response is used in SQL, HTML, or shell context without validation |
| `missing-rate-limit` | Missing rate limit | warning | LLM API calls are made without rate limiting or throttling |
| `excessive-tool-permissions` | Excessive tool permissions | warning | Tool definition grants write permissions where read would suffice |
| `unguarded-agent-loop` | Unguarded agent loop | error | Agent loop has no iteration limit or timeout guard |

## Scope

The module only analyzes files that import a recognized LLM SDK or contain LLM-related indicators. Recognized SDKs include:

### Python
`openai`, `anthropic`, `langchain`, `llama_index`, `transformers`, `cohere`, `google.generativeai`, `vertexai`, `litellm`, `autogen`, `crewai`

### Go
`github.com/sashabaranov/go-openai`, `github.com/anthropics/anthropic-sdk-go`, `github.com/tmc/langchaingo`

## Detection Strategy

### Unsafe Tool Use

Scans tool definitions (functions, dicts, structs annotated as tools) for patterns that enable arbitrary code execution: `subprocess`, `exec()`, `eval()`, `os.system`, `shell=True`.

### Prompt Injection Exposure

Detects string interpolation (f-strings, `.format()`, `%` formatting, concatenation) on lines that construct prompts when the interpolated values come from user-controlled sources.

### Missing Output Validation

1. Identifies variables that receive LLM API responses.
2. Checks if those variables are used in dangerous contexts: `cursor.execute()`, `os.system()`, `subprocess.run()`, `innerHTML`.

### Missing Rate Limit

Checks whether files with LLM API calls also contain rate-limiting patterns: `time.sleep`, `semaphore`, `backoff`, `retry`, `TokenBucket`, etc.

### Excessive Tool Permissions

Flags tool permission definitions that include both read and write/delete/execute access, suggesting the principle of least privilege is not applied.

### Unguarded Agent Loop

Detects `while True` / `for {}` loops in agent contexts without iteration limits, counters, timeouts, or break conditions within the loop body.

## Confidence Scoring

| Rule | Confidence |
|------|-----------|
| unsafe-tool-use | 0.8 |
| prompt-injection-exposure | 0.8 |
| missing-output-validation | 0.8 |
| missing-rate-limit | 0.7 |
| excessive-tool-permissions | 0.7 |
| unguarded-agent-loop | 0.8 |

## Suppression

```python
# chaffra:ignore prompt-injection-exposure
prompt = f"Process: {user_input}"
```

```go
// chaffra:ignore unguarded-agent-loop
for {
    resp := agent.Step()
}
```

## CLI Usage

```bash
chaffra llm-defense .                             # Analyze current directory
chaffra llm-defense ./src --format json           # JSON output
chaffra explain llm-defense:prompt-injection-exposure  # Explain a rule
```
