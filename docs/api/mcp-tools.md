# MCP Tools Reference

chaffra exposes analysis capabilities through the Model Context Protocol (MCP),
allowing AI coding assistants to query health scores, dead-code findings, and
rule explanations directly.

## Protocol

JSON-RPC 2.0 over stdio. Start the server with:

```bash
chaffra mcp
```

## Available Tools

### chaffra/health

Compute a composite health score for the codebase.

**Input Schema:**

```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Path to the repository root (defaults to current directory)"
    }
  }
}
```

**Output:** JSON object with `score` (0-100), `grade` (A-F), `files` array with
per-file breakdown, and `total_files` count.

### chaffra/dead-code

Detect dead code: unused functions, types, imports, and files.

**Input Schema:**

```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Path to the repository root (defaults to current directory)"
    }
  }
}
```

**Output:** JSON object with `findings` array and `metrics` object containing
`files_analyzed`, `duration_ms`, and counters.

### chaffra/explain

Explain a specific diagnostic rule in plain language.

**Input Schema:**

```json
{
  "type": "object",
  "properties": {
    "rule_id": {
      "type": "string",
      "description": "Rule ID to explain (e.g. 'dead-code:unused-function')"
    }
  },
  "required": ["rule_id"]
}
```

**Output:** JSON object with `rule_id`, `name`, `description`, `rationale`,
`default_severity`, `suppression_syntax`, and `examples`.

## Example Session

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"editor","version":"1.0"}}}
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"chaffra","version":"0.1.0"}}}

{"jsonrpc":"2.0","method":"notifications/initialized"}

{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":2,"result":{"tools":[...]}}

{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"chaffra/health","arguments":{"path":"."}}}
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{...}"}]}}
```

## Error Handling

Tool errors return `isError: true` in the result with an error message in the
content text. JSON-RPC protocol errors use standard error codes:

| Code   | Meaning          |
|--------|------------------|
| -32700 | Parse error      |
| -32600 | Invalid request  |
| -32601 | Method not found |
| -32603 | Internal error   |
