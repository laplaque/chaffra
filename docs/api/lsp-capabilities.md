# LSP Capabilities Reference

chaffra provides a lightweight Language Server Protocol implementation for
editor integration. Start the server with:

```bash
chaffra lsp
```

## Protocol

JSON-RPC 2.0 over stdio with Content-Length headers per the LSP specification.

## Supported Capabilities

### textDocument/didSave

When a file is saved, chaffra runs dead-code and complexity analysis on the
saved file and publishes diagnostics via `textDocument/publishDiagnostics`.

**Diagnostics include:**
- Unused functions, types, imports (dead-code module)
- High cyclomatic complexity findings (complexity module)
- High cognitive complexity findings (complexity module)

### textDocument/didOpen

When a file is opened, chaffra analyzes the file content and publishes initial
diagnostics.

### textDocument/hover

Hovering over a function shows complexity metrics:

- Function name
- Cyclomatic complexity
- Cognitive complexity
- Line count
- Maximum nesting depth

**Example hover content:**

```
**main** - Cyclomatic: 3, Cognitive: 2, Lines: 15, Max nesting: 2
```

## Diagnostic Mapping

chaffra findings map to LSP diagnostics as follows:

| chaffra Severity | LSP Severity  |
|------------------|---------------|
| Error            | Error (1)     |
| Warning          | Warning (2)   |
| Info             | Information (3)|

Each diagnostic includes:
- `source`: "chaffra"
- `code`: the rule ID (e.g. "unused-function")
- `range`: mapped from the finding's location (converted to 0-based lines)

## Server Capabilities Advertised

```json
{
  "textDocumentSync": "Full",
  "hoverProvider": true
}
```

## Supported Languages

- Go (`.go` files)
- Python (`.py` files)

## Editor Configuration

### VS Code (with a generic LSP client)

```json
{
  "languageserver": {
    "chaffra": {
      "command": "chaffra",
      "args": ["lsp"],
      "filetypes": ["go", "python"]
    }
  }
}
```

### Neovim (with nvim-lspconfig)

```lua
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

configs.chaffra = {
  default_config = {
    cmd = { 'chaffra', 'lsp' },
    filetypes = { 'go', 'python' },
    root_dir = lspconfig.util.root_pattern('.chaffra.toml', '.git'),
  },
}

lspconfig.chaffra.setup({})
```
