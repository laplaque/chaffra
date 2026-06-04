# Writing External Modules

External modules extend chaffra's analysis capabilities by implementing the
`AnalysisModule` gRPC service. They run as separate processes or Docker
containers and communicate with chaffra over localhost gRPC.

## Service Contract

Every external module implements the gRPC service defined in
`proto/chaffra/module/v1/module.proto`:

```protobuf
service AnalysisModule {
  rpc Describe(DescribeRequest) returns (ModuleInfo);
  rpc Analyze(AnalysisRequest)  returns (AnalysisResponse);
  rpc Explain(ExplainRequest)   returns (ExplainResponse);
  rpc Fix(FixRequest)           returns (FixResponse);
}
```

### RPCs

| RPC | Purpose |
|-----|---------|
| **Describe** | Return module metadata: ID, name, version, supported languages, rules. |
| **Analyze** | Receive source files and config, return findings. |
| **Explain** | Given a rule ID, return a detailed explanation. |
| **Fix** | Given findings, return text edits to fix them (or dry-run). |

## Transport Modes

External modules can be loaded in three ways, configured in `.chaffra.toml`:

### Command mode (default)

Spawn a local process. Chaffra passes `--port <N>` and connects over gRPC:

```toml
[[external_modules]]
id = "gin"
command = "chaffra-module-gin"
```

The module binary must listen on `127.0.0.1:<port>` for gRPC.

### gRPC mode

Connect to an already-running gRPC server:

```toml
[[external_modules]]
id = "gin"
mode = "grpc"
endpoint = "http://localhost:50051"
```

### Container mode

Run a Docker container with the module:

```toml
[[external_modules]]
id = "gin"
mode = "container"
image = "chaffra/module-gin:latest"
port = 50052
```

## Writing a Module

1. **Pick a language.** Write the module in the framework's native language
   (e.g., Go for gin analysis, Python for FastAPI analysis).

2. **Implement the gRPC service.** Use the proto definition to generate
   server stubs in your language.

3. **Package as a binary or Docker image.**
   - Binary: accept `--port <N>` flag, listen on `127.0.0.1:N`.
   - Docker: expose the gRPC port, listen on `0.0.0.0:<port>`.

4. **Register in `.chaffra.toml`** using the appropriate transport mode.

## Example: Minimal Go Module

```go
package main

import (
    "flag"
    "fmt"
    "net"

    pb "github.com/laplaque/chaffra/proto/chaffra/module/v1"
    "google.golang.org/grpc"
)

type server struct {
    pb.UnimplementedAnalysisModuleServer
}

func (s *server) Describe(ctx context.Context, req *pb.DescribeRequest) (*pb.ModuleInfo, error) {
    return &pb.ModuleInfo{
        Id:       "my-module",
        Name:     "My Custom Module",
        Version:  "0.1.0",
        Languages: []string{"go"},
    }, nil
}

func main() {
    port := flag.Int("port", 50051, "gRPC port")
    flag.Parse()

    lis, _ := net.Listen("tcp", fmt.Sprintf(":%d", *port))
    s := grpc.NewServer()
    pb.RegisterAnalysisModuleServer(s, &server{})
    s.Serve(lis)
}
```

## Finding Schema

Each finding returned by `Analyze` should include:

| Field | Required | Description |
|-------|----------|-------------|
| `rule_id` | yes | Unique rule identifier |
| `message` | yes | Human-readable description |
| `severity` | yes | "info", "warning", or "error" |
| `location` | yes | File, line, column range |
| `confidence` | no | 0.0 to 1.0 (default 1.0) |
| `metadata` | no | Key-value pairs for tooling |

## Testing

Use `grpcurl` or a test harness to verify your module:

```bash
grpcurl -plaintext localhost:50051 chaffra.module.v1.AnalysisModule/Describe
```
