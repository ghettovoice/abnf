# abnf_gen

`abnf_gen` exposes programmatic helpers for parsing ABNF grammars and generating Go code. It is the underlying engine powering the [`cmd/abnf`](../../cmd/abnf) CLI and can be embedded in your own tooling pipelines.

## Components

- **ParserGenerator** – parses ABNF sources into in-memory `abnf.Operator`/`abnf.Rule` mappings for dynamic evaluation.
- **CodeGenerator** – renders `abnf.Operator`/`abnf.Rule` implementations as formatted Go source files.
- **rulesParser** – internal parser that merges multiple grammar files and understands rule extensions (`=/`).

## Quick Start

```go
package main

import (
    "bytes"
    "log"

    "github.com/ghettovoice/abnf/pkg/abnf_gen"
)

const grammar = `ALPHA = %x41 / %x42`

func main() {
    var g abnf_gen.ParserGenerator
    if _, err := g.ReadFrom(bytes.NewBufferString(grammar)); err != nil {
        log.Fatal(err)
    }

    op := g.Operators()["ALPHA"]
    _ = op // use the operator to parse input at runtime
}
```

## Generating Code

```go
var g abnf_gen.CodeGenerator
g.PackageName = "example"

if _, err := g.ReadFrom(bytes.NewBufferString(grammar)); err != nil {
    log.Fatal(err)
}

var buf bytes.Buffer
if _, err := g.WriteTo(&buf); err != nil {
    log.Fatal(err)
}

// buf now contains a complete Go file with operator/rule descriptors
```

### External Rules

Both generators accept an optional `External` map keyed by rule name. Each entry can provide:

- `Operator` – custom `abnf.Operator` for parser-only workflows.
- `PackagePath`/`PackageName` – import details for code generation (e.g., reusing `abnf_core`).

## Related Docs

- [abnf CLI](../../cmd/abnf/README.md)
- [Core package readme](../abnf_core/README.md)
