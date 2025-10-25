# abnf_def

`abnf_def` ships the full ABNF grammar defined across [RFC 5234](https://www.rfc-editor.org/rfc/rfc5234) and [RFC 7405](https://www.rfc-editor.org/rfc/rfc7405). The package is generated from the canonical specification and is intended to serve as a reference implementation for higher-level parsers or tooling.

## Overview

- Generated from the upstream `rules.abnf` file using the [`cmd/abnf`](../../cmd/abnf) CLI.
- Provides descriptors returning both operators (`abnf.Operator`) and rules (`abnf.Rule`).
- Handles rule extensions present in the RFCs via generated alternations.

## Usage

```go
package main

import (
    "fmt"

    "github.com/ghettovoice/abnf"
    "github.com/ghettovoice/abnf/pkg/abnf_def"
)

func main() {
    nodes := abnf.NewNodes()
    defer nodes.Free()

    input := []byte("rule = *ALPHA")
    if err := abnf_def.Rules().Rule(input, nodes); err != nil {
        panic(err)
    }

    fmt.Println(nodes.Best().String())
}
```

## Regenerating

If you tweak `rules.abnf`, align the generated Go files by running:

```bash
abnf generate ./abnf.yml
```

The `abnf.yml` configuration under this directory documents the exact inputs and output paths used.

## References

- [RFC 5234](https://www.rfc-editor.org/rfc/rfc5234)
- [RFC 7405](https://www.rfc-editor.org/rfc/rfc7405)
- [abnf CLI documentation](../../cmd/abnf/README.md)
