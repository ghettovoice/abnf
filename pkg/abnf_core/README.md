# abnf_core

`abnf_core` provides generated implementations of the core rules defined in [RFC 5234 Appendix B](https://www.rfc-editor.org/rfc/rfc5234#appendix-B). The package exposes reusable operators and rules that match the canonical grammar definitions so you can bootstrap parsers without rewriting the ABNF specification.

## Overview

- Generated from the upstream `rules.abnf` file using the [`cmd/abnf`](../../cmd/abnf) CLI.
- Exposes both operator factories (returning `abnf.Operator`) and rule wrappers (returning `abnf.Rule`).
- Lazily initialises every rule the first time it is used to keep startup fast.

## Usage

```go
package main

import (
    "fmt"

    "github.com/ghettovoice/abnf"
    "github.com/ghettovoice/abnf/pkg/abnf_core"
)

func main() {
    nodes := abnf.NewNodes()
    defer nodes.Free()

    input := []byte("GoLang")
    if err := abnf_core.Operators().ALPHA(input, 0, nodes); err != nil {
        panic(err)
    }

    fmt.Println(nodes.Best().String())
}
```

## Regenerating

If you modify `rules.abnf`, regenerate this package to keep the Go sources in sync:

```bash
abnf generate -c ./abnf.yml
```

The `abnf.yml` configuration under this directory documents the exact inputs and output paths used.

## References

- [RFC 5234 Appendix B](https://www.rfc-editor.org/rfc/rfc5234#appendix-B)
- [abnf CLI documentation](../../cmd/abnf/README.md)
