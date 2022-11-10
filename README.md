# abnf

[![Go Reference](https://pkg.go.dev/badge/github.com/ghettovoice/abnf.svg)](https://pkg.go.dev/github.com/ghettovoice/abnf)
[![Coverage Status](https://coveralls.io/repos/github/ghettovoice/abnf/badge.svg?branch=master)](https://coveralls.io/github/ghettovoice/abnf?branch=master)

Package `abnf` implements ABNF grammar as described in [RFC 5234](https://www.rfc-editor.org/rfc/rfc5234) 
and [RFC 7405](https://www.rfc-editor.org/rfc/rfc7405).

Inspired by:

- https://github.com/declaresub/abnf
- https://github.com/elimity-com/abnf

## Installation

Add `abnf` package and all subpackages to your project:

```bash
go get github.com/ghettovoice/abnf/...
```

## Usage

Build a rule from basic operators:

```go
package main

import (
    "fmt"

    "github.com/ghettovoice/abnf"
)

var abc = abnf.Concat(
    `"a" "b" *"cd"`,
    abnf.Literal(`"a"`, []byte("a")),
    abnf.Literal(`"b"`, []byte("b")),
    abnf.Repeat0Inf(`*"cd"`, abnf.Literal(`"cd"`, []byte("cd"))),
)

func main() {
    var ns abnf.Nodes

    fmt.Println(abc([]byte("ab"), ns[:0]))
    fmt.Println(abc([]byte("abcd"), ns[:0]))
    fmt.Println(abc([]byte("abcdcd"), ns[:0]))
}
```

## CLI

Checkout `abnf` CLI [README](./cmd/abnf/README.md).

## License

MIT License - see [LICENSE](./LICENSE) file for a full text.
