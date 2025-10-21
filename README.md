# abnf

[![Go Reference](https://pkg.go.dev/badge/github.com/ghettovoice/abnf.svg)](https://pkg.go.dev/github.com/ghettovoice/abnf)
[![Go Report Card](https://goreportcard.com/badge/github.com/ghettovoice/abnf)](https://goreportcard.com/report/github.com/ghettovoice/abnf)
[![Tests](https://github.com/ghettovoice/abnf/actions/workflows/test.yml/badge.svg)](https://github.com/ghettovoice/abnf/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/ghettovoice/abnf/badge.svg?branch=master)](https://coveralls.io/github/ghettovoice/abnf?branch=master)
[![CodeQL](https://github.com/ghettovoice/abnf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/ghettovoice/abnf/actions/workflows/github-code-scanning/codeql)

Package `abnf` implements ABNF grammar as described in [RFC 5234](https://www.rfc-editor.org/rfc/rfc5234)
and [RFC 7405](https://www.rfc-editor.org/rfc/rfc7405).

Inspired by:

- <https://github.com/declaresub/abnf>
- <https://github.com/elimity-com/abnf>

## Installation

Add `abnf` package and all subpackages to your project:

```bash
go get github.com/ghettovoice/abnf@latest
```

## Usage

Build a custom operator from basic operators:

```go
package main

import (
    "fmt"

    "github.com/ghettovoice/abnf"
)

var op = abnf.Concat(
    `"a" "b" *"cd"`,
    abnf.Literal(`"a"`, []byte("a")),
    abnf.Literal(`"b"`, []byte("b")),
    abnf.Repeat0Inf(`*"cd"`, abnf.Literal(`"cd"`, []byte("cd"))),
)

func main() {
    ns := abnf.NewNodes()
    defer ns.Free()

    if err := op([]byte("ab"), 0, &ns); err != nil {
        panic(err)
    }
    fmt.Println(ns.Best())

    ns.Clear()
    if err := op([]byte("abcd"), 0, &ns); err != nil {
        panic(err)
    }
    fmt.Println(ns.Best())

    ns.Clear()
    if err := op([]byte("abcdcd"), 0, &ns); err != nil {
        panic(err)
    }
    fmt.Println(ns.Best())

    // Output:
    // ab
    // abcd
    // abcdcd
}
```

## CLI

Checkout `abnf` CLI [README](./cmd/abnf/README.md).

## License

MIT License - see [LICENSE](./LICENSE) file for a full text.
