# abnf

[![Go Reference](https://pkg.go.dev/badge/github.com/ghettovoice/abnf.svg)](https://pkg.go.dev/github.com/ghettovoice/abnf)
[![Go Report Card](https://goreportcard.com/badge/github.com/ghettovoice/abnf)](https://goreportcard.com/report/github.com/ghettovoice/abnf)
[![Tests](https://github.com/ghettovoice/abnf/actions/workflows/test.yml/badge.svg)](https://github.com/ghettovoice/abnf/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/ghettovoice/abnf/badge.svg?branch=master)](https://coveralls.io/github/ghettovoice/abnf?branch=master)
[![CodeQL](https://github.com/ghettovoice/abnf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/ghettovoice/abnf/actions/workflows/github-code-scanning/codeql)

**abnf** is a toolkit for working with Augmented Backus–Naur Form (ABNF) grammars in Go, implementing the specifications from [RFC 5234](https://www.rfc-editor.org/rfc/rfc5234) and [RFC 7405](https://www.rfc-editor.org/rfc/rfc7405). It delivers reusable parsing operators, ready-made rule sets, and a CLI/code generation pipeline that help you build fast and reliable parsers.

Inspired by [declaresub/abnf](https://github.com/declaresub/abnf) and [elimity-com/abnf](https://github.com/elimity-com/abnf).

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Library](#library)
  - [CLI](#cli)
- [Quick Start](#quick-start)
- [Packages](#packages)
- [CLI Overview](#cli-overview)
- [Contributing](#contributing)
- [License](#license)

## Features

- Composable ABNF operators mirroring the RFC syntax and semantics.
- High-performance node reuse with pooling and optional caching.
- Generated rule sets for RFC core and definition grammars.
- Detailed error tracing with optional lightweight errors when you need speed.
- CLI tool and code generator for turning ABNF grammar files into Go packages.

## Installation

### Library

```bash
go get github.com/ghettovoice/abnf@latest
```

### CLI

```bash
go install github.com/ghettovoice/abnf/cmd/abnf@latest
```

## Quick Start

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
    nodes := abnf.NewNodes()
    defer nodes.Free()

    input := []byte("abcdcd")
    if err := op(input, 0, nodes); err != nil {
        panic(err)
    }

    best := nodes.Best()
    fmt.Printf("matched: %s (len=%d)\n", best.String(), best.Len())
}
```

## Packages

| Package | Description |
|---------|-------------|
| [`github.com/ghettovoice/abnf`](https://pkg.go.dev/github.com/ghettovoice/abnf) | Core operators, node utilities, and error helpers. |
| [`pkg/abnf_core`](./pkg/abnf_core) | Generated implementation of RFC 5234 Appendix B core rules. |
| [`pkg/abnf_def`](./pkg/abnf_def) | Generated implementation of the main ABNF grammar rules. |
| [`pkg/abnf_gen`](./pkg/abnf_gen) | Parser and code generation helpers you can embed in tooling. |
| [`cmd/abnf`](./cmd/abnf) | CLI for generating Go code directly from ABNF files. |

## CLI Overview

The [`abnf` CLI](./cmd/abnf/README.md) scaffolds configs and generates Go code from `.abnf` sources. Typical workflow:

1. Generate a starter config: `abnf config ./grammar.yml`
2. Update the YAML with your grammar files and output options.
3. Run `abnf generate -c ./grammar.yml` to emit ready-to-use Go sources.

## Contributing

Issues and pull requests are welcome. To get started:

```bash
make test
make lint
make bench
```

## License

Distributed under the MIT License. See [LICENSE](./LICENSE) for details.
