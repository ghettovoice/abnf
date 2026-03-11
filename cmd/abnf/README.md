# abnf CLI

`abnf` is a command-line interface for turning `.abnf` grammar files into Go packages. It scaffolds configuration, resolves dependencies, and emits idiomatic Go code that uses the core `github.com/ghettovoice/abnf` operators.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Commands](#commands)
- [Examples](#examples)
- [Generate2 Usage](#generate2-usage)

## Installation

```bash
go install github.com/ghettovoice/abnf/cmd/abnf@latest
```

Upgrade at any time with the same command.

## Quick Start

```bash
# create a starter config next to your grammar files
abnf config ./grammar.yml

# edit grammar.yml to point to your ABNF files and output package

# generate Go sources
abnf generate ./grammar.yml
```

Use `abnf -h` to see global flags and `abnf help <command>` for command-specific options.

## Configuration

The generated YAML config contains the following fields:

| Field | Description |
| ----- | ----------- |
| `inputs` | List of ABNF files to parse (paths are relative to the config file). |
| `package` | Package name for the generated Go code. |
| `output` | Destination Go file path (relative to the config file). |
| `external` | Optional list of external rule providers, each with `path`, `name`, and `rules`. |

## Commands

| Command | Description |
| ------- | ----------- |
| `abnf config [path]` | Writes a starter configuration file. Defaults to `./abnf.yml`. |
| `abnf generate [path]` | Generates Go sources per the configuration. |
| `abnf generate2` | Generates Go sources without YAML config using Go file comments. |
| `abnf version` | Prints the CLI version (mirrors library `VERSION`). |
| `abnf help` | Prints help for a command. |

Global flags include `--verbose` for additional logging and `--y` to skip overwrite prompts.

## Examples

- Core ABNF rules generated with this CLI live in [`pkg/abnf_core`](../../pkg/abnf_core).
- The definition grammar generated with this CLI lives in [`pkg/abnf_def`](../../pkg/abnf_def).

## Generate2 Usage

The `generate2` command eliminates the need for YAML configuration files. Instead,
it uses special comments in your Go source file and automatically includes core ABNF elements.
This functionality was introduced in [GitHub issue #69](https://github.com/ghettovoice/abnf/issues/69).

### Directory Structure

```text
my_grammar
  |- grammar.go
  |- some.abnf
  |- another.abnf
  |- my_grammar_abnf.go  <- generated file
```

### Go File Configuration

Add a `//go:generate` directive and optional external configuration comment to your Go file:

```go
package my_grammar

//go:generate go tool abnf gen2

/*
external:
    - path: github.com/other/abnf/pkg/element
      name: my_abnf_elements
      rules: [FOO, BAR, BAZ]
*/
```

### Usage

```bash
# Generate code using go:generate
go generate

# Or run directly
abnf generate2
```

### Features

- **No YAML config required**: Configuration is embedded in Go file comments
- **Automatic core elements**: Core ABNF rules are included unconditionally
- **Simplified naming**: Generated file follows `xxx_abnf.go` naming convention
- **External rules support**: Optional external rule configuration via comments

The external configuration comment is optional - omit it if you don't need
additional external elements beyond the core ABNF rules.
