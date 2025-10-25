# abnf CLI

`abnf` is a command-line interface for turning `.abnf` grammar files into Go packages. It scaffolds configuration, resolves dependencies, and emits idiomatic Go code that uses the core `github.com/ghettovoice/abnf` operators.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Commands](#commands)
- [Examples](#examples)

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
abnf generate -c ./grammar.yml
```

Use `abnf -h` to see global flags and `abnf help <command>` for command-specific options.

## Configuration

The generated YAML config contains the following fields:

| Field | Description |
|-------|-------------|
| `inputs` | List of ABNF files to parse (paths are relative to the config file). |
| `package` | Package name for the generated Go code. |
| `output` | Destination Go file path (relative to the config file). |
| `external` | Optional list of external rule providers, each with `path`, `name`, and `rules`. |

## Commands

| Command | Description |
|---------|-------------|
| `abnf config [path]` | Writes a starter configuration file. Defaults to `./abnf.yml`. |
| `abnf generate --config <path>` | Generates Go sources per the configuration. |
| `abnf version` | Prints the CLI version (mirrors library `VERSION`). |
| `abnf help` | Prints help for a command. |

Global flags include `--verbose` for additional logging and `--y` to skip overwrite prompts.

## Examples

- Core ABNF rules generated with this CLI live in [`pkg/abnf_core`](../../pkg/abnf_core).
- The definition grammar generated with this CLI lives in [`pkg/abnf_def`](../../pkg/abnf_def).
