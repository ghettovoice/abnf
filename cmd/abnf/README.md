# abnf CLI tool

`abnf` provides Go code generation from ABNF files.

## Install

```bash
go install github.com/ghettovoice/abnf/cmd/abnf@latest
```

## Usage

Read help about available commands and their arguments:

```bash
abnf -h
abnf help [command]
```

First we need to generate basic config:

```bash
abnf config ./config.yaml
```

Then update config options:

- `inputs`: list of ABNF files to parse relative to the config file location
- `package`: name of the generated package
- `output`: path to the generated Go file relative to the config file location
- `as_operators`: whether to generate operators instead of factories
- `external`: list of external ABNF rules used in inputs. Each external rule has the following fields:
  - `path`: Go package import path
  - `name`: Go package name
  - `is_operators`: whether the package contains operators or factories
  - `rules`: list of ABNF rule names, i.e. function names

Now with the config file ready, we can generate the code:

```bash
abnf generate ./config.yaml
```

As example of config file and generated code, check [abnf_core](https://github.com/ghettovoice/abnf/tree/master/pkg/abnf_core) and [abnf_def](https://github.com/ghettovoice/abnf/tree/master/pkg/abnf_def) directories.
