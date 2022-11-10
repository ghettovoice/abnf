package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/ghettovoice/abnf/pkg/abnf_gen"
)

var (
	buildHash, buildTime, buildVersion string
)

func main() {
	app := &cli.App{
		Name:  "abnf",
		Usage: "Generates parsers from ABNF grammar (RFC 5234, RFC 7405)",
		Commands: []*cli.Command{
			{
				Name:    "version",
				Aliases: []string{"ver"},
				Usage:   "Shows version information",
				Action:  versionAction,
			},
			{
				Name:    "config",
				Aliases: []string{"conf"},
				Usage:   "Generates YML config",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "y",
						Usage: "Forces config file overwriting",
					},
				},
				ArgsUsage: "[path]",
				Action:    configAction,
			},
			{
				Name:    "generate",
				Aliases: []string{"gen"},
				Usage:   "Generates Go sources from ABNF rules",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"conf", "c"},
						Usage:   "Path to the YML config file. Takes abnf.yml in the current directory by default.",
					},
					&cli.BoolFlag{
						Name:  "y",
						Usage: "Forces output Go file overwriting",
					},
				},
				Action: generateAction,
			},
		},
		EnableBashCompletion: true,
		Suggest:              true,
	}
	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))
	for _, cmd := range app.Commands {
		sort.Sort(cli.FlagsByName(cmd.Flags))
	}

	cli.HandleExitCoder(app.Run(os.Args))
}

func versionAction(_ *cli.Context) error {
	fmt.Println("Build hash:   ", buildHash)
	fmt.Println("Build time:   ", buildTime)
	fmt.Println("Build version:", buildVersion)
	return nil
}

const defaultConfPath = "abnf.yml"

func configAction(ctx *cli.Context) error {
	wd, err := os.Getwd()
	if err != nil {
		return cli.Exit(fmt.Errorf("get working directory: %w", err), 1)
	}

	confPath := defaultConfPath
	if ctx.Args().Len() > 0 {
		if v := strings.TrimSpace(ctx.Args().First()); v != "" {
			confPath = v
		}
	}
	confPath = makePath(confPath, wd)

	if !ctx.Bool("y") {
		if _, err := os.Stat(confPath); err == nil {
			v := "no"
			fmt.Printf("WARN: File %s is already exist. Overwrite? (y, N)\n", confPath)
			fmt.Scanln(&v)

			switch strings.ToLower(v) {
			case "0", "n", "no":
				return cli.Exit(fmt.Errorf("config generation canceled"), 1)
			}
		}
	}

	fd, err := os.OpenFile(confPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return cli.Exit(fmt.Errorf("open output file %s: %w", confPath, err), 1)
	}
	defer fd.Close()

	_, err = fd.Write([]byte(
		`# input ABNF files
inputs:
    - rules.abnf
# output package name
package: rules
# output file path
output: rules.g.go
# on/off operators generation
as_operators: false
# external ABNF rules
external:
    - path: github.com/ghettovoice/abnf/pkg/abnf_core
      name: abnf_core
      is_operators: true
      rules: [ALPHA, BIT, CHAR, CR, CRLF, CTL, DIGIT, DQUOTE, HEXDIG, HTAB, LF, LWSP, OCTET, SP, VCHAR, WSP]
`,
	))
	if err != nil {
		return cli.Exit(fmt.Errorf("write config file %s: %w", confPath, err), 1)
	}

	fmt.Printf("config written to file %s\n", confPath)

	return nil
}

func generateAction(ctx *cli.Context) error {
	wd, err := os.Getwd()
	if err != nil {
		return cli.Exit(fmt.Errorf("get working directory: %w", err), 1)
	}

	// read config
	confPath := defaultConfPath
	if v := ctx.String("config"); len(v) > 0 {
		confPath = v
	}
	confPath = makePath(confPath, wd)

	buf, err := os.ReadFile(confPath)
	if err != nil {
		return cli.Exit(fmt.Errorf("read config file %s: %w", confPath, err), 1)
	}

	cfg, err := parseConfig(buf)
	if err != nil {
		return cli.Exit(err, 1)
	}

	fmt.Printf("config file %s loaded\n", confPath)

	// setup CodeGenerator
	var errs []error
	g := abnf_gen.CodeGenerator{
		PackageName: cfg.Package,
		AsOperators: cfg.AsOperators,
	}
	if len(cfg.External) > 0 {
		g.External = make(map[string]abnf_gen.ExternalRule)
		for i, entry := range cfg.External {
			if entry.Path == "" {
				errs = append(errs, fmt.Errorf("'path' field is missing in external entry %d", i+1))
				continue
			}

			for _, rule := range entry.Rules {
				g.External[rule] = abnf_gen.ExternalRule{
					IsOperator:  entry.IsOperators,
					PackagePath: entry.Path,
					PackageName: entry.Name,
				}

				fmt.Printf("external rule %s (%s.%s) registered\n", rule, entry.Path, entry.Name)
			}
		}
	}
	if len(errs) > 0 {
		return cli.Exit(multiError(errs), 1)
	}

	// read, parse input ABNF files
	errs = errs[:0]
	for _, in := range cfg.Inputs {
		in = makePath(in, filepath.Dir(confPath))
		fd, err := os.Open(in)
		if err != nil {
			errs = append(errs, fmt.Errorf("open ABNF file %s: %w", in, err))
			continue
		}

		if _, err = g.ReadFrom(fd); err != nil {
			fd.Close()
			errs = append(errs, fmt.Errorf("read, parse ABNF file %s: %w", in, err))
			continue
		}

		fd.Close()

		fmt.Printf("ABNF file %s parsed\n", in)
	}
	if len(errs) > 0 {
		return cli.Exit(multiError(errs), 1)
	}

	// write Go sources to output file
	outPath := "rules.g.go"
	if cfg.Output != "" {
		outPath = cfg.Output
	}
	outPath = makePath(outPath, filepath.Dir(confPath))

	if !ctx.Bool("y") {
		if _, err := os.Stat(outPath); err == nil {
			v := "no"
			fmt.Printf("WARN: File %s is already exist. Overwrite? (y, N)\n", outPath)
			fmt.Scanln(&v)

			switch strings.ToLower(v) {
			case "0", "n", "no":
				return cli.Exit(fmt.Errorf("code generation canceled"), 1)
			}
		}
	}

	fd, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return cli.Exit(fmt.Errorf("open output file %s: %w", outPath, err), 1)
	}
	defer fd.Close()

	if _, err := g.WriteTo(fd); err != nil {
		return cli.Exit(fmt.Errorf("write generated code to file %s: %w", outPath, err), 1)
	}

	fmt.Printf("generated code written to file %s\n", outPath)

	return nil
}
