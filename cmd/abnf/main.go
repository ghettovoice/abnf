package main

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/ghettovoice/abnf"
	"github.com/ghettovoice/abnf/pkg/abnf_gen"
)

func main() {
	cmd := &cli.Command{
		Name:                  "abnf",
		Usage:                 "generates parsers from ABNF grammar (RFC 5234, RFC 7405)",
		EnableShellCompletion: true,
		Suggest:               true,
		Commands: []*cli.Command{
			{
				Name:    "version",
				Aliases: []string{"ver"},
				Usage:   "shows version information",
				Action:  versionAction,
			},
			{
				Name:    "config",
				Aliases: []string{"conf"},
				Usage:   "generates YML config",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "y",
						Usage: "forces config file overwriting",
					},
				},
				ArgsUsage: "[path]",
				Action:    configAction,
			},
			{
				Name:    "generate",
				Aliases: []string{"gen"},
				Usage:   "generates Go sources from ABNF rules",
				Flags: []cli.Flag{
					// TODO: remove later
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"conf", "c"},
						Usage:   "[DEPRECATED] path to the YML config file. takes abnf.yml in the current directory by default",
					},
					&cli.BoolFlag{
						Name:  "y",
						Usage: "forces output Go file overwriting",
					},
				},
				ArgsUsage: "[path]",
				Action:    generateAction,
			},
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "enables verbose output",
			},
		},
		Authors: []any{
			mail.Address{Name: "Vladimir Vershinin", Address: "ghettovoice@gmail.com"},
		},
	}

	cli.HandleExitCoder(cmd.Run(context.Background(), os.Args))
}

func versionAction(_ context.Context, _ *cli.Command) error {
	fmt.Println("Abnf version:", abnf.VERSION)
	return nil
}

const defaultConfPath = "abnf.yml"

func configAction(_ context.Context, cmd *cli.Command) error {
	wd, err := os.Getwd()
	if err != nil {
		return cli.Exit(fmt.Errorf("get working directory: %w", err), 1) //errtrace:skip
	}

	confPath := defaultConfPath
	if cmd.Args().Len() > 0 {
		if v := strings.TrimSpace(cmd.Args().First()); v != "" {
			confPath = v
		}
	}
	confPath = makePath(confPath, wd)

	if !cmd.Bool("y") {
		if _, err := os.Stat(confPath); err == nil {
			v := "no"
			fmt.Printf("File %s is already exist. Overwrite? (y, N)\n", confPath)
			if _, err := fmt.Scanln(&v); err != nil {
				return cli.Exit(fmt.Errorf("read user input: %w", err), 1) //errtrace:skip
			}

			switch strings.ToLower(v) {
			case "0", "n", "no":
				return cli.Exit(fmt.Errorf("config generation canceled"), 1) //errtrace:skip
			}
		}
	}

	fd, err := os.OpenFile(confPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return cli.Exit(fmt.Errorf("open output file: %w", err), 1) //errtrace:skip
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
# external ABNF rules
external:
    - path: github.com/ghettovoice/abnf/pkg/abnf_core
      name: abnf_core
      rules: [ALPHA, BIT, CHAR, CR, CRLF, CTL, DIGIT, DQUOTE, HEXDIG, HTAB, LF, LWSP, OCTET, SP, VCHAR, WSP]
`,
	))
	if err != nil {
		return cli.Exit(fmt.Errorf("write config file: %w", err), 1) //errtrace:skip
	}

	fmt.Printf("config written to file %s\n", confPath)

	return nil
}

func generateAction(_ context.Context, cmd *cli.Command) error {
	wd, err := os.Getwd()
	if err != nil {
		return cli.Exit(fmt.Errorf("get working directory: %w", err), 1) //errtrace:skip
	}

	// read config
	confPath := defaultConfPath
	if cmd.Args().Len() > 0 {
		if v := strings.TrimSpace(cmd.Args().First()); v != "" {
			confPath = v
		}
	} else if v := cmd.String("config"); len(v) > 0 {
		confPath = v
	}
	confPath = makePath(confPath, wd)

	buf, err := os.ReadFile(confPath)
	if err != nil {
		return cli.Exit(fmt.Errorf("read config file: %w", err), 1) //errtrace:skip
	}

	cfg, err := parseConfig(buf)
	if err != nil {
		return cli.Exit(err, 1) //errtrace:skip
	}

	fmt.Printf("config file %s loaded\n", confPath)

	// setup CodeGenerator
	var errs []error
	g := abnf_gen.CodeGenerator{
		PackageName: cfg.Package,
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
					PackagePath: entry.Path,
					PackageName: entry.Name,
				}

				if cmd.Bool("verbose") {
					fmt.Printf("external rule %s (%s.%s) registered\n", rule, entry.Path, entry.Name)
				}
			}
		}
	}
	if len(errs) > 0 {
		return cli.Exit(errors.Join(errs...), 1) //errtrace:skip
	}

	// read, parse input ABNF files
	errs = errs[:0]
	for _, in := range cfg.Inputs {
		in = makePath(in, filepath.Dir(confPath))
		fd, err := os.Open(in)
		if err != nil {
			errs = append(errs, fmt.Errorf("open ABNF file: %w", err))
			continue
		}

		if _, err = g.ReadFrom(fd); err != nil {
			fd.Close()
			errs = append(errs, fmt.Errorf("parse ABNF file %s: %w", in, err))
			continue
		}

		fd.Close()

		fmt.Printf("ABNF file %s parsed\n", in)
	}
	if len(errs) > 0 {
		return cli.Exit(errors.Join(errs...), 1) //errtrace:skip
	}

	// write Go sources to output file
	outPath := "rules.g.go"
	if cfg.Output != "" {
		outPath = cfg.Output
	}
	outPath = makePath(outPath, filepath.Dir(confPath))

	if !cmd.Bool("y") {
		if _, err := os.Stat(outPath); err == nil {
			v := "no"
			fmt.Printf("File %s is already exist. Overwrite? (y, N)\n", outPath)
			if _, err := fmt.Scanln(&v); err != nil {
				return cli.Exit(fmt.Errorf("read user input: %w", err), 1) //errtrace:skip
			}

			switch strings.ToLower(v) {
			case "0", "n", "no":
				return cli.Exit(fmt.Errorf("code generation canceled"), 1) //errtrace:skip
			}
		}
	}

	fd, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return cli.Exit(fmt.Errorf("open output file: %w", err), 1) //errtrace:skip
	}
	defer fd.Close()

	if _, err := g.WriteTo(fd); err != nil {
		return cli.Exit(fmt.Errorf("write generated code to file %s: %w", outPath, err), 1) //errtrace:skip
	}

	fmt.Printf("generated code written to file %s\n", outPath)

	return nil
}
