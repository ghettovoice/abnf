package main

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type config struct {
	Inputs      []string `yaml:"inputs"`
	Package     string   `yaml:"package"`
	Output      string   `yaml:"output"`
	AsOperators bool     `yaml:"as_operators"`
	External    []struct {
		Path        string   `yaml:"path"`
		Name        string   `yaml:"name"`
		IsOperators bool     `yaml:"is_operators"`
		Rules       []string `yaml:"rules"`
	} `yaml:"external"`
}

func parseConfig(raw []byte) (*config, error) {
	var cfg config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Package == "" {
		return nil, fmt.Errorf("config's 'package' field is empty")
	}
	if len(cfg.Inputs) == 0 {
		return nil, fmt.Errorf("config's 'inputs' field is empty")
	}

	return &cfg, nil
}
