package main

import "path/filepath"

func makePath(p, rd string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Clean(filepath.Join(rd, p))
}
