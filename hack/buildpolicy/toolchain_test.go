// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package buildpolicy

import (
	"bufio"
	"go/version"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Check every builder, including fixtures that do not ship to operators. A
// stale GOTOOLCHAIN=local builder cannot even download this module's inputs.
func TestGoBuildersSupportModuleToolchain(t *testing.T) {
	root := filepath.Join("..", "..")
	module, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	minimum := ""
	for _, line := range strings.Split(string(module), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "go" {
			minimum = "go" + fields[1]
		}
	}
	if !version.IsValid(minimum) {
		t.Fatal("module has no valid minimum Go version")
	}
	builders := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "Dockerfile" && !strings.HasPrefix(entry.Name(), "Dockerfile.") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(strings.NewReader(string(body)))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
				continue
			}
			for _, field := range fields[1:] {
				if !strings.HasPrefix(field, "golang:") {
					continue
				}
				builders++
				candidate := strings.TrimPrefix(field, "golang:")
				candidate = strings.SplitN(strings.SplitN(candidate, "@", 2)[0], "-", 2)[0]
				if !version.IsValid("go"+candidate) || version.Compare("go"+candidate, minimum) < 0 {
					t.Errorf("%s: Go builder must support module minimum %s", path, minimum)
				}
			}
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if builders < 4 {
		t.Fatal("expected shipped and fixture Go builders to be inspected")
	}
}
