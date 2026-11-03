// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var (
	coreAcronymBoundary = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)
	coreCamelBoundary   = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	coreWords           = regexp.MustCompile(`[A-Za-z]+|[0-9]+`)
)

// Split identifiers before folding case: RCONPort is an adapter assumption,
// whereas Configure, UserConfigDir, InClusterConfig and strconv are not.
// Separating digits also bounds port matches and recognizes the 7DTD acronym.
func coreAdapterTerms(source string) []string {
	source = coreAcronymBoundary.ReplaceAllString(source, "$1 $2")
	source = coreCamelBoundary.ReplaceAllString(source, "$1 $2")
	words := coreWords.FindAllString(strings.ToLower(source), -1)
	found := map[string]bool{}
	for i, word := range words {
		switch word {
		case "factorio", "rcon", "sdtd", "sevendays", "34197", "27015", "26900":
			found[word] = true
		}
		if i+1 < len(words) {
			if word == "7" && words[i+1] == "dtd" {
				found["7dtd"] = true
			}
			if word == "seven" && words[i+1] == "days" {
				found["sevendays"] = true
			}
		}
	}
	var terms []string
	for _, term := range []string{"factorio", "rcon", "7dtd", "sdtd", "sevendays", "34197", "27015", "26900"} {
		if found[term] {
			terms = append(terms, term)
		}
	}
	return terms
}

type coreNeutralityScan struct {
	visited  []string
	findings []string
}

func scanCoreNeutrality(root string) (coreNeutralityScan, error) {
	var scan coreNeutralityScan
	for _, tree := range []string{"internal", "cmd", "api"} {
		err := filepath.WalkDir(filepath.Join(root, tree), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if entry.IsDir() {
				// Adapters own game vocabulary; catalog registers those adapters.
				// Only these exact subtrees are allowed, not similar path names.
				if entry.Name() == "testdata" || rel == "internal/games" || rel == "internal/catalog" {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if entry.Type()&fs.ModeSymlink != 0 {
				return fmt.Errorf("production Go source is a symlink: %s", rel)
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, contents, parser.PackageClauseOnly|parser.ParseComments)
			if err != nil {
				return fmt.Errorf("parse production header %s: %w", rel, err)
			}
			if ast.IsGenerated(file) {
				return nil
			}
			scan.visited = append(scan.visited, rel)
			if terms := coreAdapterTerms(string(contents)); len(terms) > 0 {
				scan.findings = append(scan.findings, fmt.Sprintf("%s: %s", rel, strings.Join(terms, ", ")))
			}
			return nil
		})
		if err != nil {
			return scan, fmt.Errorf("scan %s: %w", tree, err)
		}
	}
	return scan, nil
}

func TestCoreNeutrality(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate module root")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	scan, err := scanCoreNeutrality(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range scan.findings {
		t.Errorf("production core contains adapter vocabulary: %s", finding)
	}
	for _, required := range []string{"internal/controller/", "internal/apiserver/", "internal/cli/", "cmd/arcadectl-controller/", "api/admin/v1/"} {
		visited := false
		for _, path := range scan.visited {
			if strings.HasPrefix(path, required) {
				visited = true
			}
		}
		if !visited {
			t.Errorf("no production file visited in %s", required)
		}
	}
}

func TestCoreNeutralityMatcher(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   []string
	}{
		{`legacyRCONPort`, []string{"rcon"}},
		{`"/factorio/saves"`, []string{"factorio"}},
		{`SevenDaysWorld`, []string{"sevendays"}},
		{`"/sdtd/Saves"`, []string{"sdtd"}},
		{`port = 26900`, []string{"26900"}},
		{`7dtd`, []string{"7dtd"}},
		{`legacy7DTDPort`, []string{"7dtd"}},
		{`seven-days`, []string{"sevendays"}},
		{`seven_days`, []string{"sevendays"}},
		{`seven days`, []string{"sevendays"}},
		{`sevendays`, []string{"sevendays"}},
		{`ports = []int{34197,27015}`, []string{"34197", "27015"}},
		{`Configure`, nil},
		{`UserConfigDir`, nil},
		{`InClusterConfig`, nil},
		{`strconv.ParseInt`, nil},
		{`maxVersionDigits = 128`, nil},
		{`1269001`, nil},
		{`341970 1270150`, nil},
		{`factorious rconnection sdtdish sevendayshift`, nil},
	} {
		t.Run(tc.source, func(t *testing.T) {
			if got := coreAdapterTerms(tc.source); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("terms = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCoreNeutralityWalkerBoundaries(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"internal/games/adapter/game.go":    "package adapter\n// factorio\n",
		"internal/catalog/register.go":      "package catalog\n// factorio\n",
		"internal/core/testdata/fixture.go": "package fixture\n// rcon\n",
		"cmd/core/local_test.go":            "package core\n// sdtd\n",
		"api/core/generated.go":             "// Code generated by fixture. DO NOT EDIT.\npackage core\n// 7dtd\n",
		"api/core/readme.txt":               "26900",
		"internal/core/safe.go":             "package core\n// Configure\n",
		"internal/gamesake/leak.go":         "package gamesake\n// factorio\n",
		"internal/catalogue/leak.go":        "package catalogue\n// rcon\n",
		"cmd/adapter/leak.go":               "package adapter\n// sdtd\n",
		"api/core/leak.go":                  "package core\n// seven-days\n",
		"api/core/fake_generated.go":        "package core\n// Code generated by fixture. DO NOT EDIT.\n// 26900\n",
	}
	for path, contents := range files {
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scan, err := scanCoreNeutrality(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/catalogue/leak.go: rcon",
		"internal/gamesake/leak.go: factorio",
		"cmd/adapter/leak.go: sdtd",
		"api/core/fake_generated.go: 26900",
		"api/core/leak.go: sevendays",
	}
	if !reflect.DeepEqual(scan.findings, want) {
		t.Fatalf("findings = %v, want %v", scan.findings, want)
	}
	if len(scan.visited) != 6 {
		t.Fatalf("visited %v, want exactly 6 production files", scan.visited)
	}
}

func TestCoreNeutralityWalkerRefusesMissingRoot(t *testing.T) {
	if _, err := scanCoreNeutrality(t.TempDir()); err == nil {
		t.Fatal("missing production roots accepted")
	}
}

func TestCoreNeutralityWalkerRefusesSourceSymlinks(t *testing.T) {
	root := t.TempDir()
	for _, tree := range []string{"internal", "cmd", "api"} {
		if err := os.Mkdir(filepath.Join(root, tree), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside.go")
	if err := os.WriteFile(outside, []byte("package outside\n// factorio\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "internal", "escape.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := scanCoreNeutrality(root); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("source symlink was not refused: %v", err)
	}
}
