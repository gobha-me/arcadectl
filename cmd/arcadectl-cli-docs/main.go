// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gobha-me/arcadectl/internal/cligen"
)

func main() {
	directory := flag.String("output", "docs/generated/cli", "Generated output directory")
	check := flag.Bool("check", false, "Verify generated artifacts without writing")
	flag.Parse()
	files, err := cligen.Files()
	if err != nil {
		fail()
	}
	if !*check {
		if os.MkdirAll(*directory, 0755) != nil {
			fail()
		}
	}
	for name, contents := range files {
		path := filepath.Join(*directory, name)
		if *check {
			actual, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(actual, contents) {
				fail()
			}
		} else {
			if os.WriteFile(path, contents, 0644) != nil {
				fail()
			}
		}
	}
}
func fail() {
	fmt.Fprintln(os.Stderr, "CLI artifacts are unavailable or stale; run make generate-cli")
	os.Exit(1)
}
