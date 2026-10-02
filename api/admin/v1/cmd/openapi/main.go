// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0
package main

import (
	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"os"
)

func main() {
	contents, err := adminv1.OpenAPI()
	if err != nil {
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(contents); err != nil {
		os.Exit(1)
	}
}
