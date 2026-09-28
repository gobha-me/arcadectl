// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gobha-me/arcadectl/internal/backupauth"
)

func main() {
	if err := backupauth.Run(context.Background(), backupauth.Config{}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "backup authority failed")
		os.Exit(backupauth.ExitCode(err))
	}
}
