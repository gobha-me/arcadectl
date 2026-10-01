// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gobha-me/arcadectl/internal/backupworker"
)

func main() {
	result, err := backupworker.Run(context.Background(), backupworker.Config{})
	if err != nil {
		_ = os.WriteFile(backupworker.DefaultTerminationPath, backupworker.FailureMessage(err), 0o600)
		_, _ = fmt.Fprintln(os.Stderr, "backup worker failed")
		os.Exit(backupworker.ExitCode(err))
	}
	message, err := backupworker.SuccessMessage(result)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "backup worker failed")
		os.Exit(20)
	}
	if err := os.WriteFile(backupworker.DefaultTerminationPath, message, 0o600); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "backup worker failed")
		os.Exit(20)
	}
}
