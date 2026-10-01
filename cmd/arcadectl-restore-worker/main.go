// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gobha-me/arcadectl/internal/restoreworker"
)

func main() {
	result, err := restoreworker.Run(context.Background(), restoreworker.Config{})
	if err != nil {
		_ = os.WriteFile(restoreworker.DefaultTerminationPath, restoreworker.FailureMessage(err), 0o600)
		_, _ = fmt.Fprintln(os.Stderr, "restore worker failed")
		os.Exit(restoreworker.ExitCode(err))
	}
	message, err := restoreworker.SuccessMessage(result)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "restore worker failed")
		os.Exit(20)
	}
	if err := os.WriteFile(restoreworker.DefaultTerminationPath, message, 0o600); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "restore worker failed")
		os.Exit(20)
	}
}
