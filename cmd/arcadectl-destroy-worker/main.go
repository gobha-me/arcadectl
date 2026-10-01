// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gobha-me/arcadectl/internal/restoreworker"
)

func main() {
	// A destroy worker is repository-only even if its immutable input is
	// accidentally replaced with a restore Populate request.
	contents, readErr := os.ReadFile(restoreworker.DefaultInputPath)
	var stage struct {
		Stage restoreworker.Stage `json:"stage"`
	}
	if readErr != nil || len(contents) == 0 || len(contents) > 1<<20 || json.Unmarshal(contents, &stage) != nil || stage.Stage != restoreworker.StagePreflight {
		_, _ = fmt.Fprintln(os.Stderr, "destroy verification worker failed")
		os.Exit(20)
	}
	result, err := restoreworker.Run(context.Background(), restoreworker.Config{})
	if err != nil {
		_ = os.WriteFile(restoreworker.DefaultTerminationPath, restoreworker.FailureMessage(err), 0o600)
		_, _ = fmt.Fprintln(os.Stderr, "destroy verification worker failed")
		os.Exit(restoreworker.ExitCode(err))
	}
	if result.Stage != restoreworker.StagePreflight {
		_, _ = fmt.Fprintln(os.Stderr, "destroy verification worker failed")
		os.Exit(20)
	}
	message, err := restoreworker.SuccessMessage(result)
	if err != nil || os.WriteFile(restoreworker.DefaultTerminationPath, message, 0o600) != nil {
		_, _ = fmt.Fprintln(os.Stderr, "destroy verification worker failed")
		os.Exit(20)
	}
}
