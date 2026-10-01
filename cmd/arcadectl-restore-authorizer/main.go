// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gobha-me/arcadectl/internal/restoreauth"
)

func main() {
	if err := restoreauth.Run(context.Background(), restoreauth.Config{}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "restore authority failed")
		os.Exit(restoreauth.ExitCode(err))
	}
}
