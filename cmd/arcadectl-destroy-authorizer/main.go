// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gobha-me/arcadectl/internal/destroyauth"
)

func main() {
	if err := destroyauth.Run(context.Background(), destroyauth.Config{}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "destroy authority failed")
		os.Exit(destroyauth.ExitCode(err))
	}
}
