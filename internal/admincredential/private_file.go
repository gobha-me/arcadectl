// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package admincredential

import (
	"errors"
	"path/filepath"

	"github.com/gobha-me/arcadectl/internal/privatefs"
)

var ErrPrivateOutput = errors.New("private credential output failed")

// The output must be durably created before a cluster mutation. Every path
// ancestor is descriptor-anchored without symlinks, the existing parent is
// exactly 0700, and the file is exclusively created with mode 0600. Unknown
// durability never authorizes a mutation or deletion of private output.
func writePrivateFile(path string, contents []byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrPrivateOutput
	}
	store, err := privatefs.Open(filepath.Dir(path), false)
	if err != nil {
		return ErrPrivateOutput
	}
	defer store.Close()
	if _, err := store.CreateExclusive(filepath.Base(path), contents); err != nil {
		return ErrPrivateOutput
	}
	return nil
}
