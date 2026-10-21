// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installfiles

import (
	"crypto/ed25519"
	"slices"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"golang.org/x/sys/unix"
)

const BaselinePayloadName = "baseline.json"

// LoadBaseline authenticates a separate non-rollback security artifact with an
// external trust key. It uses the same descriptor-anchored, bounded, no-links
// reads as runtime packages but a distinct fixed entry set/signature domain.
// Authentication does not establish policy semantics, ownership or permission
// to mutate a cluster; callers must independently Compile the selected scope.
func LoadBaseline(directory string, trustedKey ed25519.PublicKey) (*installbaseline.Verified, error) {
	if len(trustedKey) != ed25519.PublicKeySize {
		return nil, ErrKey
	}
	trustedKey = slices.Clone(trustedKey)
	fd, err := openDirectory(directory)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer unix.Close(fd)
	if err := exactEntries(fd, []string{ManifestName, SignatureName, BaselinePayloadName}); err != nil {
		return nil, err
	}
	manifest, err := readAt(fd, ManifestName, installbaseline.MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	if _, err := installbaseline.ParseManifest(manifest); err != nil {
		return nil, err
	}
	signature, err := readAt(fd, SignatureName, installbaseline.MaxSignatureBytes)
	if err != nil {
		return nil, err
	}
	payload, err := readAt(fd, BaselinePayloadName, installbaseline.MaxPayloadBytes)
	if err != nil {
		return nil, err
	}
	return installbaseline.Verify(manifest, signature, payload, trustedKey)
}
