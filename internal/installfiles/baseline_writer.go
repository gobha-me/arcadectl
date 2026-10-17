// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installfiles

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"golang.org/x/sys/unix"
)

// WriteBaseline authenticates a separate security artifact before any write.
// Its flat closed inventory never shares a runtime package's staging directory
// or publication identity. Existing output is never replaced. Publication uses
// the runtime writer's descriptor/ownership/no-links/durability protections.
func WriteBaseline(directory string, manifest, signature, payload []byte, trust ed25519.PublicKey) error {
	return writeBaseline(directory, manifest, signature, payload, trust, writeOperations{unix.Fsync, unix.Renameat2})
}

func writeBaseline(directory string, manifest, signature, payload []byte, trust ed25519.PublicKey, ops writeOperations) (result error) {
	// Reject lengths before copying any caller-provided buffer. The exported
	// writer is a separate boundary from the already-bounded file loader.
	if len(trust) != ed25519.PublicKeySize || len(signature) == 0 || len(signature) > installbaseline.MaxSignatureBytes {
		return installbaseline.ErrSignature
	}
	if len(manifest) == 0 || len(manifest) > installbaseline.MaxManifestBytes || len(payload) == 0 || len(payload) > installbaseline.MaxPayloadBytes {
		return installbaseline.ErrInvalid
	}
	signature, trust = bytes.Clone(signature), bytes.Clone(trust)
	verified, err := installbaseline.Verify(manifest, signature, payload, trust)
	if err != nil {
		return err
	}
	manifest, _ = verified.ManifestBytes()
	payload, _ = verified.Payload()
	// Authentication is distinct from the closed reviewed semantics. Never
	// publish an authenticated arbitrary policy under the baseline command.
	metadata, _ := verified.Manifest()
	for _, profile := range metadata.Profiles {
		if _, err := installbaseline.Compile(verified, "arcadectl-system", profile); err != nil {
			return err
		}
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || len(directory) > 4096 || !outputName.MatchString(filepath.Base(directory)) {
		return ErrUnavailable
	}
	parent, err := openOutputParent(filepath.Dir(directory))
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	var parentIdentity, observed unix.Stat_t
	if unix.Fstat(parent, &parentIdentity) != nil {
		return ErrUnavailable
	}
	name := filepath.Base(directory)
	if err := unix.Fstatat(parent, name, &observed, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return ErrExists
	} else if err != unix.ENOENT {
		return ErrUnavailable
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return ErrUnavailable
	}
	stageName := ".arcadectl-baseline-" + hex.EncodeToString(random)
	if unix.Mkdirat(parent, stageName, 0700) != nil {
		return ErrUnavailable
	}
	stage, err := unix.Openat(parent, stageName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrOutcomeUnknown
	}
	defer unix.Close(stage)
	var identity unix.Stat_t
	if unix.Fchmod(stage, 0700) != nil || unix.Fstat(stage, &identity) != nil || !privateDirectory(&identity) {
		return ErrOutcomeUnknown
	}
	owned := make(map[string]unix.Stat_t, 3)
	preserve := false
	defer func() {
		if !preserve && !cleanBaselineStage(parent, stageName, stage, identity, owned) {
			result = ErrOutcomeUnknown
		}
	}()
	for _, entry := range []struct {
		name string
		body []byte
	}{{ManifestName, manifest}, {SignatureName, signature}, {BaselinePayloadName, payload}} {
		id, err := writeNewFile(stage, entry.name, entry.body)
		if id.Ino != 0 {
			owned[entry.name] = id
		}
		if err != nil {
			return ErrUnavailable
		}
	}
	if !authenticatedBaselineStage(stage, owned, trust) || ops.syncDir(stage) != nil {
		return ErrUnavailable
	}
	if unix.Fstatat(parent, stageName, &observed, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameDirectory(observed, identity) {
		preserve = true
		return ErrOutcomeUnknown
	}
	if err := ops.rename(parent, stageName, parent, name, unix.RENAME_NOREPLACE); err != nil {
		if err == unix.EEXIST {
			return ErrExists
		}
		preserve = true
		return ErrOutcomeUnknown
	}
	preserve = true
	if ops.syncDir(parent) != nil || unix.Fstatat(parent, name, &observed, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameDirectory(observed, identity) {
		return ErrOutcomeUnknown
	}
	currentParent, err := openOutputParent(filepath.Dir(directory))
	if err != nil {
		return ErrOutcomeUnknown
	}
	defer unix.Close(currentParent)
	if unix.Fstat(currentParent, &observed) != nil || observed.Dev != parentIdentity.Dev || observed.Ino != parentIdentity.Ino || !authenticatedBaselineStage(stage, owned, trust) {
		return ErrOutcomeUnknown
	}
	return nil
}

func authenticatedBaselineStage(stage int, owned map[string]unix.Stat_t, trust ed25519.PublicKey) bool {
	if exactEntries(stage, []string{ManifestName, SignatureName, BaselinePayloadName}) != nil || len(owned) != 3 {
		return false
	}
	bodies := make(map[string][]byte, 3)
	for _, entry := range []struct {
		name  string
		limit int64
	}{{ManifestName, installbaseline.MaxManifestBytes}, {SignatureName, installbaseline.MaxSignatureBytes}, {BaselinePayloadName, installbaseline.MaxPayloadBytes}} {
		expected, exists := owned[entry.name]
		if !exists || !sameFile(stage, entry.name, expected) {
			return false
		}
		body, err := readAt(stage, entry.name, entry.limit)
		if err != nil || !sameFile(stage, entry.name, expected) {
			return false
		}
		bodies[entry.name] = body
	}
	_, err := installbaseline.Verify(bodies[ManifestName], bodies[SignatureName], bodies[BaselinePayloadName], trust)
	return err == nil
}

// Only unlink exact task-created files after checking the entire closed entry
// set and every original inode. Unknown publication keeps all evidence intact.
func cleanBaselineStage(parent int, name string, stage int, identity unix.Stat_t, owned map[string]unix.Stat_t) bool {
	var observed unix.Stat_t
	if unix.Fstatat(parent, name, &observed, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameDirectory(observed, identity) || !onlyEntries(stage, map[string]bool{ManifestName: true, SignatureName: true, BaselinePayloadName: true}) {
		return false
	}
	for _, entry := range []string{ManifestName, SignatureName, BaselinePayloadName} {
		if expected, exists := owned[entry]; exists {
			if !sameFile(stage, entry, expected) {
				return false
			}
		} else if unix.Fstatat(stage, entry, &observed, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
			return false
		}
	}
	for _, entry := range []string{ManifestName, SignatureName, BaselinePayloadName} {
		if expected, exists := owned[entry]; exists && (!sameFile(stage, entry, expected) || unix.Unlinkat(stage, entry, 0) != nil) {
			return false
		}
	}
	return unix.Fstatat(parent, name, &observed, unix.AT_SYMLINK_NOFOLLOW) == nil && sameDirectory(observed, identity) && unix.Unlinkat(parent, name, unix.AT_REMOVEDIR) == nil && unix.Fsync(parent) == nil
}
