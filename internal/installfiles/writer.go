// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installfiles

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"golang.org/x/sys/unix"
)

var (
	ErrExists         = errors.New("installation package output already exists")
	ErrOutcomeUnknown = errors.New("installation package publication or durability is unconfirmed; preserve and verify existing output before retrying")
	outputName        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

type writeOperations struct {
	syncDir func(int) error
	rename  func(int, string, int, string, uint) error
}

// Write authenticates the exact bytes with the explicitly supplied external
// trust key before creating anything. Output is a new directory with the fixed
// entry set; existing paths are never replaced. The existing parent must be
// euid-owned, exact 0700, and reached through trusted non-symlink ancestors.
// Private staging and RENAME_NOREPLACE prevent a partial package appearing at
// the requested output. ErrOutcomeUnknown never means nothing changed: retain
// and inspect the requested output and private staging before another attempt.
func Write(directory string, manifest, signature []byte, payloads map[string][]byte, trustedKey ed25519.PublicKey) error {
	return writePackage(directory, manifest, signature, payloads, trustedKey, writeOperations{unix.Fsync, unix.Renameat2})
}

func writePackage(directory string, manifest, signature []byte, payloads map[string][]byte, trustedKey ed25519.PublicKey, ops writeOperations) (result error) {
	signature = append([]byte(nil), signature...)
	trustedKey = append(ed25519.PublicKey(nil), trustedKey...)
	pkg, err := installpackage.Verify(manifest, signature, payloads, trustedKey)
	if err != nil {
		return err
	}
	// The authenticated snapshot, not mutable caller slices, is written.
	manifest, _ = pkg.ManifestBytes()
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || len(directory) > 4096 || !outputName.MatchString(filepath.Base(directory)) {
		return ErrUnavailable
	}
	parent, err := openOutputParent(filepath.Dir(directory))
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	var parentIdentity unix.Stat_t
	if unix.Fstat(parent, &parentIdentity) != nil {
		return ErrUnavailable
	}
	name := filepath.Base(directory)
	var st unix.Stat_t
	if err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return ErrExists
	} else if err != unix.ENOENT {
		return ErrUnavailable
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return ErrUnavailable
	}
	stage := ".arcadectl-package-" + hex.EncodeToString(random)
	if unix.Mkdirat(parent, stage, 0700) != nil {
		return ErrUnavailable
	}
	stageFD, err := unix.Openat(parent, stage, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		// No anchored staging handle: do not guess which path to delete.
		return ErrOutcomeUnknown
	}
	defer unix.Close(stageFD)
	var identity unix.Stat_t
	if unix.Fchmod(stageFD, 0700) != nil || unix.Fstat(stageFD, &identity) != nil || !privateDirectory(&identity) {
		return ErrOutcomeUnknown
	}
	preserve := false
	owned := stageContents{files: make(map[string]unix.Stat_t)}
	defer func() {
		if !preserve && !cleanStage(parent, stage, stageFD, identity, owned) {
			result = ErrOutcomeUnknown
		}
	}()
	if unix.Mkdirat(stageFD, "manifests", 0700) != nil {
		return ErrUnavailable
	}
	payloadFD, err := unix.Openat(stageFD, "manifests", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrUnavailable
	}
	defer unix.Close(payloadFD)
	if unix.Fchmod(payloadFD, 0700) != nil {
		return ErrUnavailable
	}
	if unix.Fstat(payloadFD, &owned.payloadDirectory) != nil || !privateDirectory(&owned.payloadDirectory) {
		return ErrUnavailable
	}
	for _, path := range []string{installpackage.AnchorsPath, installpackage.APIPath, installpackage.ControllerPath} {
		body, _ := pkg.Payload(path)
		id, err := writeNewFile(payloadFD, filepath.Base(path), body)
		if id.Ino != 0 {
			owned.files[path] = id
		}
		if err != nil {
			return ErrUnavailable
		}
	}
	for _, entry := range []struct {
		name string
		body []byte
	}{{ManifestName, manifest}, {SignatureName, signature}} {
		id, err := writeNewFile(stageFD, entry.name, entry.body)
		if id.Ino != 0 {
			owned.files[entry.name] = id
		}
		if err != nil {
			return ErrUnavailable
		}
	}
	if exactEntries(payloadFD, []string{"anchors.yaml", "api.yaml", "controller.yaml"}) != nil || exactEntries(stageFD, []string{ManifestName, SignatureName, "manifests"}) != nil {
		return ErrUnavailable
	}
	if ops.syncDir(payloadFD) != nil || ops.syncDir(stageFD) != nil {
		return ErrUnavailable
	}
	// Correlate the source name to the actual staging directory before rename.
	var observed unix.Stat_t
	if unix.Fstatat(parent, stage, &observed, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameDirectory(observed, identity) {
		preserve = true
		return ErrOutcomeUnknown
	}
	if err := ops.rename(parent, stage, parent, name, unix.RENAME_NOREPLACE); err != nil {
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
	// A descriptor anchors safe writes even if an ancestor is renamed. Do not
	// claim publication at the requested path unless its parent still matches.
	currentParent, err := openOutputParent(filepath.Dir(directory))
	if err != nil {
		return ErrOutcomeUnknown
	}
	defer unix.Close(currentParent)
	if unix.Fstat(currentParent, &observed) != nil || observed.Dev != parentIdentity.Dev || observed.Ino != parentIdentity.Ino {
		return ErrOutcomeUnknown
	}
	if !authenticatedStage(stageFD, owned, trustedKey) {
		return ErrOutcomeUnknown
	}
	return nil
}

// Read and authenticate through the actual published directory descriptor, not
// a reconstructed path. Retain substituted output on any failure; verification
// of inputs before publication is not evidence of output integrity afterwards.
func authenticatedStage(stage int, owned stageContents, trust ed25519.PublicKey) bool {
	if exactEntries(stage, []string{ManifestName, SignatureName, "manifests"}) != nil {
		return false
	}
	payload, err := unix.Openat(stage, "manifests", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(payload)
	var st unix.Stat_t
	if unix.Fstat(payload, &st) != nil || !sameDirectory(st, owned.payloadDirectory) || exactEntries(payload, []string{"anchors.yaml", "api.yaml", "controller.yaml"}) != nil {
		return false
	}
	bodies := make(map[string][]byte, 5)
	for _, path := range []string{ManifestName, SignatureName, installpackage.AnchorsPath, installpackage.APIPath, installpackage.ControllerPath} {
		fd, base, limit := stage, path, int64(installpackage.MaxManifestBytes)
		if path == SignatureName {
			limit = installpackage.MaxSignatureBytes
		}
		if strings.HasPrefix(path, "manifests/") {
			fd, base, limit = payload, filepath.Base(path), installpackage.MaxPayloadBytes
		}
		expected, exists := owned.files[path]
		if !exists || !sameFile(fd, base, expected) {
			return false
		}
		body, err := readAt(fd, base, limit)
		if err != nil || !sameFile(fd, base, expected) {
			return false
		}
		bodies[path] = body
	}
	_, err = installpackage.Verify(bodies[ManifestName], bodies[SignatureName], map[string][]byte{installpackage.AnchorsPath: bodies[installpackage.AnchorsPath], installpackage.APIPath: bodies[installpackage.APIPath], installpackage.ControllerPath: bodies[installpackage.ControllerPath]}, trust)
	return err == nil
}

func privateDirectory(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == uint32(os.Geteuid()) && st.Mode&07777 == 0700 && st.Nlink != 0
}

func openOutputParent(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, ErrUnavailable
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrUnavailable
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, ErrUnavailable
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)) {
			unix.Close(fd)
			return -1, ErrUnavailable
		}
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !privateDirectory(&st) {
		unix.Close(fd)
		return -1, ErrUnavailable
	}
	return fd, nil
}

func writeNewFile(parent int, name string, body []byte) (identity unix.Stat_t, result error) {
	fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return identity, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), "installation-package-file")
	defer func() {
		if unix.Fstat(fd, &identity) != nil {
			identity = unix.Stat_t{}
			result = ErrUnavailable
		}
		if file.Close() != nil {
			result = ErrUnavailable
		}
	}()
	if unix.Fchmod(fd, 0600) != nil {
		return identity, ErrUnavailable
	}
	if n, err := file.Write(body); err != nil || n != len(body) || file.Sync() != nil {
		return identity, ErrUnavailable
	}
	return identity, nil
}

type stageContents struct {
	payloadDirectory unix.Stat_t
	files            map[string]unix.Stat_t
}

func sameDirectory(observed, expected unix.Stat_t) bool {
	return privateDirectory(&observed) && observed.Dev == expected.Dev && observed.Ino == expected.Ino && observed.Uid == expected.Uid && observed.Gid == expected.Gid && observed.Mode == expected.Mode
}

func sameFile(parent int, name string, expected unix.Stat_t) bool {
	var current unix.Stat_t
	if unix.Fstatat(parent, name, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || current.Mode&unix.S_IFMT != unix.S_IFREG || current.Mode&07777 != 0600 || current.Uid != uint32(os.Geteuid()) || current.Nlink != 1 {
		return false
	}
	expected.Atim = current.Atim
	return expected == current
}

// Remove only fixed task-created entries through anchored descriptors, and only
// unlink the staging name if it still names this directory. Never recurse.
func cleanStage(parent int, name string, stage int, identity unix.Stat_t, owned stageContents) bool {
	var st unix.Stat_t
	if unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameDirectory(st, identity) {
		return false
	}
	// Refuse an altered entry set before deleting any candidate byte. Partial
	// task-owned construction is allowed, but foreign entries are not.
	if !onlyEntries(stage, map[string]bool{ManifestName: true, SignatureName: true, "manifests": true}) {
		return false
	}
	payload, err := unix.Openat(stage, "manifests", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		defer unix.Close(payload)
		if unix.Fstat(payload, &st) != nil || !sameDirectory(st, owned.payloadDirectory) {
			return false
		}
		if !onlyEntries(payload, map[string]bool{"anchors.yaml": true, "api.yaml": true, "controller.yaml": true}) {
			return false
		}
	} else if err != unix.ENOENT || owned.payloadDirectory.Ino != 0 {
		return false
	}
	// Correlate EVERY child before the first unlink. Correct names, UID/mode
	// and labels do not establish ownership of replacement files/directories.
	for _, path := range []string{ManifestName, SignatureName, installpackage.AnchorsPath, installpackage.APIPath, installpackage.ControllerPath} {
		fd, base := stage, path
		if strings.HasPrefix(path, "manifests/") {
			fd, base = payload, filepath.Base(path)
		}
		expected, exists := owned.files[path]
		if !exists {
			if fd < 0 {
				continue
			}
			if err := unix.Fstatat(fd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
				return false
			}
		} else if fd < 0 || !sameFile(fd, base, expected) {
			return false
		}
	}
	for _, path := range []string{ManifestName, SignatureName, installpackage.AnchorsPath, installpackage.APIPath, installpackage.ControllerPath} {
		if expected, exists := owned.files[path]; exists {
			fd, base := stage, path
			if strings.HasPrefix(path, "manifests/") {
				fd, base = payload, filepath.Base(path)
			}
			if !sameFile(fd, base, expected) || unix.Unlinkat(fd, base, 0) != nil {
				return false
			}
		}
	}
	if payload >= 0 {
		if unix.Fstatat(stage, "manifests", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameDirectory(st, owned.payloadDirectory) || unix.Unlinkat(stage, "manifests", unix.AT_REMOVEDIR) != nil {
			return false
		}
	}
	if unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Dev == identity.Dev && st.Ino == identity.Ino {
		return unix.Unlinkat(parent, name, unix.AT_REMOVEDIR) == nil && unix.Fsync(parent) == nil
	}
	return false
}

func onlyEntries(fd int, allowed map[string]bool) bool {
	copyFD, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(copyFD), "installation-staging-directory")
	defer file.Close()
	entries, err := file.ReadDir(len(allowed) + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > len(allowed) {
		return false
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return false
		}
	}
	return true
}
