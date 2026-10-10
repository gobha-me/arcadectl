// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package installfiles loads a fixed signed installation package directory.
// Package bytes are untrusted until verified with an externally supplied key.
// No archive extraction, key discovery, cluster access, or resource adoption is
// performed here. Linux descriptor anchoring rejects symlinks and special files.
package installfiles

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"golang.org/x/sys/unix"
)

const (
	ManifestName  = "manifest.json"
	SignatureName = "signature.json"
	maxKeyBytes   = 8192
)

var ErrUnavailable = errors.New("installation package files are unavailable or unsafe")
var ErrKey = errors.New("installation signing or trust key is unavailable or invalid")

// ReadTrustKey accepts exactly one external PKIX Ed25519 public-key PEM block
// from a trusted, non-writable-by-others regular file. No package-provided key
// path, embedded key, or signature fingerprint may establish trust.
func ReadTrustKey(path string) (ed25519.PublicKey, error) {
	body, _, err := privatefs.ReadAbsolute(path, maxKeyBytes, privatefs.TrustedPublic)
	if err != nil {
		return nil, ErrKey
	}
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(pem.EncodeToMemory(block))) {
		return nil, ErrKey
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		return nil, ErrKey
	}
	return slices.Clone(key), nil
}

// ReadSigningKey additionally requires exact private-file protection. It never
// generates a release identity, accepts inline secrets, or prints key contents.
func ReadSigningKey(path string) (ed25519.PrivateKey, error) {
	body, _, err := privatefs.ReadAbsolute(path, maxKeyBytes, privatefs.Private)
	if err != nil {
		return nil, ErrKey
	}
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(pem.EncodeToMemory(block))) {
		return nil, ErrKey
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(key) != ed25519.PrivateKeySize {
		return nil, ErrKey
	}
	return slices.Clone(key), nil
}

// Load refuses any undeclared file, symlink, hard link, directory substitution,
// FIFO, device, oversized file or malformed envelope. Reads use fixed relative
// names under open directory descriptors; no package path is interpreted.
func Load(directory string, trustedKey ed25519.PublicKey) (*installpackage.VerifiedPackage, error) {
	if len(trustedKey) != ed25519.PublicKeySize {
		return nil, ErrKey
	}
	trustedKey = slices.Clone(trustedKey)
	fd, err := openDirectory(directory)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer unix.Close(fd)
	if err := exactEntries(fd, []string{ManifestName, SignatureName, "manifests"}); err != nil {
		return nil, err
	}
	manifest, err := readAt(fd, ManifestName, installpackage.MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	signature, err := readAt(fd, SignatureName, installpackage.MaxSignatureBytes)
	if err != nil {
		return nil, err
	}
	// Verify canonical metadata before opening any payload. It is not yet
	// authenticated, but gives a bounded exact three-file contract.
	if _, err := installpackage.ParseManifest(manifest); err != nil {
		return nil, err
	}
	manifestFD, err := unix.Openat(fd, "manifests", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer unix.Close(manifestFD)
	if err := exactEntries(manifestFD, []string{"anchors.yaml", "api.yaml", "controller.yaml"}); err != nil {
		return nil, err
	}
	payloads := make(map[string][]byte, 3)
	for _, path := range []string{installpackage.AnchorsPath, installpackage.APIPath, installpackage.ControllerPath} {
		body, err := readAt(manifestFD, filepath.Base(path), installpackage.MaxPayloadBytes)
		if err != nil {
			return nil, err
		}
		payloads[path] = body
	}
	return installpackage.Verify(manifest, signature, payloads, trustedKey)
}

// All absolute path components are traversed with O_NOFOLLOW. Package bytes
// need not be private/trusted: authenticity comes only from external-key Verify.
func openDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || len(path) > 4096 {
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
	}
	return fd, nil
}

func exactEntries(fd int, expected []string) error {
	// A separate descriptor anchors the enumeration without transferring the
	// caller's directory handle or sharing its directory-stream position.
	copyFD, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrUnavailable
	}
	file := os.NewFile(uintptr(copyFD), "package-directory")
	defer file.Close()
	entries, err := file.ReadDir(len(expected) + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	if len(entries) != len(expected) {
		return ErrUnavailable
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	want := slices.Clone(expected)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		return ErrUnavailable
	}
	return nil
}

func readAt(fd int, name string, maximum int64) ([]byte, error) {
	fileFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fileFD), "package-file")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fileFD, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Size < 1 || before.Size > maximum {
		return nil, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(body)) > maximum || int64(len(body)) != before.Size || unix.Fstat(fileFD, &after) != nil {
		return nil, ErrUnavailable
	}
	before.Atim = after.Atim
	if before != after {
		return nil, ErrUnavailable
	}
	return body, nil
}
