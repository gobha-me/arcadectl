// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installfiles

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"golang.org/x/sys/unix"
)

func baselineDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	manifest, payload, err := installbaseline.Build(strings.Repeat("a", 40), 1791500000)
	if err != nil {
		t.Fatal("baseline fixture build failed")
	}
	signature, err := installbaseline.Sign(manifest, fakeKey())
	if err != nil {
		t.Fatal("baseline fixture signing failed")
	}
	for name, body := range map[string][]byte{ManifestName: manifest, SignatureName: signature, BaselinePayloadName: payload} {
		if os.WriteFile(filepath.Join(directory, name), body, 0600) != nil {
			t.Fatal("baseline fixture write failed")
		}
	}
	return directory
}

func TestLoadSeparateSignedBaseline(t *testing.T) {
	directory := baselineDirectory(t)
	verified, err := LoadBaseline(directory, fakeTrust())
	if err != nil || !verified.IsVerified() {
		t.Fatal("exact external-key baseline was refused")
	}
	if _, err := installbaseline.Compile(verified, "isolated-baseline", "kubernetes-1.37.0"); err != nil {
		t.Fatal("authenticated reviewed baseline did not compile")
	}
	if _, err := LoadBaseline(directory, make(ed25519.PublicKey, ed25519.PublicKeySize)); err != installbaseline.ErrSignature {
		t.Fatal("baseline used an untrusted key")
	}
	if _, err := LoadBaseline(directory, nil); err != ErrKey {
		t.Fatal("baseline has no external trust requirement")
	}
	// Neither artifact format may be treated as the other, even using a shared
	// fixture trust key. They have different inventories and signature domains.
	if _, err := Load(directory, fakeTrust()); err == nil {
		t.Fatal("baseline was accepted as a runtime package")
	}
	if _, err := LoadBaseline(packageDirectory(t), fakeTrust()); err == nil {
		t.Fatal("runtime package was accepted as a security baseline")
	}
}

func TestBaselineLoaderRefusesTamperingAndUnexpectedEntries(t *testing.T) {
	for _, name := range []string{ManifestName, SignatureName, BaselinePayloadName, "extra"} {
		t.Run(name, func(t *testing.T) {
			directory := baselineDirectory(t)
			if os.WriteFile(filepath.Join(directory, name), []byte("UNTRUSTED-INPUT-MUST-NOT-ECHO"), 0600) != nil {
				t.Fatal("baseline mutation fixture failed")
			}
			if _, err := LoadBaseline(directory, fakeTrust()); err == nil || strings.Contains(err.Error(), "UNTRUSTED-INPUT-MUST-NOT-ECHO") {
				t.Fatal("tampered bytes were accepted or echoed")
			}
		})
	}
}

func TestBaselineLoaderRefusesLinkedPaths(t *testing.T) {
	for _, name := range []string{ManifestName, SignatureName, BaselinePayloadName} {
		for _, kind := range []string{"symlink", "hardlink"} {
			t.Run(name+"-"+kind, func(t *testing.T) {
				directory := baselineDirectory(t)
				target := filepath.Join(directory, name)
				outside := filepath.Join(t.TempDir(), "original")
				if kind == "symlink" {
					if os.Rename(target, outside) != nil || os.Symlink(outside, target) != nil {
						t.Fatal("symlink fixture failed")
					}
				} else if os.Link(target, outside) != nil {
					t.Fatal("hardlink fixture failed")
				}
				if _, err := LoadBaseline(directory, fakeTrust()); err != ErrUnavailable {
					t.Fatal("linked baseline file was accepted")
				}
			})
		}
	}
	directory := baselineDirectory(t)
	ancestor := filepath.Join(t.TempDir(), "linked")
	if os.Symlink(directory, ancestor) != nil {
		t.Fatal("linked baseline ancestor fixture failed")
	}
	if _, err := LoadBaseline(ancestor, fakeTrust()); err != ErrUnavailable {
		t.Fatal("linked baseline directory was accepted")
	}
	for _, path := range []string{".", "relative", directory + "/../" + filepath.Base(directory), "/"} {
		if _, err := LoadBaseline(path, fakeTrust()); err != ErrUnavailable {
			t.Fatal("unsafe baseline path was accepted")
		}
	}
}

func TestBaselineLoaderRefusesSpecialEmptyAndOversizedFiles(t *testing.T) {
	for _, entry := range []struct {
		name  string
		limit int64
	}{{ManifestName, installbaseline.MaxManifestBytes}, {SignatureName, installbaseline.MaxSignatureBytes}, {BaselinePayloadName, installbaseline.MaxPayloadBytes}} {
		for _, kind := range []string{"fifo", "directory", "empty", "oversized"} {
			t.Run(entry.name+"-"+kind, func(t *testing.T) {
				directory := baselineDirectory(t)
				target := filepath.Join(directory, entry.name)
				if os.Remove(target) != nil {
					t.Fatal("owned baseline entry substitution failed")
				}
				switch kind {
				case "fifo":
					if unix.Mkfifo(target, 0600) != nil {
						t.Fatal("owned FIFO fixture failed")
					}
				case "directory":
					if os.Mkdir(target, 0700) != nil {
						t.Fatal("owned directory fixture failed")
					}
				case "empty":
					if os.WriteFile(target, nil, 0600) != nil {
						t.Fatal("owned empty-file fixture failed")
					}
				case "oversized":
					file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
					if err != nil {
						t.Fatal("owned oversized-file fixture failed")
					}
					truncateErr, closeErr := file.Truncate(entry.limit+1), file.Close()
					if truncateErr != nil || closeErr != nil {
						t.Fatal("owned oversized-file fixture failed")
					}
				}
				start := time.Now()
				if _, err := LoadBaseline(directory, fakeTrust()); err != ErrUnavailable {
					t.Fatal("unsafe baseline entry was accepted")
				}
				if time.Since(start) > 5*time.Second {
					t.Fatal("unsafe baseline read blocked")
				}
			})
		}
	}
}
