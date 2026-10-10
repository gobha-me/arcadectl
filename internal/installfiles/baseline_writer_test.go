// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installfiles

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"golang.org/x/sys/unix"
)

func baselineWriteFixture(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	manifest, payload, err := installbaseline.Build(strings.Repeat("a", 40), 1791500000)
	if err != nil {
		t.Fatal("reviewed baseline fixture unavailable")
	}
	signature, err := installbaseline.Sign(manifest, fakeKey())
	if err != nil {
		t.Fatal("baseline signing fixture unavailable")
	}
	return manifest, signature, payload
}

func TestWriteBaselineAuthenticatedReproducibleAndSeparate(t *testing.T) {
	manifest, signature, payload := baselineWriteFixture(t)
	parent := outputParent(t)
	first, second := filepath.Join(parent, "first"), filepath.Join(parent, "second")
	for _, directory := range []string{first, second} {
		if WriteBaseline(directory, manifest, signature, payload, fakeTrust()) != nil {
			t.Fatal("separate baseline publication refused")
		}
		verified, err := LoadBaseline(directory, fakeTrust())
		if err != nil || !verified.IsVerified() {
			t.Fatal("published baseline did not authenticate")
		}
		if _, err := Load(directory, fakeTrust()); err == nil {
			t.Fatal("baseline became a runtime package")
		}
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 3 {
			t.Fatal("baseline fixed inventory changed")
		}
		for _, name := range []string{"", ManifestName, SignatureName, BaselinePayloadName} {
			stat, err := os.Lstat(filepath.Join(directory, name))
			want := os.FileMode(0600)
			if name == "" {
				want = 0700
			}
			if err != nil || stat.Mode().Perm() != want {
				t.Fatal("baseline publication is not private")
			}
		}
	}
	for _, name := range []string{ManifestName, SignatureName, BaselinePayloadName} {
		a, errA := os.ReadFile(filepath.Join(first, name))
		b, errB := os.ReadFile(filepath.Join(second, name))
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			t.Fatal("baseline publication changed deterministic bytes")
		}
	}
	if WriteBaseline(first, manifest, signature, payload, fakeTrust()) != ErrExists {
		t.Fatal("baseline publication replaced existing output")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 2 {
		t.Fatal("successful publication or definite refusal leaked staging")
	}
}

func TestWriteBaselineBoundsBeforeAllocationAndEffects(t *testing.T) {
	manifest, signature, payload := baselineWriteFixture(t)
	for _, field := range []string{"manifest", "signature", "payload", "trust"} {
		t.Run(field, func(t *testing.T) {
			m, s, p, trust := manifest, signature, payload, fakeTrust()
			want := installbaseline.ErrInvalid
			switch field {
			case "manifest":
				m = make([]byte, installbaseline.MaxManifestBytes+1)
			case "signature":
				s = make([]byte, installbaseline.MaxSignatureBytes+1)
				want = installbaseline.ErrSignature
			case "payload":
				p = make([]byte, installbaseline.MaxPayloadBytes+1)
			case "trust":
				trust = make(ed25519.PublicKey, installbaseline.MaxPayloadBytes+1)
				want = installbaseline.ErrSignature
			}
			parent := outputParent(t)
			target := filepath.Join(parent, "candidate")
			var result error
			allocations := testing.AllocsPerRun(10, func() { result = WriteBaseline(target, m, s, p, trust) })
			entries, err := os.ReadDir(parent)
			if result != want || allocations != 0 || err != nil || len(entries) != 0 {
				t.Fatal("over-limit writer input allocated or produced effects", allocations)
			}
		})
	}
	for _, field := range []string{"manifest", "signature", "payload", "trust"} {
		t.Run("tamper-"+field, func(t *testing.T) {
			m, s, p, trust := bytes.Clone(manifest), bytes.Clone(signature), bytes.Clone(payload), bytes.Clone(fakeTrust())
			switch field {
			case "manifest":
				m[len(m)-1] ^= 1
			case "signature":
				s[len(s)-1] ^= 1
			case "payload":
				p[len(p)-1] ^= 1
			case "trust":
				trust[0] ^= 1
			}
			parent := outputParent(t)
			if WriteBaseline(filepath.Join(parent, "candidate"), m, s, p, trust) == nil {
				t.Fatal("writer accepted unauthenticated bytes")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatal("authentication failure caused filesystem effects")
			}
		})
	}
}

func TestWriteBaselineNoReplacementAndUnknownOutcomePreservation(t *testing.T) {
	for _, fault := range []string{"collision", "stage-fsync", "rename-unknown", "rename-committed-error", "parent-fsync", "substituted-output", "foreign-staging-entry"} {
		t.Run(fault, func(t *testing.T) {
			manifest, signature, payload := baselineWriteFixture(t)
			parent := outputParent(t)
			target := filepath.Join(parent, "candidate")
			ops := writeOperations{unix.Fsync, unix.Renameat2}
			calls := 0
			ops.syncDir = func(fd int) error {
				calls++
				if fault == "stage-fsync" && calls == 1 || fault == "parent-fsync" && calls == 2 {
					return unix.EIO
				}
				if fault == "foreign-staging-entry" && calls == 1 {
					_, err := writeNewFile(fd, "foreign", []byte("FOREIGN-PRESERVE"))
					if err != nil {
						t.Error("foreign staging fixture unavailable")
					}
					return unix.EIO
				}
				return unix.Fsync(fd)
			}
			ops.rename = func(old int, oldName string, next int, nextName string, flags uint) error {
				if flags != unix.RENAME_NOREPLACE {
					t.Fatal("baseline publication can replace output")
				}
				if fault == "collision" {
					if os.WriteFile(target, []byte("FOREIGN-PRESERVE"), 0600) != nil {
						t.Fatal("collision fixture unavailable")
					}
				} else if fault == "rename-unknown" {
					return unix.EIO
				}
				err := unix.Renameat2(old, oldName, next, nextName, flags)
				if err != nil {
					return err
				}
				if fault == "rename-committed-error" {
					return unix.EIO
				}
				if fault == "substituted-output" && os.WriteFile(filepath.Join(target, BaselinePayloadName), []byte("FOREIGN-PRESERVE"), 0600) != nil {
					t.Fatal("substitution fixture unavailable")
				}
				return nil
			}
			err := writeBaseline(target, manifest, signature, payload, fakeTrust(), ops)
			want := ErrOutcomeUnknown
			if fault == "collision" {
				want = ErrExists
			} else if fault == "stage-fsync" {
				want = ErrUnavailable
			}
			if err != want {
				t.Fatal("publication uncertainty changed meaning", err)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || fault == "stage-fsync" && len(entries) != 0 || fault != "stage-fsync" && len(entries) != 1 {
				t.Fatal("publication discarded unknown evidence or leaked definite failure")
			}
			if fault == "collision" {
				body, err := os.ReadFile(target)
				if err != nil || string(body) != "FOREIGN-PRESERVE" {
					t.Fatal("collision modified foreign output")
				}
			}
			if fault == "foreign-staging-entry" {
				body, err := os.ReadFile(filepath.Join(parent, entries[0].Name(), "foreign"))
				if err != nil || string(body) != "FOREIGN-PRESERVE" {
					t.Fatal("cleanup destroyed an unowned staging entry")
				}
			}
		})
	}
}

func TestWriteBaselineRejectsSignedSemanticWeakeningAndDomainCrossover(t *testing.T) {
	for _, change := range []string{"weakened-policy", "reordered-resources", "runtime-signature"} {
		t.Run(change, func(t *testing.T) {
			manifest, signature, payload := baselineWriteFixture(t)
			if change == "runtime-signature" {
				_, signature, _ = writeFixture(t)
			} else {
				var objects []map[string]any
				if json.Unmarshal(payload, &objects) != nil || len(objects) != installbaseline.ResourceCount {
					t.Fatal("reviewed policy fixture unavailable")
				}
				if change == "weakened-policy" {
					objects[0]["spec"].(map[string]any)["failurePolicy"] = "Ignore"
				} else {
					objects[0], objects[1] = objects[1], objects[0]
				}
				raw, err := json.Marshal(objects)
				if err != nil {
					t.Fatal("semantic mutation fixture unavailable")
				}
				payload, err = canonicaljson.CanonicalJSON(raw)
				if err != nil {
					t.Fatal("canonical mutation fixture unavailable")
				}
				metadata, err := installbaseline.ParseManifest(manifest)
				if err != nil {
					t.Fatal("baseline metadata fixture unavailable")
				}
				hash := sha256.Sum256(payload)
				metadata.PayloadSHA256, metadata.PayloadSize = hex.EncodeToString(hash[:]), len(payload)
				raw, err = json.Marshal(metadata)
				if err != nil {
					t.Fatal("mutated metadata fixture unavailable")
				}
				manifest, err = canonicaljson.CanonicalJSON(raw)
				if err != nil {
					t.Fatal("canonical metadata fixture unavailable")
				}
				signature, err = installbaseline.Sign(manifest, fakeKey())
				if err != nil {
					t.Fatal("mutated signature fixture unavailable")
				}
				if _, err := installbaseline.Verify(manifest, signature, payload, fakeTrust()); err != nil {
					t.Fatal("semantic negative fixture was not independently authenticated")
				}
			}
			parent := outputParent(t)
			if WriteBaseline(filepath.Join(parent, "candidate"), manifest, signature, payload, fakeTrust()) == nil {
				t.Fatal("publication treated signing as semantic proof")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatal("semantic/domain refusal produced filesystem effects")
			}
		})
	}
}

func TestWriteBaselineUnsafePathsAndExistingTargetsHaveNoEffects(t *testing.T) {
	for _, kind := range []string{"relative", "unclean", "unsafe-name", "file", "directory", "symlink", "fifo", "linked-parent", "public-parent", "writable-ancestor"} {
		t.Run(kind, func(t *testing.T) {
			manifest, signature, payload := baselineWriteFixture(t)
			parent := outputParent(t)
			target := filepath.Join(parent, "candidate")
			want := ErrUnavailable
			switch kind {
			case "relative":
				target = "candidate"
			case "unclean":
				target = parent + "/../candidate"
			case "unsafe-name":
				target = filepath.Join(parent, "-candidate")
			case "file":
				want = ErrExists
				if os.WriteFile(target, []byte("FOREIGN-PRESERVE"), 0600) != nil {
					t.Fatal("foreign file fixture unavailable")
				}
			case "directory":
				want = ErrExists
				if os.Mkdir(target, 0700) != nil {
					t.Fatal("foreign directory fixture unavailable")
				}
			case "symlink":
				want = ErrExists
				if os.Symlink(filepath.Join(parent, "absent"), target) != nil {
					t.Fatal("foreign symlink fixture unavailable")
				}
			case "fifo":
				want = ErrExists
				if unix.Mkfifo(target, 0600) != nil {
					t.Fatal("foreign FIFO fixture unavailable")
				}
			case "linked-parent":
				link := filepath.Join(outputParent(t), "link")
				if os.Symlink(parent, link) != nil {
					t.Fatal("linked parent fixture unavailable")
				}
				target = filepath.Join(link, "candidate")
			case "public-parent":
				if os.Chmod(parent, 0755) != nil {
					t.Fatal("public parent fixture unavailable")
				}
			case "writable-ancestor":
				if os.Mkdir(filepath.Join(parent, "nested"), 0700) != nil || os.Chmod(parent, 0777) != nil {
					t.Fatal("writable ancestor fixture unavailable")
				}
				target = filepath.Join(parent, "nested", "candidate")
			}
			if err := WriteBaseline(target, manifest, signature, payload, fakeTrust()); err != want {
				t.Fatal("unsafe baseline path was accepted", err)
			}
			if kind == "file" {
				body, err := os.ReadFile(target)
				if err != nil || string(body) != "FOREIGN-PRESERVE" {
					t.Fatal("unsafe-target refusal modified a foreign file")
				}
			}
		})
	}
}
