// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installfiles

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"golang.org/x/sys/unix"
)

func writeFixture(t *testing.T) ([]byte, []byte, map[string][]byte) {
	t.Helper()
	source := packageDirectory(t)
	manifest, err := os.ReadFile(filepath.Join(source, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := os.ReadFile(filepath.Join(source, SignatureName))
	if err != nil {
		t.Fatal(err)
	}
	payloads := map[string][]byte{}
	for _, path := range []string{installpackage.AnchorsPath, installpackage.APIPath, installpackage.ControllerPath} {
		payloads[path], err = os.ReadFile(filepath.Join(source, path))
		if err != nil {
			t.Fatal(err)
		}
	}
	return manifest, signature, payloads
}

func outputParent(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if os.Chmod(parent, 0700) != nil {
		t.Fatal("protect parent")
	}
	return parent
}

func TestWriteAtomicAuthenticatedPackage(t *testing.T) {
	manifest, signature, payloads := writeFixture(t)
	parent := outputParent(t)
	first, second := filepath.Join(parent, "first"), filepath.Join(parent, "second")
	for _, path := range []string{first, second} {
		if err := Write(path, manifest, signature, payloads, fakeTrust()); err != nil {
			t.Fatal(err)
		}
		pkg, err := Load(path, fakeTrust())
		if err != nil || !pkg.IsVerified() {
			t.Fatal("published package not verified", err)
		}
		for _, name := range []string{"", "manifests", ManifestName, SignatureName, installpackage.AnchorsPath, installpackage.APIPath, installpackage.ControllerPath} {
			st, err := os.Stat(filepath.Join(path, name))
			if err != nil {
				t.Fatal(err)
			}
			want := os.FileMode(0600)
			if st.IsDir() {
				want = 0700
			}
			if st.Mode().Perm() != want {
				t.Fatalf("mode: %s %o", name, st.Mode().Perm())
			}
		}
	}
	for _, name := range []string{ManifestName, SignatureName, installpackage.AnchorsPath, installpackage.APIPath, installpackage.ControllerPath} {
		a, _ := os.ReadFile(filepath.Join(first, name))
		b, _ := os.ReadFile(filepath.Join(second, name))
		if !bytes.Equal(a, b) {
			t.Fatal("package bytes not reproducible")
		}
	}
	if err := Write(first, manifest, signature, payloads, fakeTrust()); !errors.Is(err, ErrExists) {
		t.Fatal("overwrote existing output", err)
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 2 {
		t.Fatal("staging leaked after success or refusal")
	}
}

func TestWriteRefusesUnauthenticatedBytesBeforeEffects(t *testing.T) {
	manifest, signature, payloads := writeFixture(t)
	parent := outputParent(t)
	payloads[installpackage.APIPath] = []byte("SECRET-CANARY")
	err := Write(filepath.Join(parent, "candidate"), manifest, signature, payloads, fakeTrust())
	if err == nil || strings.Contains(err.Error(), "SECRET-CANARY") {
		t.Fatal("unauthenticated bytes accepted or exposed")
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 0 {
		t.Fatal("authentication failure wrote output")
	}
}

func TestWriteRefusesUnsafeTargetsAndAncestors(t *testing.T) {
	manifest, signature, payloads := writeFixture(t)
	for _, kind := range []string{"relative", "unclean", "unsafe-name", "existing-file", "existing-directory", "existing-symlink", "existing-fifo", "parent-symlink", "ancestor-symlink", "public-parent", "writable-ancestor"} {
		t.Run(kind, func(t *testing.T) {
			parent := outputParent(t)
			target := filepath.Join(parent, "candidate")
			switch kind {
			case "relative":
				target = "candidate"
			case "unclean":
				target = parent + "/../candidate"
			case "unsafe-name":
				target = filepath.Join(parent, "-candidate")
			case "existing-file":
				if os.WriteFile(target, []byte("FOREIGN"), 0600) != nil {
					t.Fatal("fixture")
				}
			case "existing-directory":
				if os.Mkdir(target, 0700) != nil {
					t.Fatal("fixture")
				}
			case "existing-symlink":
				if os.Symlink(filepath.Join(parent, "missing"), target) != nil {
					t.Fatal("fixture")
				}
			case "existing-fifo":
				if unix.Mkfifo(target, 0600) != nil {
					t.Fatal("fixture")
				}
			case "parent-symlink", "ancestor-symlink":
				link := filepath.Join(outputParent(t), "link")
				if os.Symlink(parent, link) != nil {
					t.Fatal("fixture")
				}
				if kind == "ancestor-symlink" {
					if os.Mkdir(filepath.Join(parent, "nested"), 0700) != nil {
						t.Fatal("fixture")
					}
					link = filepath.Join(link, "nested")
				}
				target = filepath.Join(link, "candidate")
			case "public-parent":
				if os.Chmod(parent, 0755) != nil {
					t.Fatal("fixture")
				}
			case "writable-ancestor":
				if os.Mkdir(filepath.Join(parent, "nested"), 0700) != nil || os.Chmod(parent, 0777) != nil {
					t.Fatal("fixture")
				}
				target = filepath.Join(parent, "nested", "candidate")
			}
			if err := Write(target, manifest, signature, payloads, fakeTrust()); err == nil {
				t.Fatal("unsafe output accepted")
			}
			if kind == "existing-file" {
				body, _ := os.ReadFile(target)
				if string(body) != "FOREIGN" {
					t.Fatal("foreign output modified")
				}
			}
		})
	}
}

func TestWriteConcurrentTargetCreationNeverOverwrites(t *testing.T) {
	manifest, signature, payloads := writeFixture(t)
	parent := outputParent(t)
	target := filepath.Join(parent, "candidate")
	ops := writeOperations{syncDir: unix.Fsync, rename: func(old int, oldName string, next int, nextName string, flags uint) error {
		if flags != unix.RENAME_NOREPLACE {
			t.Fatal("rename permits replacement")
		}
		if os.WriteFile(target, []byte("FOREIGN"), 0600) != nil {
			t.Fatal("create competing target")
		}
		return unix.Renameat2(old, oldName, next, nextName, flags)
	}}
	if err := writePackage(target, manifest, signature, payloads, fakeTrust(), ops); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(target)
	if string(body) != "FOREIGN" {
		t.Fatal("foreign output replaced")
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 {
		t.Fatal("definite collision staging not removed")
	}
}

func TestWritePreservesUnknownRenameAndDurabilityOutcomes(t *testing.T) {
	for _, mode := range []string{"rename-unconfirmed", "rename-committed-error", "parent-fsync"} {
		t.Run(mode, func(t *testing.T) {
			manifest, signature, payloads := writeFixture(t)
			parent := outputParent(t)
			target := filepath.Join(parent, "candidate")
			ops := writeOperations{unix.Fsync, unix.Renameat2}
			if mode == "parent-fsync" {
				calls := 0
				ops.syncDir = func(fd int) error {
					calls++
					if calls == 3 {
						return unix.EIO
					}
					return unix.Fsync(fd)
				}
			} else {
				ops.rename = func(old int, oldName string, next int, nextName string, flags uint) error {
					if mode == "rename-committed-error" {
						if err := unix.Renameat2(old, oldName, next, nextName, flags); err != nil {
							t.Fatal(err)
						}
					}
					return unix.EIO
				}
			}
			if err := writePackage(target, manifest, signature, payloads, fakeTrust(), ops); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("unknown outcome not preserved", err)
			}
			entries, _ := os.ReadDir(parent)
			if len(entries) != 1 {
				t.Fatal("unconfirmed candidate removed")
			}
			path := filepath.Join(parent, entries[0].Name())
			if _, err := Load(path, fakeTrust()); err != nil {
				t.Fatal("preserved bytes not verifiable", err)
			}
		})
	}
}

func TestWriteParentReplacementDoesNotClaimRequestedPublication(t *testing.T) {
	manifest, signature, payloads := writeFixture(t)
	base := outputParent(t)
	parent := filepath.Join(base, "parent")
	if os.Mkdir(parent, 0700) != nil {
		t.Fatal("parent fixture")
	}
	target := filepath.Join(parent, "candidate")
	ops := writeOperations{unix.Fsync, func(old int, oldName string, next int, nextName string, flags uint) error {
		if os.Rename(parent, filepath.Join(base, "moved")) != nil || os.Mkdir(parent, 0700) != nil {
			t.Fatal("replace parent fixture")
		}
		return unix.Renameat2(old, oldName, next, nextName, flags)
	}}
	if err := writePackage(target, manifest, signature, payloads, fakeTrust(), ops); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("requested path identity not revalidated", err)
	}
	if _, err := Load(filepath.Join(base, "moved", "candidate"), fakeTrust()); err != nil {
		t.Fatal("anchored published package lost", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("replacement parent affected")
	}
}

func TestWritePreservesAlteredStagingInsteadOfGuessingCleanup(t *testing.T) {
	manifest, signature, payloads := writeFixture(t)
	parent := outputParent(t)
	var staging string
	ops := writeOperations{unix.Fsync, func(old int, oldName string, next int, nextName string, flags uint) error {
		staging = filepath.Join(parent, oldName)
		if os.WriteFile(filepath.Join(staging, "foreign"), []byte("FOREIGN"), 0600) != nil {
			t.Fatal("alter staging")
		}
		return unix.EEXIST
	}}
	if err := writePackage(filepath.Join(parent, "candidate"), manifest, signature, payloads, fakeTrust(), ops); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("uncertain cleanup not reported", err)
	}
	for _, path := range []string{ManifestName, SignatureName, installpackage.APIPath, "foreign"} {
		if _, err := os.Stat(filepath.Join(staging, path)); err != nil {
			t.Fatal("altered staging deleted")
		}
	}
}

func TestCollisionCleanupRefusesAnySameNameSubstitution(t *testing.T) {
	for _, kind := range []string{"stage-directory", "payload-directory", "payload-file", "envelope-file", "payload-hardlink", "payload-symlink", "payload-permissions", "payload-in-place"} {
		t.Run(kind, func(t *testing.T) {
			manifest, signature, payloads := writeFixture(t)
			parent := outputParent(t)
			var stage, foreign string
			ops := writeOperations{unix.Fsync, func(old int, oldName string, next int, nextName string, flags uint) error {
				stage = filepath.Join(parent, oldName)
				foreign = filepath.Join(stage, installpackage.APIPath)
				switch kind {
				case "stage-directory":
					if os.Rename(stage, stage+".original") != nil || os.Mkdir(stage, 0700) != nil {
						t.Fatal("stage replacement")
					}
					foreign = filepath.Join(stage, ManifestName)
					if os.WriteFile(foreign, []byte("FOREIGN"), 0600) != nil {
						t.Fatal("foreign stage")
					}
				case "payload-directory":
					path := filepath.Join(stage, "manifests")
					if os.Rename(path, filepath.Join(parent, "original-payload")) != nil || os.Mkdir(path, 0700) != nil || os.WriteFile(foreign, []byte("FOREIGN"), 0600) != nil {
						t.Fatal("payloaddir replacement")
					}
				case "payload-file", "envelope-file":
					if kind == "envelope-file" {
						foreign = filepath.Join(stage, ManifestName)
					}
					if os.Rename(foreign, filepath.Join(parent, "original-file")) != nil || os.WriteFile(foreign, []byte("FOREIGN"), 0600) != nil {
						t.Fatal("file replacement")
					}
				case "payload-hardlink":
					if os.Link(foreign, filepath.Join(parent, "linked")) != nil {
						t.Fatal("hardlink")
					}
				case "payload-symlink":
					if os.Rename(foreign, filepath.Join(parent, "original-file")) != nil || os.Symlink(filepath.Join(parent, "original-file"), foreign) != nil {
						t.Fatal("symlink")
					}
				case "payload-permissions":
					if os.Chmod(foreign, 0644) != nil {
						t.Fatal("chmod")
					}
				case "payload-in-place":
					if os.WriteFile(foreign, []byte("FOREIGN"), 0600) != nil {
						t.Fatal("inplace")
					}
				}
				return unix.EEXIST
			}}
			if err := writePackage(filepath.Join(parent, "candidate"), manifest, signature, payloads, fakeTrust(), ops); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("substituted child not refused", err)
			}
			if _, err := os.Lstat(foreign); err != nil {
				t.Fatal("substituted foreign bytes removed")
			}
			if kind != "stage-directory" {
				for _, name := range []string{ManifestName, SignatureName} {
					if _, err := os.Stat(filepath.Join(stage, name)); err != nil {
						t.Fatal("candidate envelope removed before complete ownership proof")
					}
				}
			}
		})
	}
}

func TestSuccessfulRenameReverifiesPublishedTree(t *testing.T) {
	for _, kind := range []string{"payload-replacement", "extra-entry", "payload-directory", "payload-in-place", "envelope-replacement"} {
		t.Run(kind, func(t *testing.T) {
			manifest, signature, payloads := writeFixture(t)
			parent := outputParent(t)
			target := filepath.Join(parent, "candidate")
			ops := writeOperations{unix.Fsync, func(old int, oldName string, next int, nextName string, flags uint) error {
				stage := filepath.Join(parent, oldName)
				path := filepath.Join(stage, installpackage.APIPath)
				switch kind {
				case "payload-replacement", "envelope-replacement":
					if kind == "envelope-replacement" {
						path = filepath.Join(stage, ManifestName)
					}
					if os.Rename(path, filepath.Join(parent, "original-file")) != nil || os.WriteFile(path, []byte("FOREIGN"), 0600) != nil {
						t.Fatal("replace payload")
					}
				case "extra-entry":
					if os.WriteFile(filepath.Join(stage, "extra"), []byte("FOREIGN"), 0600) != nil {
						t.Fatal("extra entry")
					}
				case "payload-directory":
					path = filepath.Join(stage, "manifests")
					if os.Rename(path, filepath.Join(parent, "original-payload")) != nil || os.Mkdir(path, 0700) != nil {
						t.Fatal("replace payload directory")
					}
				case "payload-in-place":
					if os.WriteFile(path, []byte("FOREIGN"), 0600) != nil {
						t.Fatal("modify payload")
					}
				}
				return unix.Renameat2(old, oldName, next, nextName, flags)
			}}
			if err := writePackage(target, manifest, signature, payloads, fakeTrust(), ops); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("altered publication reported success", err)
			}
			if _, err := os.Stat(target); err != nil {
				t.Fatal("uncertain publication removed")
			}
		})
	}
}
