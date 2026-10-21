// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package admincredential

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPrivateOutputRejectsLinksAndSpecialFilesBeforeClusterEffects(t *testing.T) {
	for _, kind := range []string{"ancestor symlink", "output symlink", "hardlink", "FIFO", "directory", "group writable ancestor", "relative", "unclean"} {
		t.Run(kind, func(t *testing.T) {
			base := privateTestDirectory(t)
			path := filepath.Join(base, "credential.json")
			victim := filepath.Join(base, "untouched.json")
			if err := os.WriteFile(victim, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "ancestor symlink":
				link := filepath.Join(base, "linked")
				if err := os.Symlink(base, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "credential.json")
			case "output symlink":
				if err := os.Symlink(victim, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(victim, path); err != nil {
					t.Fatal(err)
				}
			case "FIFO":
				if err := unix.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "group writable ancestor":
				if err := os.Chmod(base, 0o770); err != nil {
					t.Fatal(err)
				}
				child := filepath.Join(base, "private")
				if err := os.Mkdir(child, 0o700); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(child, "credential.json")
			case "relative":
				path = "credential.json"
			case "unclean":
				path = base + "/./credential.json"
			}
			cluster := &fakeCluster{}
			workflow, _ := NewWithAccess(cluster, Config{Namespace: customNamespace})
			start := time.Now()
			if err := workflow.Initialize(context.Background(), InitializeOptions{OutputPath: path, Now: time.Now().UTC(), Lifetime: time.Hour}); !errors.Is(err, ErrPrivateOutput) {
				t.Fatalf("unsafe output accepted: %v", err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("unsafe file operation blocked")
			}
			if cluster.secret != nil {
				t.Fatal("cluster mutation preceded durable private output")
			}
			contents, err := os.ReadFile(victim)
			if err != nil || string(contents) != "unchanged" {
				t.Fatal("existing data changed")
			}
		})
	}
}

func TestTrustedCAReaderRefusesUnsafePathsAndBoundsWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"ancestor symlink", "CA symlink", "hardlink", "FIFO", "directory", "group writable file", "group writable ancestor", "too large"} {
		t.Run(kind, func(t *testing.T) {
			base := privateTestDirectory(t)
			path := filepath.Join(base, "ca.pem")
			if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "ancestor symlink":
				link := filepath.Join(base, "linked")
				if err := os.Symlink(base, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "ca.pem")
			case "CA symlink":
				link := filepath.Join(base, "linked.pem")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "hardlink":
				link := filepath.Join(base, "linked.pem")
				if err := os.Link(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "FIFO":
				path = filepath.Join(base, "fifo.pem")
				if err := unix.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				path = base
			case "group writable file":
				if err := os.Chmod(path, 0o660); err != nil {
					t.Fatal(err)
				}
			case "group writable ancestor":
				if err := os.Chmod(base, 0o770); err != nil {
					t.Fatal(err)
				}
			case "too large":
				if err := os.WriteFile(path, []byte(strings.Repeat("x", 1024*1024+1)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			start := time.Now()
			if _, err := readBoundedPublicFile(path, 1024*1024); !errors.Is(err, ErrActivationIncomplete) {
				t.Fatalf("unsafe CA accepted: %v", err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("unsafe CA operation blocked")
			}
		})
	}
}
