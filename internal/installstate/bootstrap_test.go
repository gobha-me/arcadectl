// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/gobha-me/arcadectl/internal/privatefs"
)

func privateStore(t *testing.T) *privatefs.Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := privatefs.Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestBootstrapReceiptPrecedesNamespaceEffectsAndPinsUID(t *testing.T) {
	plan := testPlan(t)
	for _, test := range []struct {
		name            string
		fail, committed bool
		want            error
	}{
		{"fresh", false, false, nil},
		{"lost-committed", true, true, nil},
		{"lost-uncommitted", true, false, ErrOutcomeUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			storage := privateStore(t)
			receipt, err := PrepareBootstrap(storage, "installation.json", plan)
			if err != nil {
				t.Fatal(err)
			}
			server := &namespaceServer{failCreate: test.fail, commitOnCreateFailure: test.committed}
			server.beforeCreate = func() {
				body, _, err := storage.Read("installation.json", MaxBytes)
				if err != nil {
					t.Fatal("namespace mutation preceded durable receipt")
				}
				d, err := decodeBootstrap(body, plan)
				if err != nil || !d.CreateAttempted || d.NamespaceUID != "" || d.InstallationID != receipt.document.InstallationID {
					t.Fatal("bootstrap receipt does not identify this candidate")
				}
			}
			namespaces := server.client().CoreV1().Namespaces()
			snapshot, err := receipt.EnsureNamespace(context.Background(), namespaces)
			if !errors.Is(err, test.want) || server.creates != 1 {
				t.Fatalf("bootstrap=%v creates=%d", err, server.creates)
			}
			if test.want != nil {
				if server.updates != 0 {
					t.Fatal("uncertain namespace admitted subsequent mutation")
				}
				if _, err := receipt.EnsureNamespace(context.Background(), namespaces); !errors.Is(err, ErrOutcomeUnknown) || server.creates != 1 {
					t.Fatal("direct retry replayed an uncertain Create")
				}
				loaded, loadErr := LoadBootstrap(storage, "installation.json", plan)
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				if _, err := loaded.EnsureNamespace(context.Background(), namespaces); !errors.Is(err, ErrOutcomeUnknown) || server.creates != 1 {
					t.Fatal("explicit resume replayed an uncertain Create")
				}
				return
			}
			if snapshot.Anchor().UID != "namespace-uid" || snapshot.Document().Revision != 1 || server.updates != 1 {
				t.Fatal("namespace identity was not bound")
			}
			loaded, err := LoadBootstrap(storage, "installation.json", plan)
			if err != nil || loaded.document.NamespaceUID != "namespace-uid" {
				t.Fatal("namespace UID was not durably pinned before binding")
			}
			second, err := loaded.EnsureNamespace(context.Background(), namespaces)
			if err != nil || second.Anchor() != snapshot.Anchor() || server.creates != 1 || server.updates != 1 {
				t.Fatalf("explicit resume replayed a completed effect: %v", err)
			}
			server.live = nil
			if _, err := loaded.EnsureNamespace(context.Background(), namespaces); !errors.Is(err, ErrOwnership) || server.creates != 1 {
				t.Fatal("pinned namespace absence led to recreation")
			}
		})
	}
}

func TestBootstrapRejectsForeignNamespaceReplacementAndLocalChanges(t *testing.T) {
	plan := testPlan(t)
	for _, test := range []string{"foreign-nonce", "weakened-psa", "unexpected-label", "unexpected-annotation", "replaced-uid", "local-file-change"} {
		t.Run(test, func(t *testing.T) {
			storage := privateStore(t)
			receipt, err := PrepareBootstrap(storage, "installation.json", plan)
			if err != nil {
				t.Fatal(err)
			}
			server := &namespaceServer{}
			namespaces := server.client().CoreV1().Namespaces()
			if test == "replaced-uid" || test == "local-file-change" {
				if _, err := receipt.EnsureNamespace(context.Background(), namespaces); err != nil {
					t.Fatal(err)
				}
			} else {
				attempted := receipt.document
				attempted.CreateAttempted = true
				body, err := encodeBootstrap(attempted, plan)
				if err != nil {
					t.Fatal(err)
				}
				identity, err := storage.AtomicWrite("installation.json", body, &receipt.identity)
				if err != nil {
					t.Fatal(err)
				}
				receipt.document, receipt.identity = attempted, identity
				live, _, err := bootstrapNamespace(plan, receipt.document.InstallationID)
				if err != nil {
					t.Fatal(err)
				}
				live.UID, live.ResourceVersion = "namespace-uid", "1"
				server.live = live
			}
			switch test {
			case "foreign-nonce":
				server.live.Annotations[BootstrapAnnotation] = "foreign"
			case "weakened-psa":
				server.live.Labels["pod-security.kubernetes.io/enforce"] = "privileged"
			case "unexpected-label":
				server.live.Labels["foreign"] = "selector"
			case "unexpected-annotation":
				server.live.Annotations["foreign"] = "value"
			case "replaced-uid":
				server.live.UID = "replacement"
			case "local-file-change":
				d := receipt.document
				d.InstallationID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
				body, err := encodeBootstrap(d, plan)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := storage.AtomicWrite("installation.json", body, &receipt.identity); err != nil {
					t.Fatal(err)
				}
			}
			before := server.updates
			_, err = receipt.EnsureNamespace(context.Background(), namespaces)
			want := ErrOwnership
			if test == "local-file-change" {
				want = ErrConflict
			}
			if !errors.Is(err, want) || server.creates != 0 && test != "replaced-uid" && test != "local-file-change" || server.updates != before {
				t.Fatalf("foreign adoption/effect: %v", err)
			}
		})
	}
}

func TestBootstrapInterruptedBindCanResumeWithoutNewCandidate(t *testing.T) {
	plan := testPlan(t)
	storage := privateStore(t)
	receipt, err := PrepareBootstrap(storage, "installation.json", plan)
	if err != nil {
		t.Fatal(err)
	}
	server := &namespaceServer{failUpdate: true}
	namespaces := server.client().CoreV1().Namespaces()
	if _, err := receipt.EnsureNamespace(context.Background(), namespaces); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("unconfirmed bind counted as completed")
	}
	loaded, err := LoadBootstrap(storage, "installation.json", plan)
	if err != nil || loaded.document.NamespaceUID == "" {
		t.Fatal("interrupted bind lost original UID")
	}
	server.failUpdate = false
	snapshot, err := loaded.EnsureNamespace(context.Background(), namespaces)
	if err != nil || snapshot.Anchor().InstallationID != receipt.document.InstallationID || server.creates != 1 || server.updates != 2 {
		t.Fatal("resume changed nonce or replayed namespace creation")
	}
}

func TestBootstrapPrivateReceiptNoOverwriteAndStrictInput(t *testing.T) {
	plan := testPlan(t)
	storage := privateStore(t)
	if _, err := PrepareBootstrap(storage, "installation.json", plan); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareBootstrap(storage, "installation.json", plan); !errors.Is(err, ErrConflict) {
		t.Fatal("private bootstrap evidence overwritten")
	}
	for _, name := range []string{"", "../foreign", ".dot", "name/child"} {
		if _, err := PrepareBootstrap(storage, name, plan); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe receipt name accepted")
		}
	}
	if _, err := PrepareBootstrap(nil, "new.json", plan); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil private store accepted")
	}
	if _, err := (*BootstrapReceipt)(nil).EnsureNamespace(context.Background(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero bootstrap accepted")
	}
}
