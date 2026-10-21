// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/privatefs"
)

type cancelBeforeAnchorReturn struct {
	context.Context
	cancel context.CancelFunc
	calls  int
}

func (c *cancelBeforeAnchorReturn) Err() error {
	c.calls++
	if c.calls == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestPinnedAnchorCancellationAfterDurabilityReturnsNoAuthority(t *testing.T) {
	r, _ := pinnedReceiptFixture(t, true)
	body, id, err := r.store.Read(r.name, MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	injected := &cancelBeforeAnchorReturn{Context: ctx, cancel: cancel}
	anchor, err := r.PinnedAnchor(injected)
	if err != ErrOwnership || anchor != (Anchor{}) || injected.calls != 2 {
		t.Fatal("late cancellation returned authority", err)
	}
	after, afterID, err := r.store.Read(r.name, MaxBytes)
	if err != nil || !bytes.Equal(body, after) || id != afterID {
		t.Fatal("late cancellation changed original evidence")
	}
}

// Seed only protected local evidence: no Namespace provider, Create or lock
// file is available to mask accidental effects by the read-only accessor.
func pinnedReceiptFixture(t *testing.T, pinned bool) (*BootstrapReceipt, string) {
	t.Helper()
	base := t.TempDir()
	if os.Chmod(base, 0700) != nil {
		t.Fatal("private receipt fixture unavailable")
	}
	store, err := privatefs.Open(base, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	r, err := PrepareBootstrap(store, "installation.json", testPlan(t))
	if err != nil {
		t.Fatal(err)
	}
	if pinned {
		d := r.document
		d.CreateAttempted, d.NamespaceUID = true, "original-namespace-uid"
		setPinnedReceiptDocument(t, r, d)
	}
	return r, base
}

func setPinnedReceiptDocument(t *testing.T, r *BootstrapReceipt, d bootstrapDocument) {
	t.Helper()
	body, err := encodeBootstrap(d, r.plan)
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.store.AtomicWrite(r.name, body, &r.identity)
	if err != nil {
		t.Fatal(err)
	}
	r.document, r.identity = d, id
}

func TestPinnedAnchorReturnsDurableIdentityWithoutEffects(t *testing.T) {
	r, base := pinnedReceiptFixture(t, true)
	want := Anchor{Namespace: r.document.Namespace, UID: r.document.NamespaceUID, InstallationID: r.document.InstallationID}
	before, id, err := r.store.Read(r.name, MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 1 || entries[0].Name() != r.name {
		t.Fatal("fixture must start with only the original receipt")
	}
	loaded, err := LoadBootstrap(r.store, r.name, r.plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, instance := range []*BootstrapReceipt{r, loaded} {
		anchor, err := instance.PinnedAnchor(context.Background())
		if err != nil || anchor != want {
			t.Fatal("original identity was not proved", err)
		}
	}
	after, afterID, err := r.store.Read(r.name, MaxBytes)
	if err != nil || !bytes.Equal(before, after) || id != afterID {
		t.Fatal("accessor changed protected receipt bytes or inode")
	}
	afterEntries, err := os.ReadDir(base)
	if err != nil || !reflect.DeepEqual(entries, afterEntries) {
		t.Fatal("accessor created a file or replaced local evidence")
	}
}

func TestPinnedAnchorRefusesUnresolvedAndStaleEvidence(t *testing.T) {
	for _, fault := range []string{"unattempted", "attempted", "nil-context", "cancelled", "nil-receiver", "nil-store", "nil-plan", "substituted-plan", "bad-name", "missing", "closed-store", "unsafe-store", "changed-bytes", "replaced-inode", "changed-memory", "malformed"} {
		t.Run(fault, func(t *testing.T) {
			r, base := pinnedReceiptFixture(t, fault != "unattempted" && fault != "attempted")
			ctx := context.Background()
			want := ErrOwnership
			switch fault {
			case "unattempted", "attempted":
				if fault == "attempted" {
					d := r.document
					d.CreateAttempted = true
					setPinnedReceiptDocument(t, r, d)
				}
				want = ErrOutcomeUnknown
			case "nil-context":
				ctx, want = nil, ErrInvalid
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-receiver":
				r, want = nil, ErrInvalid
			case "nil-store":
				r.store, want = nil, ErrInvalid
			case "nil-plan":
				r.plan, want = nil, ErrInvalid
			case "substituted-plan":
				r.plan, want = lifecyclePlan(t, 2), ErrInvalid
			case "bad-name":
				r.name, want = "../PRIVATE-CANARY", ErrInvalid
			case "missing":
				if os.Remove(filepath.Join(base, r.name)) != nil {
					t.Fatal("remove exact fixture receipt")
				}
			case "closed-store":
				if r.store.Close() != nil {
					t.Fatal("close fixture store")
				}
			case "unsafe-store":
				if os.Chmod(base, 0755) != nil {
					t.Fatal("set unsafe fixture directory")
				}
			case "changed-bytes":
				body, _, err := r.store.Read(r.name, MaxBytes)
				if err != nil || os.WriteFile(filepath.Join(base, r.name), append(body, '\n'), 0600) != nil {
					t.Fatal("change exact fixture receipt")
				}
				want = ErrConflict
			case "replaced-inode", "malformed":
				body, _, err := r.store.Read(r.name, MaxBytes)
				if err != nil {
					t.Fatal(err)
				}
				want = ErrConflict
				if fault == "malformed" {
					body, want = []byte(`{"PRIVATE-CANARY":"not a receipt"}`), ErrInvalid
				}
				newID, err := r.store.AtomicWrite(r.name, body, &r.identity)
				if err != nil {
					t.Fatal(err)
				}
				if fault == "malformed" {
					r.identity = newID // force the strict decoder, not stale identity
				}
			case "changed-memory":
				r.document.InstallationID, want = strings.Repeat("e", 32), ErrConflict
			}
			anchor, err := r.PinnedAnchor(ctx)
			if err != want || anchor != (Anchor{}) || strings.Contains(err.Error(), "PRIVATE-CANARY") {
				t.Fatal("unproved receipt returned authority", err)
			}
		})
	}
}

func TestPinnedAnchorStalePrePinInstanceRequiresExplicitReload(t *testing.T) {
	r, _ := pinnedReceiptFixture(t, false)
	stale, err := LoadBootstrap(r.store, r.name, r.plan)
	if err != nil {
		t.Fatal(err)
	}
	d := r.document
	d.CreateAttempted, d.NamespaceUID = true, "original-namespace-uid"
	setPinnedReceiptDocument(t, r, d)
	if anchor, err := stale.PinnedAnchor(context.Background()); err != ErrConflict || anchor != (Anchor{}) {
		t.Fatal("stale unpinned receiver adopted later identity")
	}
	loaded, err := LoadBootstrap(r.store, r.name, r.plan)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := loaded.PinnedAnchor(context.Background())
	if err != nil || anchor.UID != "original-namespace-uid" || anchor.InstallationID != d.InstallationID {
		t.Fatal("explicit reload lost original pinned identity", err)
	}
}
