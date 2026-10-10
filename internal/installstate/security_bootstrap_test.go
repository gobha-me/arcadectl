// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"context"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
)

func TestSecurityBootstrapPinsBaselineBeforeNamespaceMutation(t *testing.T) {
	plan := testPlan(t)
	baseline := baselinePlan(t, plan, 1)
	for _, fixture := range []struct {
		name            string
		fail, committed bool
		expected        error
	}{
		{"fresh", false, false, nil}, {"lost-committed", true, true, nil}, {"lost-uncommitted", true, false, ErrOutcomeUnknown},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			storage := privateStore(t)
			receipt, err := PrepareBootstrapWithBaseline(storage, "installation.json", plan, baseline)
			if err != nil {
				t.Fatal("security bootstrap preparation failed")
			}
			server := &namespaceServer{failCreate: fixture.fail, commitOnCreateFailure: fixture.committed}
			server.beforeCreate = func() {
				body, _, err := storage.Read("installation.json", MaxBytes)
				if err != nil {
					t.Fatal("namespace effect preceded durable security pin")
				}
				pinned, err := decodeBootstrapWithBaseline(body, plan, baseline)
				if err != nil || pinned.BaselineSHA256 != baseline.Digest() || pinned.BaselineVersion != installbaseline.Version || !pinned.CreateAttempted || pinned.NamespaceUID != "" || pinned.InstallationID != receipt.document.InstallationID {
					t.Fatal("pre-effect receipt does not bind both original identities")
				}
			}
			namespaces := server.client().CoreV1().Namespaces()
			snapshot, err := receipt.EnsureNamespace(context.Background(), namespaces)
			if err != fixture.expected || server.creates != 1 {
				t.Fatal("security bootstrap did not honor its one-effect bound")
			}
			loaded, err := LoadBootstrapWithBaseline(storage, "installation.json", plan, baseline)
			if err != nil {
				t.Fatal("pinned security receipt could not be reloaded")
			}
			if fixture.expected != nil {
				if snapshot != nil || server.updates != 0 {
					t.Fatal("ambiguous namespace outcome admitted later journal effects")
				}
				if _, err := loaded.EnsureNamespace(context.Background(), namespaces); err != ErrOutcomeUnknown || server.creates != 1 {
					t.Fatal("security receipt resume retried an ambiguous namespace create")
				}
				return
			}
			security := snapshot.Document().SecurityBaseline
			if security == nil || security.Stage != BaselinePreparing || security.ArtifactDigest != baseline.Digest() || len(security.Resources) != 0 {
				t.Fatal("namespace bind fabricated verification or lost its security pin")
			}
			anchor, err := loaded.PinnedAnchor(context.Background())
			if err != nil || anchor != snapshot.Anchor() {
				t.Fatal("original durable namespace anchor was not preserved")
			}
			if _, err := loaded.EnsureNamespace(context.Background(), namespaces); err != nil || server.creates != 1 || server.updates != 1 {
				t.Fatal("security bootstrap resume replayed completed effects")
			}
			if _, err := LoadBootstrap(storage, "installation.json", plan); err != ErrInvalid {
				t.Fatal("runtime-only bootstrap accepted a security-pinned receipt")
			}
			if _, err := LoadBootstrapWithBaseline(storage, "installation.json", plan, baselinePlan(t, plan, 2)); err != ErrInvalid {
				t.Fatal("security bootstrap accepted a substituted signed baseline")
			}
		})
	}
}

func TestLegacyBootstrapEvidenceRemainsOriginalDuringSecurityEnrollment(t *testing.T) {
	plan := testPlan(t)
	baseline := baselinePlan(t, plan, 1)
	for _, createOriginal := range []bool{false, true} {
		storage := privateStore(t)
		original, err := PrepareBootstrap(storage, "installation.json", plan)
		if err != nil {
			t.Fatal("legacy receipt fixture preparation failed")
		}
		server := &namespaceServer{}
		namespaces := server.client().CoreV1().Namespaces()
		if createOriginal {
			if _, err := original.EnsureNamespace(context.Background(), namespaces); err != nil {
				t.Fatal("original namespace fixture creation failed")
			}
		}
		before, identity, err := storage.Read("installation.json", MaxBytes)
		if err != nil {
			t.Fatal("original durable receipt fixture read failed")
		}
		loaded, err := LoadBootstrapWithBaseline(storage, "installation.json", plan, baseline)
		if err != nil || loaded.document.BaselineSHA256 != "" || loaded.document.BaselineVersion != "" {
			t.Fatal("authentic legacy omission was relabeled as security protection")
		}
		if _, err := loaded.EnsureNamespace(context.Background(), namespaces); err != ErrInvalid {
			t.Fatal("legacy receipt without a security pin authorized fresh namespace effects")
		}
		anchor, err := loaded.PinnedAnchor(context.Background())
		if createOriginal {
			if err != nil || anchor.UID != original.document.NamespaceUID || anchor.InstallationID != original.document.InstallationID {
				t.Fatal("legacy original-identity evidence was lost")
			}
		} else if err != ErrOutcomeUnknown {
			t.Fatal("empty legacy receipt became ownership evidence")
		}
		after, afterIdentity, err := storage.Read("installation.json", MaxBytes)
		if err != nil || identity != afterIdentity || !bytes.Equal(before, after) {
			t.Fatal("security enrollment rewrote authentic legacy receipt bytes")
		}
		if createOriginal && server.creates != 1 || !createOriginal && server.creates != 0 {
			t.Fatal("legacy enrollment repeated namespace creation")
		}
	}
}

func TestSecurityBootstrapRejectsUntrustedPlanBeforeAnyReceiptWrite(t *testing.T) {
	plan := testPlan(t)
	storage := privateStore(t)
	for _, zero := range []*installbaseline.Plan{nil, {}} {
		if _, err := PrepareBootstrapWithBaseline(storage, "installation.json", plan, zero); err != ErrInvalid {
			t.Fatal("unverified security baseline created a bootstrap receipt")
		}
		if _, err := LoadBootstrapWithBaseline(storage, "installation.json", plan, zero); err != ErrInvalid {
			t.Fatal("unverified security baseline loaded a bootstrap receipt")
		}
	}
	if _, err := PrepareBootstrap(storage, "installation.json", plan); err != nil {
		t.Fatal("untrusted security input wrote or occupied the receipt path")
	}
}
