// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

func enrollmentOptions(f *enrollmentSafetyTLSFixture) BaselineEnrollmentOptions {
	return BaselineEnrollmentOptions{OriginalBootstrap: f.legacy.f.plan, BootstrapReceipt: "Bootstrap_Original.json", Lifecycle: f.legacy.opts}
}

// Real direct HTTPS composition and Store.Commit, independent PUT oracle. Its
// resource health/storage/RBAC responses remain synthetic, not native proof.
func TestBaselineEnrollmentBeginOriginalCASClosedTLS(t *testing.T) {
	for _, mode := range []installstate.Mode{installstate.Install, installstate.Upgrade, installstate.Rollback} {
		t.Run(string(mode), func(t *testing.T) {
			f := newEnrollmentSafetyTLSFixture(t, mode)
			f.allowIntroduction = true
			before := f.snapshot
			next, err := f.lifecycle.BeginBaselineEnrollment(t.Context(), before, enrollmentOptions(f))
			if err != nil || next == nil {
				t.Fatal("closed original historical introduction refused", err, f.trace)
			}
			d := next.Document()
			if d.Mode != mode || d.Stage != installstate.Complete || d.Revision != before.Document().Revision+1 || d.SecurityBaseline == nil || d.SecurityBaseline.Stage != installstate.BaselinePreparing || d.SecurityBaseline.Enrollment == nil || next.ResourceVersion() == before.ResourceVersion() || f.namespaceUpdates != 1 || f.namespaceUpdateRequests != 1 || f.writes != 0 {
				t.Fatal("introduction fabricated state, changed history or issued extra effects")
			}
			d.SecurityBaseline, d.Revision = nil, before.Document().Revision
			if !reflect.DeepEqual(d, before.Document()) {
				t.Fatal("introduction changed historical runtime")
			}
			observed, err := f.lifecycle.engine.journal.Load(t.Context(), next.Anchor())
			if err != nil || !reflect.DeepEqual(observed.Bytes(), next.Bytes()) || observed.ResourceVersion() != next.ResourceVersion() || before.Document().SecurityBaseline != nil {
				t.Fatal("returned next snapshot is not the actual untouched-source CAS result")
			}
			if _, err := f.lifecycle.engine.baseline.runtimeAccessWitness(t.Context(), next); err != ErrSecurityBaseline {
				t.Fatal("preparing enrollment opened ordinary runtime guard")
			}
			if _, err := f.lifecycle.BeginBaselineEnrollment(t.Context(), next, enrollmentOptions(f)); err != ErrSecurityBaseline || f.namespaceUpdateRequests != 1 {
				t.Fatal("introduced journal replayed source introduction")
			}
		})
	}
}

func TestBaselineEnrollmentBeginRefusalAndAmbiguousCASClosedTLS(t *testing.T) {
	for _, which := range []string{"update-denied", "conflict", "unapplied-error", "applied-error", "post-CAS-secret"} {
		t.Run(which, func(t *testing.T) {
			f := newEnrollmentSafetyTLSFixture(t, installstate.Install)
			f.allowIntroduction = which != "update-denied"
			switch which {
			case "conflict":
				f.beforeNamespaceUpdate = func() {
					f.objects[namespaceKey(f.snapshot.Anchor().Namespace)].SetResourceVersion("999999")
				}
			case "unapplied-error":
				f.rejectNamespaceStatus = http.StatusInternalServerError
			case "applied-error":
				f.namespaceReplyStatus = http.StatusInternalServerError
			case "post-CAS-secret":
				f.afterNamespaceUpdate = func() {
					f.objects[secretKey(f.snapshot.Anchor().Namespace, "arcadectl-api-tls")].SetResourceVersion("999999")
				}
			}
			next, err := f.lifecycle.BeginBaselineEnrollment(t.Context(), f.snapshot, enrollmentOptions(f))
			requests, updates := 1, 0
			switch which {
			case "update-denied":
				requests = 0
				if err != ErrSecurityBaseline {
					t.Fatal("denied Namespace UPDATE did not refuse")
				}
			case "conflict":
				if err != installstate.ErrConflict {
					t.Fatal("original RV conflict retried or became success", err)
				}
			case "unapplied-error":
				if err != installstate.ErrOutcomeUnknown {
					t.Fatal("unapplied unknown update became success", err)
				}
			case "applied-error":
				updates = 1
				if err != nil || next.Document().SecurityBaseline == nil {
					t.Fatal("exact applied-error readback failed to correlate once", err)
				}
			case "post-CAS-secret":
				updates = 1
				if err != ErrOutcomeUnknown || next.Document().SecurityBaseline == nil {
					t.Fatal("late Secret drift accepted or committed resume snapshot lost", err)
				}
				observed, loadErr := f.lifecycle.engine.journal.Load(t.Context(), next.Anchor())
				if loadErr != nil || observed.ResourceVersion() != next.ResourceVersion() || !reflect.DeepEqual(observed.Bytes(), next.Bytes()) {
					t.Fatal("post-CAS refusal returned something other than actual committed state")
				}
			}
			if f.namespaceUpdateRequests != requests || f.namespaceUpdates != updates || f.writes != 0 {
				t.Fatal("introduction replayed PUT, wrote extra resource or lost actual state")
			}
		})
	}
}

// Replacement keeps identical contents: hashes alone must not revive a held
// original descriptor. These hooks run inside actual final pre-CAS reproof or
// post-CAS collection, never in a surrogate caller-selected proof provider.
func TestBaselineEnrollmentBeginHeldReplacementClosedTLS(t *testing.T) {
	for _, interval := range []string{"publication", "post-CAS"} {
		for _, which := range []string{"source", "bootstrap", "ca"} {
			t.Run(interval+"/"+which, func(t *testing.T) {
				f := newEnrollmentSafetyTLSFixture(t, installstate.Install)
				f.allowIntroduction = true
				name, nameErr := baselineEnrollmentSourceName(f.snapshot.Document().InstallationID, f.snapshot.Document().Revision)
				if nameErr != nil {
					t.Fatal("source filename unavailable")
				}
				injected := false
				var injectionErr error
				var originalSource []byte
				replace := func() {
					if injected {
						return
					}
					body, _, err := f.lifecycle.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
					if err != nil {
						return // the opening proof precedes exclusive publication
					}
					injected, originalSource = true, body
					for range 2 {
						if err := replaceEnrollmentInput(f, which, name); err != nil {
							injectionErr = err
							return
						}
					}
				}
				trigger, updatesAtTrigger := 6, 0
				if interval == "post-CAS" {
					trigger, updatesAtTrigger = 9, 1
				}
				f.onRules = func(user string) {
					if strings.HasSuffix(user, ":arcadectl-destroy-controller") && f.rules[user] == trigger && f.namespaceUpdates == updatesAtTrigger {
						replace()
					}
				}
				next, err := f.lifecycle.BeginBaselineEnrollment(t.Context(), f.snapshot, enrollmentOptions(f))
				if !injected || injectionErr != nil {
					t.Fatal("actual enrollment interval replacement not exercised", injectionErr)
				}
				wantUpdates, wantErr := 0, ErrSecurityBaseline
				if interval == "post-CAS" {
					wantUpdates, wantErr = 1, ErrOutcomeUnknown
					observed, loadErr := f.lifecycle.engine.journal.Load(t.Context(), next.Anchor())
					if loadErr != nil || next.Document().SecurityBaseline == nil || observed.ResourceVersion() != next.ResourceVersion() || !reflect.DeepEqual(observed.Bytes(), next.Bytes()) {
						t.Fatal("post-CAS replacement lost actual durable resume state")
					}
				}
				preserved, _, readErr := f.lifecycle.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
				if err != wantErr || f.namespaceUpdateRequests != wantUpdates || f.namespaceUpdates != wantUpdates || f.writes != 0 || readErr != nil || !reflect.DeepEqual(preserved, originalSource) {
					t.Fatal("held identical replacement accepted, replayed an effect or lost source evidence", err)
				}
			})
		}
	}
}

func replaceEnrollmentInput(f *enrollmentSafetyTLSFixture, which, sourceName string) error {
	files := f.lifecycle.engine.files
	switch which {
	case "source":
		body, identity, err := files.ReadEvidence(sourceName, privatefs.MaxEvidenceFileBytes)
		if err != nil {
			return err
		}
		if err = files.RemoveEvidence(sourceName, identity); err != nil {
			return err
		}
		_, err = files.CreateEvidenceExclusive(sourceName, body)
		return err
	case "bootstrap":
		name := enrollmentOptions(f).BootstrapReceipt
		body, identity, err := files.Read(name, installstate.MaxBytes)
		if err != nil {
			return err
		}
		_, err = files.AtomicWrite(name, body, &identity)
		return err
	case "ca":
		path := f.legacy.opts.Activation.CAFile
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err = os.WriteFile(path+".enrollment-replacement", body, 0600); err != nil {
			return err
		}
		return os.Rename(path+".enrollment-replacement", path)
	}
	return fmt.Errorf("unknown test-only replacement")
}

func TestBaselineEnrollmentBeginLostWorldRetryKeepsFirstSourceClosedTLS(t *testing.T) {
	f := newEnrollmentSafetyTLSFixture(t, installstate.Install)
	f.allowIntroduction = true
	f.rejectNamespaceStatus = http.StatusInternalServerError
	if _, err := f.lifecycle.BeginBaselineEnrollment(t.Context(), f.snapshot, enrollmentOptions(f)); err != installstate.ErrOutcomeUnknown || f.namespaceUpdateRequests != 1 || f.namespaceUpdates != 0 {
		t.Fatal("unapplied introduction did not preserve retry boundary", err)
	}
	name, _ := baselineEnrollmentSourceName(f.snapshot.Document().InstallationID, f.snapshot.Document().Revision)
	original, identity, err := f.lifecycle.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
	if err != nil {
		t.Fatal("first durable world floor unavailable")
	}
	receipt, _, err := f.lifecycle.engine.decodeBaselineEnrollmentSource(original)
	if err != nil || len(receipt.Worlds) != 2 {
		t.Fatal("original retained claim and volume not captured in first source")
	}
	claim, volume := false, false
	for _, row := range receipt.Worlds {
		claim = claim || row.Key.Kind == "PersistentVolumeClaim" && row.Key.Name == "retained-world" && row.UID == "original-retained-world"
		volume = volume || row.Key.Kind == "PersistentVolume" && row.Key.Name == "world-pv" && row.UID == f.objects[row.Key].GetUID()
	}
	if !claim || !volume {
		t.Fatal("first source omitted exact original retained identities")
	}
	// An orphan volume is no longer in the claim-derived current world tuple;
	// a cold namespace must still not redefine the first durable world floor.
	for key := range f.objects {
		if key.Kind == "PersistentVolumeClaim" && key.Name == "retained-world" {
			delete(f.objects, key)
		}
	}
	f.rejectNamespaceStatus = 0
	if _, err := f.lifecycle.BeginBaselineEnrollment(t.Context(), f.snapshot, enrollmentOptions(f)); err != ErrOutcomeUnknown || f.namespaceUpdateRequests != 1 || f.namespaceUpdates != 0 || f.writes != 0 {
		t.Fatal("retry recaptured a lost initial world or repeated introduction")
	}
	preserved, preservedID, err := f.lifecycle.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
	if err != nil || identity != preservedID || !reflect.DeepEqual(original, preserved) {
		t.Fatal("refused retry replaced or erased the first source envelope")
	}
}

func TestBaselineEnrollmentBeginRejectsCancelledAndForeignComposition(t *testing.T) {
	f := newEnrollmentSafetyTLSFixture(t, installstate.Install)
	f.allowIntroduction = true
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.lifecycle.BeginBaselineEnrollment(ctx, f.snapshot, enrollmentOptions(f)); err != ErrSecurityBaseline || f.namespaceUpdateRequests != 0 {
		t.Fatal("cancelled Begin emitted an effect")
	}
	// The actual legacy fixture has synthetic check providers; public Begin must
	// not let these stand in for the closed cluster safety composition.
	synthetic, err := NewLifecycleWithChecks(f.lifecycle.engine, f.lifecycle.secrets, f.legacy)
	if err != nil {
		t.Fatal("same-engine synthetic composition control unavailable")
	}
	if _, err := synthetic.BeginBaselineEnrollment(t.Context(), f.snapshot, enrollmentOptions(f)); err != ErrSecurityBaseline || f.namespaceUpdateRequests != 0 || f.writes != 0 {
		t.Fatal("foreign/synthetic lifecycle bypassed closed enrollment composition")
	}
}
