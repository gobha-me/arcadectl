// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Independent transition oracle: no call to the production transition checker,
// effect selector, receipt recovery or whole-template matcher.
func (f *enrollmentSafetyTLSFixture) originalBaselineTransition(before, after *installstate.SecurityBaseline) bool {
	if before == nil || after == nil || before.Version != after.Version || before.ArtifactDigest != after.ArtifactDigest || !reflect.DeepEqual(before.Enrollment, after.Enrollment) {
		return false
	}
	if before.Stage != after.Stage {
		if !reflect.DeepEqual(before.Resources, after.Resources) || !reflect.DeepEqual(before.Pending, after.Pending) {
			return false
		}
		return (before.Stage == installstate.BaselinePreparing || before.Stage == installstate.BaselineRecovery) && after.Stage == installstate.BaselineApplying || before.Stage == installstate.BaselineApplying && after.Stage == installstate.BaselineVerified && before.Pending == nil && len(before.Resources) == 12
	}
	if before.Stage != installstate.BaselineApplying {
		return false
	}
	if before.Pending == nil {
		if after.Pending == nil || after.Pending.Action != installstate.Create || !reflect.DeepEqual(before.Resources, after.Resources) {
			return false
		}
		for _, resource := range f.lifecycle.engine.baselinePlan().Resources() {
			if baselineObjectKey(resource.Object) == after.Pending.Key && resource.TemplateSHA256 == after.Pending.AfterSHA256 {
				return true
			}
		}
		return false
	}
	if after.Pending != nil || len(after.Resources) != len(before.Resources)+1 {
		return false
	}
	remaining := []installstate.BaselineResource{}
	added := 0
	for _, resource := range after.Resources {
		if resource.Key == before.Pending.Key {
			object := f.objects[resource.Key]
			if object == nil || object.GetUID() != resource.UID || resource.TemplateSHA256 != before.Pending.AfterSHA256 || object.GetAnnotations()[installstate.MutationAnnotation] != before.Pending.CreateNonce {
				return false
			}
			added++
		} else {
			remaining = append(remaining, resource)
		}
	}
	return added == 1 && reflect.DeepEqual(before.Resources, remaining)
}

func (f *enrollmentSafetyTLSFixture) originalBaselineCandidate(candidate *unstructured.Unstructured, path string) bool {
	if candidate == nil || candidate.GetAnnotations()[installstate.MutationAnnotation] == "" || candidate.GetNamespace() != "" {
		return false
	}
	if candidate.GetKind() == "ValidatingAdmissionPolicy" && path != "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies" || candidate.GetKind() == "ValidatingAdmissionPolicyBinding" && path != "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings" {
		return false
	}
	for _, resource := range f.lifecycle.engine.baselinePlan().Resources() {
		if baselineObjectKey(resource.Object) != baselineObjectKey(candidate) {
			continue
		}
		copy := candidate.DeepCopy()
		annotations := copy.GetAnnotations()
		delete(annotations, installstate.MutationAnnotation)
		copy.SetAnnotations(annotations)
		if len(annotations) == 0 && resource.Object.GetAnnotations() == nil {
			unstructured.RemoveNestedField(copy.Object, "metadata", "annotations")
		}
		return reflect.DeepEqual(copy.Object, resource.Object.Object)
	}
	return false
}

func prepareEnrollmentStepTLS(t *testing.T) (*enrollmentSafetyTLSFixture, *installstate.Snapshot) {
	t.Helper()
	f := newEnrollmentSafetyTLSFixture(t, installstate.Install)
	f.allowIntroduction, f.allowEnrollmentSteps = true, true
	current, err := f.lifecycle.BeginBaselineEnrollment(t.Context(), f.snapshot, enrollmentOptions(f))
	if err != nil {
		t.Fatal("actual initial enrollment failed", err, f.trace)
	}
	current, err = f.lifecycle.StepBaselineEnrollment(t.Context(), current, enrollmentOptions(f))
	if err != nil || current.Document().SecurityBaseline.Stage != installstate.BaselineApplying || f.namespaceUpdates != 2 || f.baselinePreviews != 0 || f.baselineCreates != 0 || f.baselineCreateReviews != 0 || f.writes != 0 {
		t.Fatal("actual preparing step changed runtime or gained CREATE", err, f.trace)
	}
	return f, current
}

func assertEnrollmentRuntimeUnchanged(t *testing.T, f *enrollmentSafetyTLSFixture, current *installstate.Snapshot) {
	t.Helper()
	d := current.Document()
	d.SecurityBaseline, d.Revision = nil, f.snapshot.Document().Revision
	if !reflect.DeepEqual(d, f.snapshot.Document()) {
		t.Fatal("baseline step changed completed historical runtime")
	}
	observed, err := f.lifecycle.engine.journal.Load(t.Context(), current.Anchor())
	if err != nil || observed.ResourceVersion() != current.ResourceVersion() || !reflect.DeepEqual(observed.Bytes(), current.Bytes()) {
		t.Fatal("step did not return actual committed journal")
	}
}

func TestBaselineEnrollmentStepOneCreateClosedTLS(t *testing.T) {
	f, current := prepareEnrollmentStepTLS(t)
	next, err := f.lifecycle.StepBaselineEnrollment(t.Context(), current, enrollmentOptions(f))
	if err != nil || next.Document().SecurityBaseline.Pending != nil || len(next.Document().SecurityBaseline.Resources) != 1 || next.Document().Revision != current.Document().Revision+2 || f.namespaceUpdates != 4 || f.baselinePreviews != 1 || f.baselineCreates != 1 || f.baselineCreateReviews != 1 || f.writes != 0 {
		t.Fatal("historical step did not perform exactly intent, one CREATE and settlement", err, f.trace)
	}
	assertEnrollmentRuntimeUnchanged(t, f, next)
	if _, err := f.lifecycle.engine.EstablishBaselineOwnership(t.Context(), next); err != ErrSecurityBaseline || f.baselineCreates != 1 {
		t.Fatal("historical enrollment leaked into ordinary fresh ownership")
	}
}

func TestBaselineEnrollmentStepAmbiguousCreateClosedTLS(t *testing.T) {
	f, current := prepareEnrollmentStepTLS(t)
	f.baselineReplyStatus = http.StatusInternalServerError
	next, err := f.lifecycle.StepBaselineEnrollment(t.Context(), current, enrollmentOptions(f))
	if err != nil || next.Document().SecurityBaseline.Pending != nil || len(next.Document().SecurityBaseline.Resources) != 1 || f.baselineCreates != 1 || f.baselinePreviews != 1 || f.namespaceUpdates != 4 || f.writes != 0 {
		t.Fatal("original ambiguous CREATE was not correlated without retry", err, f.trace)
	}
	assertEnrollmentRuntimeUnchanged(t, f, next)
}

func prepareEnrollmentPendingACKTLS(t *testing.T) (*enrollmentSafetyTLSFixture, *installstate.Snapshot) {
	t.Helper()
	f, current := prepareEnrollmentStepTLS(t)
	f.afterBaselineCreate = func() { f.rejectNamespaceStatus = http.StatusInternalServerError }
	next, err := f.lifecycle.StepBaselineEnrollment(t.Context(), current, enrollmentOptions(f))
	if err != ErrOutcomeUnknown || next.Document().SecurityBaseline.Pending == nil || len(next.Document().SecurityBaseline.Resources) != 0 || f.baselineCreates != 1 || f.baselinePreviews != 1 || f.namespaceUpdates != 3 || f.namespaceUpdateRequests != 4 || f.writes != 0 {
		t.Fatal("failed settlement lost original ACK checkpoint", err, f.trace)
	}
	if uid, err := f.lifecycle.engine.baseline.loadReceiptUID(next.Document()); err != nil || uid != "historical-baseline-1" {
		t.Fatal("actual CREATE ACK was not durably pinned before failure")
	}
	f.rejectNamespaceStatus, f.afterBaselineCreate = 0, nil
	// Genuine production reconstruction, not an in-memory pending normalization
	// or a callback replacement. Durable originals are reloaded as on CLI restart.
	access := f.lifecycle.engine.access.(*HTTPAccess)
	plans := []*installrender.Plan{}
	for _, plan := range f.lifecycle.engine.plans {
		plans = append(plans, plan)
	}
	journal, err := installstate.NewWithBaseline(access.Namespaces(), f.lifecycle.engine.baselinePlan(), plans...)
	if err != nil {
		t.Fatal("restarted actual journal unavailable")
	}
	engine, err := NewWithBaselineAccess(access, journal, f.lifecycle.engine.files, f.lifecycle.engine.baselinePlan(), plans...)
	if err != nil {
		t.Fatal("restarted actual engine unavailable")
	}
	f.lifecycle, err = NewClusterLifecycle(engine, access)
	if err != nil {
		t.Fatal("restarted actual closed composition unavailable")
	}
	reloaded, err := journal.Load(t.Context(), next.Anchor())
	if err != nil || reloaded.ResourceVersion() != next.ResourceVersion() || !reflect.DeepEqual(reloaded.Bytes(), next.Bytes()) {
		t.Fatal("restarted actual pending journal differs from original checkpoint")
	}
	return f, reloaded
}

func TestBaselineEnrollmentStepPendingACKRecoveryClosedTLS(t *testing.T) {
	f, pending := prepareEnrollmentPendingACKTLS(t)
	reviews, requests := f.baselineCreateReviews, f.namespaceUpdateRequests
	next, err := f.lifecycle.StepBaselineEnrollment(t.Context(), pending, enrollmentOptions(f))
	if err != nil || next.Document().SecurityBaseline.Pending != nil || len(next.Document().SecurityBaseline.Resources) != 1 || f.baselineCreates != 1 || f.baselinePreviews != 1 || f.baselineCreateReviews != reviews || f.namespaceUpdateRequests != requests+1 || f.namespaceUpdates != 4 || f.writes != 0 {
		t.Fatal("explicit ACK recovery replayed preview, CREATE authority or an uncertain effect", err, f.trace)
	}
	assertEnrollmentRuntimeUnchanged(t, f, next)
}

func TestBaselineEnrollmentStepPendingReceiptRefusalClosedTLS(t *testing.T) {
	f, pending := prepareEnrollmentPendingACKTLS(t)
	b := f.lifecycle.engine.baseline
	name, err := b.receiptName(pending.Document())
	if err != nil {
		t.Fatal("original pending receipt unavailable")
	}
	original, _, err := b.engine.files.Read(name, 4096)
	if err != nil || bytes.Count(original, []byte(`"originalUid":"historical-baseline-1"`)) != 1 {
		t.Fatal("actual ACK receipt identity unavailable")
	}
	requests, reviews := f.namespaceUpdateRequests, f.baselineCreateReviews
	for _, test := range []struct {
		name string
		body []byte
	}{
		{"empty-ack", bytes.Replace(original, []byte(`"originalUid":"historical-baseline-1"`), []byte(`"originalUid":""`), 1)},
		{"foreign-ack", bytes.Replace(original, []byte(`"originalUid":"historical-baseline-1"`), []byte(`"originalUid":"foreign-baseline-1"`), 1)},
		{"malformed-ack", []byte(`{"originalUid":`)},
		{"missing-ack", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, identity, err := b.engine.files.Read(name, 4096)
			if err != nil {
				t.Fatal("owned receipt test input unavailable")
			}
			if test.body == nil {
				err = b.engine.files.Remove(name, identity)
			} else {
				_, err = b.engine.files.AtomicWrite(name, test.body, &identity)
			}
			if err != nil {
				t.Fatal("owned receipt test replacement refused")
			}
			next, err := f.lifecycle.StepBaselineEnrollment(t.Context(), pending, enrollmentOptions(f))
			if err != ErrOutcomeUnknown || next.ResourceVersion() != pending.ResourceVersion() || !bytes.Equal(next.Bytes(), pending.Bytes()) || f.namespaceUpdateRequests != requests || f.baselineCreateReviews != reviews || f.baselineCreates != 1 || f.baselinePreviews != 1 || f.writes != 0 {
				t.Fatal("missing or invalid original ACK authorized adoption, settlement or CREATE replay", err)
			}
			assertEnrollmentRuntimeUnchanged(t, f, next)
			if test.body != nil {
				_, identity, readErr := b.engine.files.Read(name, 4096)
				if readErr != nil {
					t.Fatal("owned receipt test restoration input unavailable")
				}
				if _, err := b.engine.files.AtomicWrite(name, original, &identity); err != nil {
					t.Fatal("owned receipt test restoration refused")
				}
			}
		})
	}
}

func TestBaselineEnrollmentStepPendingReceiptOpeningReplacementClosedTLS(t *testing.T) {
	f, pending := prepareEnrollmentPendingACKTLS(t)
	reviews, requests := f.baselineCreateReviews, f.namespaceUpdateRequests
	name, err := f.lifecycle.engine.baseline.receiptName(pending.Document())
	if err != nil {
		t.Fatal("original pending receipt unavailable")
	}
	injected := false
	var injectionErr error
	f.onRules = func(user string) {
		if injected || !strings.HasSuffix(user, ":arcadectl-destroy-controller") {
			return
		}
		injected = true
		body, identity, err := f.lifecycle.engine.files.Read(name, 4096)
		if err == nil {
			_, err = f.lifecycle.engine.files.AtomicWrite(name, body, &identity)
		}
		injectionErr = err
	}
	next, err := f.lifecycle.StepBaselineEnrollment(t.Context(), pending, enrollmentOptions(f))
	if !injected || injectionErr != nil || err == nil || next.ResourceVersion() != pending.ResourceVersion() || !reflect.DeepEqual(next.Bytes(), pending.Bytes()) || f.namespaceUpdateRequests != requests || f.baselineCreateReviews != reviews || f.baselineCreates != 1 || f.baselinePreviews != 1 || f.writes != 0 {
		t.Fatal("opening recovery proof reacquired identically replaced ACK receipt", err, injectionErr)
	}
}

func TestBaselineEnrollmentStepPendingReceiptSettlementReplacementClosedTLS(t *testing.T) {
	f, pending := prepareEnrollmentPendingACKTLS(t)
	reviews, requests := f.baselineCreateReviews, f.namespaceUpdateRequests
	name, err := f.lifecycle.engine.baseline.receiptName(pending.Document())
	if err != nil {
		t.Fatal("original pending receipt unavailable")
	}
	injected := false
	var injectionErr error
	f.afterNamespaceUpdate = func() {
		f.onRead = func(path string) {
			if injected || path != "/version" {
				return
			}
			injected = true
			body, identity, err := f.lifecycle.engine.files.Read(name, 4096)
			if err == nil {
				_, err = f.lifecycle.engine.files.AtomicWrite(name, body, &identity)
			}
			injectionErr = err
		}
	}
	next, err := f.lifecycle.StepBaselineEnrollment(t.Context(), pending, enrollmentOptions(f))
	if !injected || injectionErr != nil || err != ErrOutcomeUnknown || next.Document().SecurityBaseline.Pending != nil || f.namespaceUpdateRequests != requests+1 || f.baselineCreateReviews != reviews || f.baselineCreates != 1 || f.baselinePreviews != 1 || f.writes != 0 {
		t.Fatal("post-settlement recovery forgot held ACK receipt or lost actual committed state", err, injectionErr)
	}
	assertEnrollmentRuntimeUnchanged(t, f, next)
}

func TestBaselineEnrollmentStepOwnedPolicyClosingRefusalClosedTLS(t *testing.T) {
	f, current := prepareEnrollmentStepTLS(t)
	current, err := f.lifecycle.StepBaselineEnrollment(t.Context(), current, enrollmentOptions(f))
	if err != nil || len(current.Document().SecurityBaseline.Resources) != 1 {
		t.Fatal("actual first owned baseline unavailable", err)
	}
	owned := current.Document().SecurityBaseline.Resources[0].Key
	actor := "system:serviceaccount:" + current.Anchor().Namespace + ":arcadectl-destroy-controller"
	trigger := f.rules[actor] + 6 // opening constructor + final effect-owner close
	requests := f.namespaceUpdateRequests
	injected := false
	f.onRules = func(user string) {
		if user == actor && f.rules[user] == trigger {
			injected = true
			delete(f.objects, owned)
		}
	}
	next, err := f.lifecycle.StepBaselineEnrollment(t.Context(), current, enrollmentOptions(f))
	if !injected || err != ErrSecurityBaseline || next.ResourceVersion() != current.ResourceVersion() || f.namespaceUpdateRequests != requests || f.baselineCreates != 1 || f.baselinePreviews != 1 || f.writes != 0 {
		t.Fatal("late acknowledged baseline loss permitted another persistent CREATE", err, f.trace)
	}
}
