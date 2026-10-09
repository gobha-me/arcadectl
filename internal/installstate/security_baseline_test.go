// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"k8s.io/apimachinery/pkg/types"
)

func baselinePlan(t *testing.T, runtimePlan *installrender.Plan, epoch int64) *installbaseline.Plan {
	t.Helper()
	manifest, payload, err := installbaseline.Build(strings.Repeat("c", 40), epoch)
	if err != nil {
		t.Fatal("baseline journal fixture build failed")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x56}, ed25519.SeedSize))
	signature, err := installbaseline.Sign(manifest, key)
	if err != nil {
		t.Fatal("baseline journal fixture signing failed")
	}
	verified, err := installbaseline.Verify(manifest, signature, payload, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal("baseline journal fixture authentication failed")
	}
	plan, err := installbaseline.Compile(verified, runtimePlan.Namespace(), runtimePlan.Profile().ID)
	if err != nil {
		t.Fatal("baseline journal fixture compilation failed")
	}
	return plan
}

func baselineResource(t *testing.T, plan *installbaseline.Plan, index int) BaselineResource {
	t.Helper()
	resource := plan.Resources()[index]
	object := resource.Object
	return BaselineResource{Key{object.GetAPIVersion(), object.GetKind(), object.GetNamespace(), object.GetName()}, types.UID(fmt.Sprintf("owned-baseline-%02d", index)), resource.TemplateSHA256}
}

func TestBaselineJournalHistoricalAbsenceIsNotVerification(t *testing.T) {
	plan := testPlan(t)
	baseline := baselinePlan(t, plan, 1)
	document := initialDocument(plan)
	legacy, err := Encode(document, plan)
	if err != nil {
		t.Fatal("historical journal fixture failed")
	}
	withContext, err := EncodeWithBaseline(document, baseline, plan)
	if err != nil || !bytes.Equal(legacy, withContext) {
		t.Fatal("baseline context rewrote historical journal bytes")
	}
	decoded, err := DecodeWithBaseline(legacy, baseline, plan)
	if err != nil || decoded.SecurityBaseline != nil {
		t.Fatal("historical omission became verified security evidence")
	}
	document.SecurityBaseline, err = PinnedSecurityBaseline(baseline)
	if err != nil {
		t.Fatal("trusted baseline pinning failed")
	}
	if _, err := Encode(document, plan); err != ErrInvalid {
		t.Fatal("baseline journal encoded without its independent trusted plan")
	}
	body, err := EncodeWithBaseline(document, baseline, plan)
	if err != nil {
		t.Fatal("pinned baseline journal encoding failed")
	}
	if _, err := Decode(body, plan); err != ErrInvalid {
		t.Fatal("baseline journal was accepted by a runtime-only decoder")
	}
	again, err := DecodeWithBaseline(body, baseline, plan)
	if err != nil || !reflect.DeepEqual(document, again) {
		t.Fatal("baseline journal canonical roundtrip failed")
	}
	if _, err := DecodeWithBaseline(body, baselinePlan(t, plan, 2), plan); err != ErrInvalid {
		t.Fatal("baseline journal accepted a substituted authenticated artifact")
	}
	for _, zero := range []*installbaseline.Plan{nil, {}} {
		if _, err := PinnedSecurityBaseline(zero); err != ErrInvalid {
			t.Fatal("untrusted baseline was pinned")
		}
		if _, err := DecodeWithBaseline(body, zero, plan); err != ErrInvalid {
			t.Fatal("baseline journal decoded without trusted semantics")
		}
	}
}

func TestBaselineJournalOnlyPriorIntentCanEstablishOriginalUID(t *testing.T) {
	plan := testPlan(t)
	baseline := baselinePlan(t, plan, 1)
	document := initialDocument(plan)
	document.SecurityBaseline, _ = PinnedSecurityBaseline(baseline)
	next := lifecycleCopy(t, document)
	next.Revision++
	next.SecurityBaseline.Stage = BaselineApplying
	if !validTransition(document, next) {
		t.Fatal("baseline application stage was refused")
	}
	document = next
	for index := 0; index < installbaseline.ResourceCount; index++ {
		resource := baselineResource(t, baseline, index)
		intent := lifecycleCopy(t, document)
		intent.Revision++
		intent.SecurityBaseline.Pending = &Pending{Action: Create, Key: resource.Key, CreateNonce: fmt.Sprintf("%032x", index+1), AfterSHA256: resource.TemplateSHA256}
		if !validTransition(document, intent) {
			t.Fatal("bounded baseline creation intent was refused")
		}
		if _, err := EncodeWithBaseline(intent, baseline, plan); err != nil {
			t.Fatal("exact baseline intent did not encode")
		}
		settled := lifecycleCopy(t, intent)
		settled.Revision++
		settled.SecurityBaseline.Pending = nil
		settled.SecurityBaseline.Resources = append(settled.SecurityBaseline.Resources, resource)
		SortBaselineResources(settled.SecurityBaseline.Resources)
		if !validTransition(intent, settled) {
			t.Fatal("prior exact intent could not establish original baseline identity")
		}
		if _, err := EncodeWithBaseline(settled, baseline, plan); err != nil {
			t.Fatal("settled baseline identity did not encode")
		}
		adoption := lifecycleCopy(t, settled)
		adoption.Revision = document.Revision + 1
		if validTransition(document, adoption) {
			t.Fatal("baseline identity was adopted without prior creation intent")
		}
		abandoned := lifecycleCopy(t, intent)
		abandoned.Revision++
		abandoned.SecurityBaseline.Pending = nil
		if validTransition(intent, abandoned) {
			t.Fatal("unconfirmed baseline intent was abandoned")
		}
		if index > 0 {
			substituted := lifecycleCopy(t, settled)
			for resourceIndex := range substituted.SecurityBaseline.Resources {
				if substituted.SecurityBaseline.Resources[resourceIndex].Key != resource.Key {
					substituted.SecurityBaseline.Resources[resourceIndex].UID = "replacement"
					break
				}
			}
			if validTransition(intent, substituted) {
				t.Fatal("creation settlement replaced a prior original UID")
			}
		}
		document = settled
	}
	verified := lifecycleCopy(t, document)
	verified.Revision++
	verified.SecurityBaseline.Stage = BaselineVerified
	if !validTransition(document, verified) {
		t.Fatal("complete original-identity inventory could not be certified")
	}
	if _, err := EncodeWithBaseline(verified, baseline, plan); err != nil {
		t.Fatal("verified baseline did not encode")
	}
	for _, mutate := range []func(*Document){
		func(d *Document) { d.SecurityBaseline = nil },
		func(d *Document) { d.SecurityBaseline.ArtifactDigest = baselinePlan(t, plan, 2).Digest() },
		func(d *Document) { d.SecurityBaseline.Resources[0].UID = "replacement" },
		func(d *Document) { d.SecurityBaseline.Resources = d.SecurityBaseline.Resources[1:] },
		func(d *Document) { d.SecurityBaseline.Stage = BaselineApplying },
	} {
		bad := lifecycleCopy(t, verified)
		bad.Revision++
		mutate(&bad)
		if validTransition(verified, bad) {
			t.Fatal("verified non-rollback baseline was rewritten or removed")
		}
	}
	// Runtime stage changes are allowed only after verified baseline ownership,
	// and must carry the original baseline inventory without modification.
	runtimeNext := lifecycleCopy(t, verified)
	runtimeNext.Revision++
	runtimeNext.Stage = Applying
	if !validTransition(verified, runtimeNext) {
		t.Fatal("verified baseline obstructed legitimate runtime progression")
	}
	blocked := lifecycleCopy(t, document)
	blocked.Revision++
	blocked.Stage = Applying
	if validTransition(document, blocked) {
		t.Fatal("runtime progression bypassed incomplete security ownership")
	}
}

func TestBaselineJournalRefusesCrossInventoryKeysAndCorruptIntent(t *testing.T) {
	plan := testPlan(t)
	baseline := baselinePlan(t, plan, 1)
	document := initialDocument(plan)
	document.SecurityBaseline, _ = PinnedSecurityBaseline(baseline)
	document.SecurityBaseline.Stage = BaselineApplying
	resource := baselineResource(t, baseline, 0)
	document.SecurityBaseline.Pending = &Pending{Action: Create, Key: resource.Key, CreateNonce: strings.Repeat("b", 32), AfterSHA256: resource.TemplateSHA256}
	for _, mutate := range []func(*Document){
		func(d *Document) { d.SecurityBaseline.Pending.Action = Delete },
		func(d *Document) { d.SecurityBaseline.Pending.Action = Update },
		func(d *Document) { d.SecurityBaseline.Pending.BeforeUID = "foreign" },
		func(d *Document) { d.SecurityBaseline.Pending.BeforeResourceVersion = "10" },
		func(d *Document) { d.SecurityBaseline.Pending.BeforeSHA256 = strings.Repeat("c", 64) },
		func(d *Document) { d.SecurityBaseline.Pending.AfterSHA256 = strings.Repeat("c", 64) },
		func(d *Document) { d.SecurityBaseline.Pending.CreateNonce = "untrusted" },
		func(d *Document) { d.SecurityBaseline.Pending.Key = d.Resources[0].Key },
		func(d *Document) { d.SecurityBaseline.Resources = append(d.SecurityBaseline.Resources, resource) },
		func(d *Document) { d.SecurityBaseline.Stage = BaselineVerified },
		func(d *Document) { d.SecurityBaseline.Version = "unknown" },
	} {
		bad := lifecycleCopy(t, document)
		mutate(&bad)
		if _, err := EncodeWithBaseline(bad, baseline, plan); err != ErrInvalid {
			t.Fatal("invalid baseline intent or cross-inventory key was accepted")
		}
	}
	document.SecurityBaseline.Pending = nil
	document.SecurityBaseline.Resources = []BaselineResource{resource}
	document.SecurityBaseline.Resources[0].UID = document.Resources[0].UID
	if _, err := EncodeWithBaseline(document, baseline, plan); err != ErrInvalid {
		t.Fatal("runtime original UID was reused as baseline ownership")
	}
}

func TestBaselineNamespaceCASCorrelatesLostResponseWithoutRetry(t *testing.T) {
	plan := testPlan(t)
	baseline := baselinePlan(t, plan, 1)
	for _, committed := range []bool{false, true} {
		document := initialDocument(plan)
		document.SecurityBaseline, _ = PinnedSecurityBaseline(baseline)
		server := &namespaceServer{live: testNamespace(plan, document)}
		store, err := NewWithBaseline(server.client().CoreV1().Namespaces(), baseline, plan)
		if err != nil {
			t.Fatal("baseline CAS store construction failed")
		}
		anchor := Anchor{document.Namespace, document.NamespaceUID, document.InstallationID}
		snapshot, err := store.Bind(context.Background(), anchor, document)
		if err != nil {
			t.Fatal("baseline initial namespace CAS failed")
		}
		next := snapshot.Document()
		next.Revision++
		next.SecurityBaseline.Stage = BaselineApplying
		server.failUpdate, server.commitOnFailure = true, committed
		result, err := store.Commit(context.Background(), snapshot, next)
		if server.updates != 2 {
			t.Fatal("baseline CAS retried an uncertain write")
		}
		if committed {
			if err != nil || result == nil || result.Document().SecurityBaseline.Stage != BaselineApplying {
				t.Fatal("exact committed baseline CAS could not be confirmed")
			}
		} else if err != ErrOutcomeUnknown || result != nil {
			t.Fatal("uncommitted baseline CAS was reported successful")
		}
	}
}

func TestBaselineRecoveryPreservesPendingIntent(t *testing.T) {
	plan := testPlan(t)
	baseline := baselinePlan(t, plan, 1)
	document := initialDocument(plan)
	document.SecurityBaseline, _ = PinnedSecurityBaseline(baseline)
	document.SecurityBaseline.Stage = BaselineApplying
	resource := baselineResource(t, baseline, 0)
	document.SecurityBaseline.Pending = &Pending{Action: Create, Key: resource.Key, CreateNonce: strings.Repeat("b", 32), AfterSHA256: resource.TemplateSHA256}
	recovery := lifecycleCopy(t, document)
	recovery.Revision++
	recovery.SecurityBaseline.Stage = BaselineRecovery
	if !validTransition(document, recovery) {
		t.Fatal("uncertain baseline outcome could not enter recovery with exact intent")
	}
	resume := lifecycleCopy(t, recovery)
	resume.Revision++
	resume.SecurityBaseline.Stage = BaselineApplying
	if !validTransition(recovery, resume) {
		t.Fatal("baseline recovery lost its original candidate")
	}
	for _, mutate := range []func(*Document){
		func(d *Document) { d.SecurityBaseline.Pending = nil },
		func(d *Document) { d.SecurityBaseline.Pending.CreateNonce = strings.Repeat("c", 32) },
		func(d *Document) { d.Stage = Applying },
	} {
		bad := lifecycleCopy(t, recovery)
		mutate(&bad)
		if validTransition(document, bad) {
			t.Fatal("baseline recovery abandoned intent or piggybacked a runtime effect")
		}
	}
}

func TestBaselineAwareStoreCannotAdvanceHistoricalRuntimeBeforeEnrollment(t *testing.T) {
	plan := testPlan(t)
	baseline := baselinePlan(t, plan, 1)
	document := initialDocument(plan)
	server := &namespaceServer{live: testNamespace(plan, document)}
	legacyStore, err := New(server.client().CoreV1().Namespaces(), plan)
	if err != nil {
		t.Fatal("historical store fixture failed")
	}
	anchor := Anchor{document.Namespace, document.NamespaceUID, document.InstallationID}
	if _, err := legacyStore.Bind(context.Background(), anchor, document); err != nil {
		t.Fatal("historical journal fixture binding failed")
	}
	guardedStore, err := NewWithBaseline(server.client().CoreV1().Namespaces(), baseline, plan)
	if err != nil {
		t.Fatal("baseline-aware store fixture failed")
	}
	snapshot, err := guardedStore.Load(context.Background(), anchor)
	if err != nil || snapshot.Document().SecurityBaseline != nil {
		t.Fatal("legacy omission was not read honestly")
	}
	next := snapshot.Document()
	next.Revision++
	next.Stage = Applying
	if _, err := guardedStore.Commit(context.Background(), snapshot, next); err != ErrInvalid || server.updates != 1 {
		t.Fatal("baseline-aware store advanced unguarded historical runtime")
	}
	enrollment := snapshot.Document()
	enrollment.Revision++
	enrollment.SecurityBaseline, _ = PinnedSecurityBaseline(baseline)
	enrolled, err := guardedStore.Commit(context.Background(), snapshot, enrollment)
	if err != nil || enrolled == nil || server.updates != 2 {
		t.Fatal("explicit same-CAS baseline enrollment was refused")
	}
	blocked := enrolled.Document()
	blocked.Revision++
	blocked.Stage = Applying
	if _, err := guardedStore.Commit(context.Background(), enrolled, blocked); err != ErrInvalid || server.updates != 2 {
		t.Fatal("baseline enrollment was mistaken for verified ownership")
	}
}
