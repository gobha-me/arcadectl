// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func testOwnedActivationRequest(t *testing.T, engine *Engine, snapshot *installstate.Snapshot, fixture *baselineBehaviorActivationFixture) (*Lifecycle, *clusterLifecycleChecks, LifecycleCheck) {
	t.Helper()
	lifecycle, err := NewClusterLifecycle(engine, engine.access.(*HTTPAccess))
	if err != nil {
		t.Fatal("actual closed lifecycle unavailable")
	}
	checks, ok := lifecycle.checks.(*clusterLifecycleChecks)
	if !ok {
		t.Fatal("closed lifecycle provider unavailable")
	}
	request := LifecycleCheck{Checkpoint: TargetAuthenticated, Snapshot: snapshot, Mode: snapshot.Document().Mode, Target: engine.plans[snapshot.Document().TargetPackage], Options: LifecycleOptions{Now: time.Now().UTC(), Activation: fixture.serving.options}}
	return lifecycle, checks, request
}

func testOwnedActivationPinsReleased(t *testing.T, fixture *baselineBehaviorActivationFixture) {
	t.Helper()
	if testBaselineReceiptDescriptors(t, filepath.Base(fixture.serving.options.CredentialFile)) != 0 || testBaselineReceiptDescriptors(t, filepath.Base(fixture.serving.options.CAFile)) != 0 {
		t.Fatal("owned activation leaked original file descriptors")
	}
}

// Actual complete baseline provider, stock native SPDY and genuine TLS/admin
// authentication. Whole Kubernetes inventory is synthetic, not a native Pod or
// the signed CLI installer. The enclosing responder checks literal rows twice.
func TestActivationEpochOwnedLifecycleAuthenticatesAndCloses(t *testing.T) {
	fixture := &baselineBehaviorActivationFixture{proofs: 2, rulePasses: 18}
	testBaselineBehaviorWholeProviderWithActivation(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, _ func() int) error {
		lifecycle, _, request := testOwnedActivationRequest(t, engine, snapshot, fixture)
		ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
		if lifecycle.check(ctx, TargetAuthenticated, snapshot, request.Options) != nil || fixture.forwards.Load() != 1 || fixture.apiCalls.Load() != 1 {
			t.Fatalf("owned production lifecycle failed one original native HTTPS activation: %s %s", diagnostic.Snapshot(), diagnostic.BoundarySnapshot())
		}
		if diagnostic.activation.step.Load() != uint32(activationComplete) {
			t.Fatal("activation completion was not closed with lifecycle ownership")
		}
		testOwnedActivationPinsReleased(t, fixture)
		return nil
	}, fixture)
}

func TestActivationEpochReadinessHasNoCredentialProbeOrAuthentication(t *testing.T) {
	fixture := &baselineBehaviorActivationFixture{}
	var secretReads atomic.Int32
	fixture.onRead = func(path string, _ map[installstate.Key]*unstructured.Unstructured) {
		if strings.Contains(path, "/secrets/") {
			secretReads.Add(1)
		}
	}
	testBaselineBehaviorWholeProviderWithActivation(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, _ func() int) error {
		_, checks, request := testOwnedActivationRequest(t, engine, snapshot, fixture)
		// Readiness does not acquire or read these nonexistent credentials.
		request.Options.Activation.CredentialFile += ".missing"
		request.Options.Activation.CAFile += ".missing"
		if checks.activation.waitEpochServing(t.Context(), request) != nil || secretReads.Load() != 0 || fixture.forwards.Load() != 0 || fixture.apiCalls.Load() != 0 {
			t.Fatal("read-only readiness consumed credentials, proofs or authentication")
		}
		// Admission's private pre-WAL wait has the same read-only contract.
		// The whole-provider responder independently requires zero behavioral
		// probes/rule reviews; no fake successful runtime guard is installed.
		ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
		defer cancel()
		if checks.prerequisites.waitOriginalServingStage(ctx, request.Snapshot, true) != nil || secretReads.Load() != 0 || fixture.forwards.Load() != 0 || fixture.apiCalls.Load() != 0 {
			t.Fatal("pre-WAL readiness consumed credentials, proofs or authentication")
		}
		return nil
	}, fixture)
	t.Run("readiness-does-not-authorize-public-observation", func(t *testing.T) {
		fixture := &baselineBehaviorActivationFixture{}
		var armed atomic.Bool
		var injected atomic.Bool
		fixture.onRead = func(path string, objects map[installstate.Key]*unstructured.Unstructured) {
			if armed.Load() && strings.Contains(path, "/validatingadmissionpolicies/") && injected.CompareAndSwap(false, true) {
				for key, object := range objects {
					if key.Kind == "ValidatingAdmissionPolicy" {
						object.Object["status"] = map[string]any{"observedGeneration": int64(0)}
						break
					}
				}
			}
		}
		testBaselineBehaviorWholeProviderWithActivation(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, _ func() int) error {
			_, checks, _ := testOwnedActivationRequest(t, engine, snapshot, fixture)
			if checks.prerequisites.waitOriginalServingStage(t.Context(), snapshot, true) != nil {
				t.Fatal("original read-only readiness refused")
			}
			// A successful private wait confers no public observation authority.
			// Withdraw policy health and require the actual native provider's
			// opening refusal, not a deadline or a fake successful guard.
			armed.Store(true)
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			serving, err := engine.ObserveServing(ctx, snapshot, checks.prerequisites.access.Serving())
			if err != ErrServing || serving != nil || !injected.Load() || diagnostic.BoundarySnapshot() != "operation=unknown baseline=actors" || fixture.forwards.Load() != 0 || fixture.apiCalls.Load() != 0 {
				t.Fatal("private readiness authorized unhealthy public observation", diagnostic.BoundarySnapshot())
			}
			return nil
		}, fixture)
	})
}

func TestActivationEpochOpeningRefusalBlocksForwardAndToken(t *testing.T) {
	fixture := &baselineBehaviorActivationFixture{}
	var armed atomic.Bool
	var injected atomic.Bool
	fixture.onRead = func(path string, objects map[installstate.Key]*unstructured.Unstructured) {
		if armed.Load() && strings.Contains(path, "/validatingadmissionpolicies/") && injected.CompareAndSwap(false, true) {
			for key, object := range objects {
				if key.Kind == "ValidatingAdmissionPolicy" {
					object.Object["status"] = map[string]any{"observedGeneration": int64(0)}
					break
				}
			}
		}
	}
	testBaselineBehaviorWholeProviderWithActivation(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, _ func() int) error {
		lifecycle, _, request := testOwnedActivationRequest(t, engine, snapshot, fixture)
		armed.Store(true)
		if lifecycle.check(t.Context(), TargetAuthenticated, snapshot, request.Options) != ErrLifecycle || !injected.Load() || fixture.forwards.Load() != 0 || fixture.apiCalls.Load() != 0 {
			t.Fatal("failed actual opening proof allowed forwarding, token or fallback")
		}
		testOwnedActivationPinsReleased(t, fixture)
		return nil
	}, fixture)
}

func TestActivationEpochDialReplacementBlocksTokenAndFallback(t *testing.T) {
	fixture := &baselineBehaviorActivationFixture{proofs: 1, rulePasses: 6}
	fixture.onUpgrade = func() {
		path := fixture.serving.options.CredentialFile
		body, err := os.ReadFile(path)
		if err != nil || os.WriteFile(path+".replacement", body, 0600) != nil || os.Rename(path+".replacement", path) != nil {
			t.Error("identical dial-window credential replacement unavailable")
		}
	}
	testBaselineBehaviorWholeProviderWithActivation(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, _ func() int) error {
		lifecycle, _, request := testOwnedActivationRequest(t, engine, snapshot, fixture)
		if lifecycle.check(t.Context(), TargetAuthenticated, snapshot, request.Options) != ErrLifecycle || fixture.forwards.Load() != 1 || fixture.apiCalls.Load() != 0 {
			t.Fatal("dial-time replacement sent a token, retried or fell back")
		}
		testOwnedActivationPinsReleased(t, fixture)
		return nil
	}, fixture)
}

func TestActivationEpochFinalJointPolicyDriftBlocksSuccess(t *testing.T) {
	fixture := &baselineBehaviorActivationFixture{proofs: 2, rulePasses: 15}
	var closingJoint atomic.Bool
	var injected atomic.Bool
	fixture.onRead = func(path string, objects map[installstate.Key]*unstructured.Unstructured) {
		if closingJoint.Load() && strings.HasSuffix(path, "/secrets/arcadectl-api-tls") && injected.CompareAndSwap(false, true) {
			for key, object := range objects {
				if key.Kind == "ValidatingAdmissionPolicy" {
					object.SetResourceVersion("late-policy-rv")
					break
				}
			}
		}
	}
	testBaselineBehaviorWholeProviderWithActivation(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, _ func() int) error {
		_, checks, request := testOwnedActivationRequest(t, engine, snapshot, fixture)
		owner, evidence, err := checks.beginTargetEpoch(t.Context(), request)
		if err != nil || owner == nil || evidence == nil || fixture.forwards.Load() != 1 || fixture.apiCalls.Load() != 1 {
			t.Fatal("owned authenticated opening unavailable for closing drift")
		}
		defer owner.release()
		copiedEvidence := &activationEvidence{self: evidence, owner: owner, serving: evidence.serving, binding: evidence.binding}
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		if owner.finish(t.Context(), copiedEvidence) != ErrActivation || owner.finish(canceled, evidence) != ErrActivation || owner.authPhase.Load() != activationAuthVerified {
			t.Fatal("copied evidence or canceled finish consumed the original owner")
		}
		// Arm only the final joint read; full closing prove has no Secret GET.
		closingJoint.Store(true)
		if owner.finish(t.Context(), evidence) != ErrActivation || !injected.Load() || owner.finish(t.Context(), evidence) != ErrActivation {
			t.Fatal("final policy drift escaped closing fence or consumed owner revived")
		}
		owner.release()
		testOwnedActivationPinsReleased(t, fixture)
		return nil
	}, fixture)
}

// Secrets are outside the behavioral policy/catalog fence. Drift during that
// substantial remote window must be checked against the same joint evidence,
// not accepted as a new credential floor after the fence finishes.
func TestActivationEpochSecretDriftDuringDialFenceBlocksToken(t *testing.T) {
	fixture := &baselineBehaviorActivationFixture{proofs: 1, rulePasses: 9}
	var connected atomic.Bool
	var injected atomic.Bool
	fixture.onUpgrade = func() { connected.Store(true) }
	fixture.onRead = func(path string, objects map[installstate.Key]*unstructured.Unstructured) {
		if connected.Load() && strings.Contains(path, "/validatingadmissionpolicies/") && injected.CompareAndSwap(false, true) {
			for key, object := range objects {
				if key.Kind == "Secret" && key.Name == "arcadectl-admin-credential" {
					object.SetResourceVersion("dial-fence-secret-rv")
					return
				}
			}
			t.Error("original retained admin Secret unavailable")
		}
	}
	testBaselineBehaviorWholeProviderWithActivation(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, _ func() int) error {
		lifecycle, _, request := testOwnedActivationRequest(t, engine, snapshot, fixture)
		if lifecycle.check(t.Context(), TargetAuthenticated, snapshot, request.Options) != ErrLifecycle || !injected.Load() || fixture.forwards.Load() != 1 || fixture.apiCalls.Load() != 0 {
			t.Fatal("post-connection fence Secret drift allowed token delivery or fallback")
		}
		testOwnedActivationPinsReleased(t, fixture)
		return nil
	}, fixture)
}

func TestActivationEpochSecretDriftDuringFinalFenceBlocksSuccess(t *testing.T) {
	fixture := &baselineBehaviorActivationFixture{proofs: 2, rulePasses: 18}
	var finishing atomic.Bool
	var jointRead atomic.Bool
	var injected atomic.Bool
	fixture.onRead = func(path string, objects map[installstate.Key]*unstructured.Unstructured) {
		if finishing.Load() && strings.HasSuffix(path, "/secrets/arcadectl-api-tls") {
			jointRead.Store(true)
		}
		if jointRead.Load() && strings.Contains(path, "/validatingadmissionpolicies/") && injected.CompareAndSwap(false, true) {
			for key, object := range objects {
				if key.Kind == "Secret" && key.Name == "arcadectl-api-tls" {
					object.SetResourceVersion("final-fence-secret-rv")
					return
				}
			}
			t.Error("original retained TLS Secret unavailable")
		}
	}
	testBaselineBehaviorWholeProviderWithActivation(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, _ func() int) error {
		_, checks, request := testOwnedActivationRequest(t, engine, snapshot, fixture)
		owner, evidence, err := checks.beginTargetEpoch(t.Context(), request)
		if err != nil || owner == nil || evidence == nil {
			t.Fatal("original authenticated owner unavailable for final Secret drift")
		}
		defer owner.release()
		finishing.Store(true)
		if owner.finish(t.Context(), evidence) != ErrActivation || !injected.Load() || owner.authPhase.Load() != activationAuthFinishing || fixture.forwards.Load() != 1 || fixture.apiCalls.Load() != 1 {
			t.Fatal("final fence Secret drift allowed successful completion")
		}
		owner.release()
		testOwnedActivationPinsReleased(t, fixture)
		return nil
	}, fixture)
}

func TestActivationEpochOwnerHeldThroughTrailingOriginalReplacement(t *testing.T) {
	fixture := &baselineBehaviorActivationFixture{proofs: 1, rulePasses: 9}
	var armed atomic.Bool
	var replaced atomic.Bool
	var namespaceReads atomic.Int32
	fixture.onRead = func(path string, _ map[installstate.Key]*unstructured.Unstructured) {
		if strings.HasSuffix(path, "/secrets/arcadectl-api-tls") && fixture.apiCalls.Load() == 1 {
			armed.Store(true)
		}
		// The first two Namespace reads close the post-auth joint reader.
		// The third is the actual lifecycle's trailing original journal load.
		if armed.Load() && path == "/api/v1/namespaces/"+fixture.serving.f.plan.Namespace() && namespaceReads.Add(1) == 3 && replaced.CompareAndSwap(false, true) {
			path := fixture.serving.options.CAFile
			if testBaselineReceiptDescriptors(t, filepath.Base(path)) != 1 {
				t.Error("owner released CA before trailing original read")
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Error("trailing original CA unavailable")
			}
			for range 2 {
				if os.WriteFile(path+".replacement", body, 0600) != nil || os.Rename(path+".replacement", path) != nil {
					t.Error("trailing identical CA replacement unavailable")
				}
			}
		}
	}
	testBaselineBehaviorWholeProviderWithActivation(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, _ func() int) error {
		lifecycle, _, request := testOwnedActivationRequest(t, engine, snapshot, fixture)
		if lifecycle.check(t.Context(), TargetAuthenticated, snapshot, request.Options) != ErrLifecycle || !replaced.Load() || fixture.forwards.Load() != 1 || fixture.apiCalls.Load() != 1 {
			t.Fatal("trailing identical replacement escaped held owner")
		}
		testOwnedActivationPinsReleased(t, fixture)
		return nil
	}, fixture)
}

func TestActivationEpochAuthenticatedOwnerCannotReplayOrFinishEarly(t *testing.T) {
	fixture := &baselineBehaviorActivationFixture{proofs: 2, rulePasses: 18}
	testBaselineBehaviorWholeProviderWithActivation(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, requests func() int) error {
		lifecycle, checks, request := testOwnedActivationRequest(t, engine, snapshot, fixture)
		owner, err := checks.activation.openActivationEpoch(t.Context(), request)
		if err != nil {
			t.Fatal("original owner unavailable for state-consumption proof")
		}
		defer owner.release()
		premature := &activationEvidence{owner: owner}
		premature.self = premature
		before := requests()
		if owner.finish(t.Context(), premature) != ErrActivation || requests() != before || owner.authPhase.Load() != activationAuthUnused {
			t.Fatal("unauthenticated owner performed closing work or consumed authority")
		}
		evidence, err := owner.authenticate(t.Context())
		if err != nil || evidence == nil {
			t.Fatal("actual one-connection authentication unavailable")
		}
		if _, err := lifecycle.original(t.Context(), snapshot); err != nil || owner.finish(t.Context(), evidence) != nil || owner.authPhase.Load() != activationAuthFinished {
			t.Fatal("original authenticated owner did not finish complete closing proof")
		}
		before = requests()
		if _, err := owner.authenticate(t.Context()); err != ErrActivation || owner.finish(t.Context(), evidence) != ErrActivation || requests() != before || fixture.forwards.Load() != 1 || fixture.apiCalls.Load() != 1 {
			t.Fatal("consumed owner replayed a proof or opened another connection")
		}
		owner.release()
		testOwnedActivationPinsReleased(t, fixture)
		return nil
	}, fixture)
}

func TestActivationEpochReleaseDuringRemoteReadBlocksAuthenticationReplay(t *testing.T) {
	fixture := &baselineBehaviorActivationFixture{proofs: 1, rulePasses: 6}
	var original atomic.Pointer[activationEpoch]
	var released atomic.Bool
	fixture.onRead = func(path string, _ map[installstate.Key]*unstructured.Unstructured) {
		owner := original.Load()
		if owner != nil && strings.Contains(path, "/secrets/") && released.CompareAndSwap(false, true) {
			// This is the remote HTTP handler, concurrent with the original
			// reader's in-flight request. Release never clears mutable fields.
			owner.release()
		}
	}
	testBaselineBehaviorWholeProviderWithActivation(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, _ *ClusterSecurityBaseline, requests func() int) error {
		_, checks, request := testOwnedActivationRequest(t, engine, snapshot, fixture)
		owner, err := checks.activation.openActivationEpoch(t.Context(), request)
		if err != nil {
			t.Fatal("actual opening owner unavailable for concurrent release")
		}
		defer owner.release()
		original.Store(owner)
		if _, err := owner.authenticate(t.Context()); err != ErrActivation || !released.Load() || owner.authPhase.Load() != activationAuthStarted || owner.phase.Load() != activationEpochReleased {
			t.Fatal("concurrent release escaped an actual remote joint read")
		}
		before := requests()
		if _, err := owner.authenticate(t.Context()); err != ErrActivation || requests() != before || fixture.forwards.Load() != 0 || fixture.apiCalls.Load() != 0 {
			t.Fatal("failed authentication replayed proof, connection or token")
		}
		testOwnedActivationPinsReleased(t, fixture)
		return nil
	}, fixture)
}
