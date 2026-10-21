// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installerprofile"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Real driver/setup/phase/WAL plumbing over synthetic HTTPS replies. This is a
// bounded case-zero refusal, NOT native admission or all-55 completion evidence.
func TestFixtureMatrixProfileDriverHelper(t *testing.T) {
	mode := os.Getenv("ARCADECTL_MATRIX_DRIVER_TEST_HELPER")
	if mode == "" {
		return
	}
	session := installerprofile.StartInherited()
	if session == nil {
		t.Fatal("owned deferred session unavailable")
	}
	defer session.Stop()
	// Race instrumentation makes the many sealed observer/file checks slower;
	// this bounds only this new synthetic subprocess, not any installer budget.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	ctx = installerprofile.WithFirstUpgradeMatrix(ctx, "upgrade", session)
	setup := func(h *fixturePhaseTest) {
		instrumentFreshFixtureRecipeV2(t, h.f.wire.ledger)
		base := h.f.actor.fixtureHandler
		h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
			for key, object := range h.f.actor.v.f.access.objects {
				if key.Kind != "Secret" {
					continue
				}
				path, err := privateSecretPath(key, false)
				if err != nil || path != r.URL.Path {
					continue
				}
				if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadata") {
					t.Error("fixture requested private Secret data")
					w.WriteHeader(403)
					return true
				}
				encodeStoppedObject(t, w, r, object)
				return true
			}
			return base(w, r)
		}
	}
	var h *fixturePhaseTest
	if mode == "non-upgrade" {
		h = fixturePhaseFactoryWithSetup(t, setup)(t)
	} else {
		previous, target := lifecycleTransitionPlans(t)
		v := newLifecycleFixturePlans(t, previous, target)
		snapshot := v.finish(t, v.f.snapshot)
		snapshot, err := v.l.Begin(ctx, snapshot, installstate.Upgrade, target.Digest(), v.opts)
		if err != nil {
			t.Fatal("genuine Upgrade transition unavailable")
		}
		stopped := false
		for range 100 {
			snapshot, err = v.l.Step(ctx, snapshot, v.opts)
			if err != nil {
				t.Fatal("Upgrade admission checkpoint unavailable")
			}
			if snapshot.Document().Stage == installstate.Applying {
				stopped = true
				break
			}
		}
		if !stopped || snapshot.Document().Mode != installstate.Upgrade {
			t.Fatal("Upgrade checkpoint not reached")
		}
		for _, secret := range v.private.objects {
			metadata := secret.DeepCopy()
			metadata.Data, metadata.StringData = nil, nil
			metadata.APIVersion, metadata.Kind = "v1", "Secret"
			v.f.access.objects[secretKey(metadata.Namespace, metadata.Name)] = servingObject(t, metadata)
		}
		actor := newActorFixtureAtCheckpointPlans(t, v, snapshot, previous, target)
		actor.request.Options.Now = time.Now().UTC()
		h = fixturePhaseFactoryFromWireFactory(t, func(t *testing.T) *fixtureWireTest { return newFixtureWireTestAtActor(t, actor) }, setup)(t)
	}
	initial, err := h.f.actor.admission.captureInitialPhase(ctx, h.f.actor.request)
	if err != nil {
		t.Fatal("initial original phase unavailable")
	}
	ledger := h.f.wire.ledger
	created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
	h.f.reply = func(w http.ResponseWriter, object *unstructured.Unstructured) {
		if mode == "setup-refusal" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		slot := -1
		for index, entry := range ledger.document.Entries {
			if entry.Key.Name == object.GetName() {
				slot = index
			}
		}
		if slot < 0 {
			t.Error("reply escaped original fixture catalog")
			w.WriteHeader(500)
			return
		}
		if ledger.document.Entries[slot].State == fixturePlanned {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(object.Object)
			return
		}
		ack := fixtureResultExample(t, ledger, slot, fixtureAcknowledgedResult, created)
		ack.SetUID(object.GetUID())
		stable := fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
		stable.SetUID(object.GetUID())
		h.f.objects[slot] = stable
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ack.Object)
	}
	base := h.f.actor.fixtureHandler
	var reached, active atomic.Bool
	h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			var review authv1.SelfSubjectAccessReview
			if err == nil && json.Unmarshal(body, &review) == nil && review.Spec.ResourceAttributes != nil && review.Spec.ResourceAttributes.Verb == "get" && strings.HasSuffix(review.Spec.ResourceAttributes.Name, "-case-00") {
				review.Status.Allowed = true
				_ = json.NewEncoder(w).Encode(review)
				return true
			}
		}
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "-case-00") {
			reached.Store(true)
			// Probe global profiler occupancy at the actual first case. If it is
			// free, stop ONLY this test's successful probe, never another owner.
			if pprof.StartCPUProfile(io.Discard) != nil {
				active.Store(true)
			} else {
				pprof.StopCPUProfile()
			}
			w.WriteHeader(http.StatusForbidden) // Deliberate case-zero refusal.
			return true
		}
		return base(w, r)
	}
	driver := &fixtureAdmissionDriver{wire: h.f.wire, initial: initial}
	runErr := driver.run(ctx)
	t.Logf("matrix-hook-counts previews=%d creates=%d deletes=%d seeds=%d reached=%t active=%t previous=%t", h.f.previews, h.f.creates, h.f.deletes, h.f.seeds, reached.Load(), active.Load(), driver.previous != nil)
	if runErr != ErrFixtures || !driver.failed || driver.next != 0 || driver.completed != 0 || ledger.behaviorCompletion != nil || h.f.deletes != 0 || h.f.seeds != 0 {
		t.Fatal("diagnostic changed driver refusal, case or effect census")
	}
	if mode == "setup-refusal" {
		if reached.Load() || h.f.previews != 1 || h.f.creates != 0 || driver.previous != nil {
			t.Fatal("failed setup entered matrix or created originals")
		}
	} else if !reached.Load() || h.f.previews != 11 || h.f.creates != 11 || driver.previous == nil || active.Load() != (mode == "upgrade") {
		t.Fatal("actual first case lacked complete setup, exact census or mode-bound capture")
	}
	if mode == "upgrade" && installerprofile.BeginFirstUpgradeMatrix(ctx) != nil {
		t.Fatal("later driver could rearm command capture")
	}
	if mode == "upgrade" {
		// The matrix-return defer must request stop before command-exit Stop.
		// Successfully acquiring a new test-owned profiler proves the previous
		// owner has joined; never stop a failed acquisition/another profiler.
		deadline := time.Now().Add(5 * time.Second)
		for {
			if pprof.StartCPUProfile(io.Discard) == nil {
				pprof.StopCPUProfile()
				break
			}
			if !time.Now().Before(deadline) {
				t.Fatal("matrix return did not request asynchronous stop")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !session.Stop() {
		t.Fatal("owned diagnostic finalization incomplete")
	}
}

func TestFixtureMatrixProfileActualDriverPlacement(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("owned test executable unavailable")
	}
	for _, mode := range []string{"upgrade", "non-upgrade", "setup-refusal"} {
		t.Run(mode, func(t *testing.T) {
			capture, err := installerprofile.NewFirstUpgradeMatrixCapture()
			if err != nil {
				t.Fatal("owned matrix capture unavailable")
			}
			defer capture.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestFixtureMatrixProfileDriverHelper$")
			command.Env = append(os.Environ(), "ARCADECTL_MATRIX_DRIVER_TEST_HELPER="+mode)
			var output bytes.Buffer // RAM only; never expose raw testing/provider output.
			command.Stdout, command.Stderr = &output, &output
			body, diagnostic, commandErr := capture.Run(command)
			if commandErr != nil || command.ProcessState == nil || !command.ProcessState.Success() {
				counts := regexp.MustCompile(`matrix-hook-counts previews=[0-9]+ creates=[0-9]+ deletes=[0-9]+ seeds=[0-9]+ reached=(?:true|false) active=(?:true|false) previous=(?:true|false)`).Find(output.Bytes())
				fixedFailure := "unclassified-test-refusal"
				for _, message := range []string{"initial sealed phase unavailable", "initial original phase unavailable", "Upgrade admission checkpoint unavailable", "genuine Upgrade transition unavailable", "Upgrade checkpoint not reached", "actual first case lacked complete setup, exact census or mode-bound capture", "failed setup entered matrix or created originals", "owned diagnostic finalization incomplete"} {
					if bytes.Contains(output.Bytes(), []byte(message)) {
						fixedFailure = message
						break
					}
				}
				t.Fatalf("actual driver placement child failed %s; %s; %s", mode, counts, fixedFailure)
			}
			if mode == "upgrade" {
				if diagnostic != nil || len(body) == 0 {
					t.Fatal("successful Upgrade setup did not start capture")
				}
			} else if body != nil || !installerprofile.FirstUpgradeMatrixNotStarted(diagnostic) {
				t.Fatal("failed setup or non-Upgrade started capture")
			}
		})
	}
}
