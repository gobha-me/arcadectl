//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/util/wait"
)

// Actual full production driver, not the earlier component helpers. Each run
// owns an empty disposable cluster; no live world, credential publication or
// user namespace is involved. This is still NOT signed-binary lifecycle CI.
func TestKindAdmissionEffectiveFullMatrix(t *testing.T) {
	for _, profile := range []struct{ id, node string }{{installrender.Profile135, targetKind135}, {installrender.Profile137, targetKind137}} {
		t.Run(profile.id, func(t *testing.T) {
			for _, mode := range []string{"cold", "warm"} {
				t.Run(mode, func(t *testing.T) {
					warm := mode == "warm"
					ctx, config, apiImage, controllerImage := targetKindFixtureImagesV2(t, profile.node, warm)
					if !warm {
						controllerImage = "registry.example/controller@sha256:" + string(bytes.Repeat([]byte("a"), 64))
					}
					plan := fixturePlanImages(t, "isolated-install", profile.id, installpackage.Images{Controller: controllerImage, API: apiImage})
					access, engine, store, snapshot, _ := targetKindInstallation(t, ctx, config, plan, warm)
					p, err := NewClusterPrerequisites(engine, access)
					if err != nil {
						t.Fatal("original prerequisites unavailable")
					}
					request := LifecycleCheck{Checkpoint: AdmissionEffective, Snapshot: snapshot, Mode: installstate.Install, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
					if warm {
						controllers, err := NewClusterControllers(p)
						ready := request
						ready.Checkpoint = ControllersAvailable
						if err != nil || wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
							return controllers.Verify(ctx, ready) == nil, nil
						}) != nil {
							t.Fatal("original warm controllers did not converge")
						}
					}
					var previous *Serving
					var quiet time.Time
					if wait.PollUntilContextTimeout(ctx, time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
						fresh, err := engine.ObserveServing(ctx, snapshot, access.Serving())
						if err != nil || fresh == nil {
							previous, quiet = nil, time.Time{}
							return false, nil
						}
						if previous == nil || previous.fingerprint != fresh.fingerprint {
							previous, quiet = fresh, time.Now()
						}
						return time.Since(quiet) >= 5*time.Second, nil
					}) != nil {
						t.Fatal("original runtime did not settle")
					}
					admission, err := NewClusterAdmission(engine, access)
					if err != nil {
						t.Fatal("original admission unavailable")
					}
					t.Log("running all 55 production cases, persistent setups, original-only cleanup and retirement")
					if err := admission.VerifyEffective(ctx, request); err != nil {
						t.Fatal("public full production admission refused")
					}
					retirement, err := engine.readFixtureRetirement(snapshot.Anchor())
					if err != nil || retirement.record.State != fixtureRetired {
						t.Fatal("public full verifier did not retire its original run")
					}
					archive, err := engine.decodeFixtureLedger(retirement.archive)
					if err != nil || archive.Recipe != fixtureRecipeV2 || archive.Behavior == nil || archive.Behavior.Version != fixtureBehaviorVersionV2 || !validFixtureBehaviorDocument(archive) || archive.DestroySeed == nil || archive.RetainedMarker == nil {
						t.Fatal("public full verifier omitted matrix or setup completion")
					}
					for _, entry := range archive.Entries {
						if entry.State != fixtureAbsent || !nativeFixtureUID(string(entry.OriginalUID)) {
							t.Fatal("public full verifier left an original fixture unresolved")
						}
					}
					fresh, err := store.Load(ctx, snapshot.Anchor())
					if err != nil || !bytes.Equal(fresh.Bytes(), snapshot.Bytes()) || fresh.ResourceVersion() != snapshot.ResourceVersion() || engine.fixtureFence(snapshot) != nil {
						t.Fatal("full admission changed original journal or left unresolved originals")
					}
				})
			}
		})
	}
}
