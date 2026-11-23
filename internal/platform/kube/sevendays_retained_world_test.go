// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube_test

import (
	"reflect"
	"strings"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/games/sevendays"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func TestSevenDaysObservedWorldSurvivesPlanTransitions(t *testing.T) {
	t.Parallel()

	// These are desired-resource plans, not running workloads. The exact PVC
	// UID below represents an already observed claim; no cluster is consulted.
	definition := sevendays.Definition()
	server := &arcadev1alpha1.GameServer{
		ObjectMeta: metav1.ObjectMeta{Name: "survival", Namespace: "survival-games", UID: "survival-server-uid"},
		Spec: arcadev1alpha1.GameServerSpec{
			Game:         definition.ID,
			ImageDigest:  "sha256:" + strings.Repeat("a", 64),
			DesiredState: arcadev1alpha1.DesiredStateRunning,
			Compute: arcadev1alpha1.ComputeSpec{
				CPURequest: resource.MustParse("500m"), CPULimit: resource.MustParse("2"),
				MemoryRequest: resource.MustParse("1Gi"), MemoryLimit: resource.MustParse("2Gi"),
			},
			Storage: arcadev1alpha1.StorageSpec{Size: resource.MustParse("10Gi")},
			Settings: runtime.RawExtension{Raw: []byte(
				`{"name":"Survival","description":"Original","visibility":"unlisted"}`)},
		},
	}
	opening, err := platformkube.Build(server, definition)
	if err != nil {
		t.Fatal(err)
	}
	if len(opening.DataClaims) != 1 || opening.DataClaims[0].Desired == nil || opening.DataIdentity == "" {
		t.Fatal("opening plan must identify one world claim")
	}
	world := opening.DataClaims[0].Desired.DeepCopy()
	const worldUID types.UID = "observed-world-pvc-uid"
	server.Status.ObservedData = &arcadev1alpha1.RetainedDataReference{
		Identity: opening.DataIdentity,
		Claims: []arcadev1alpha1.RetainedDataClaimReference{{
			Path: "world", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: world.Name, UID: string(worldUID)},
		}},
	}

	for _, transition := range []struct {
		name        string
		wantStopped bool
		prepare     func()
	}{
		{"stopped", true, func() { server.Spec.DesiredState = arcadev1alpha1.DesiredStateStopped }},
		{"restarted", false, func() { server.Spec.DesiredState = arcadev1alpha1.DesiredStateRunning }},
		{"configured", false, func() {
			server.Spec.Settings.Raw = []byte(`{"name":"Survival","description":"Changed","visibility":"unlisted"}`)
		}},
		{"image-updated", false, func() { server.Spec.ImageDigest = "sha256:" + strings.Repeat("b", 64) }},
		{"stopped-after-update", true, func() { server.Spec.DesiredState = arcadev1alpha1.DesiredStateStopped }},
		{"restarted-after-update", false, func() { server.Spec.DesiredState = arcadev1alpha1.DesiredStateRunning }},
	} {
		t.Run(transition.name, func(t *testing.T) {
			transition.prepare()
			plan, err := platformkube.Build(server, definition)
			if err != nil {
				t.Fatal(err)
			}
			if !plan.Reattach || plan.DataIdentity != opening.DataIdentity || len(plan.DataClaims) != 1 {
				t.Fatalf("transition changed the observed world identity: %#v", plan)
			}
			claim := plan.DataClaims[0]
			if claim.Desired == nil || claim.RequiredUID != worldUID || claim.Desired.Name != world.Name ||
				claim.Desired.Namespace != server.Namespace || claim.ExternallySelected {
				t.Fatalf("transition lost the exact observed claim binding: %#v", claim)
			}
			if len(claim.Desired.OwnerReferences) != 0 || claim.Desired.Labels[platformkube.LabelDataPolicy] != "retain" ||
				claim.Desired.Labels[platformkube.LabelDataIdentity] != opening.DataIdentity ||
				!reflect.DeepEqual(claim.Desired.Spec, world.Spec) {
				t.Fatalf("transition changed retained claim ownership, storage or identity: %#v", claim.Desired)
			}

			if transition.wantStopped {
				if plan.Workload != nil || plan.PlayerService != nil || plan.Configuration != nil {
					t.Fatal("stopped intent retained runtime resources")
				}
				return
			}
			if plan.Workload == nil || plan.PlayerService == nil || plan.Configuration == nil {
				t.Fatal("running intent lacks runtime resources")
			}
			pod := plan.Workload.Spec.Template.Spec
			if len(pod.Containers) != 1 || pod.Containers[0].Image != definition.ImageRepository+"@"+server.Spec.ImageDigest {
				t.Fatal("running plan did not use the requested immutable game image")
			}
			worldVolumes := 0
			for _, volume := range pod.Volumes {
				if volume.PersistentVolumeClaim != nil {
					worldVolumes++
					if volume.Name != "world" || volume.PersistentVolumeClaim.ClaimName != world.Name {
						t.Fatalf("running transition mounted another world: %#v", volume)
					}
				}
			}
			if worldVolumes != 1 {
				t.Fatalf("running world claim mounts = %d; want exactly one", worldVolumes)
			}
		})
	}
}
