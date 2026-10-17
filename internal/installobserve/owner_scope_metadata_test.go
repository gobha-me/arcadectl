// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installsafety"
)

func ownerScopePlan(t *testing.T, legacy bool, namespace, profile string) *installrender.Plan {
	t.Helper()
	images := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("a", 64), API: "registry.example/api@sha256:" + strings.Repeat("b", 64)}
	payloads, crds, err := installrender.RenderPayloads(images, legacy)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Repeat("c", 40)
	if legacy {
		source = installrender.LegacySourceSHA
	}
	body, err := installpackage.Build(installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: source, SourceEpoch: 1791223200, Images: images, Profiles: installrender.SupportedProfiles(legacy), Prerequisites: installrender.RequiredPrerequisites(), CRDs: crds}, payloads)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	signature, err := installpackage.Sign(body, key)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := installpackage.Verify(body, signature, payloads, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := installrender.Compile(pkg, namespace, profile)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestOwnerGraphScopesMatchWholeSignedObjects(t *testing.T) {
	for _, tc := range []struct {
		legacy             bool
		namespace, profile string
	}{
		{false, installrender.DefaultNamespace, installrender.Profile135},
		{false, installrender.DefaultNamespace, installrender.Profile137},
		{false, "isolated-scopes", installrender.Profile135},
		{false, "isolated-scopes", installrender.Profile137},
		{false, strings.Repeat("a", 63), installrender.Profile135},
		{true, installrender.DefaultNamespace, installrender.Profile137},
	} {
		name := tc.namespace + "/" + tc.profile
		if tc.legacy {
			name += "/predecessor"
		}
		t.Run(name, func(t *testing.T) {
			plan := ownerScopePlan(t, tc.legacy, tc.namespace, tc.profile)
			cs := append(collections(&installsafety.Snapshot{}), runtimeCollections(&installsafety.RuntimeSnapshot{})...)
			// Signed resources must still override conflicting collection hints.
			cs = append(cs, collection{gv: "rbac.authorization.k8s.io/v1", kind: "Role", namespaced: false})
			want := map[string]bool{}
			for _, c := range cs {
				want[c.gv+"/"+c.kind] = c.namespaced
			}
			// Independent oracle: use full signed objects, never ResourceMetadata.
			for _, r := range plan.Resources() {
				want[r.Object.GetAPIVersion()+"/"+r.Object.GetKind()] = r.Object.GetNamespace() != ""
			}
			for pair, scope := range map[string]bool{
				"v1/Namespace": false, "v1/ConfigMap": true, "v1/ServiceAccount": true, "v1/Service": true,
				"apps/v1/Deployment": true, "apps/v1/ReplicaSet": true,
				"rbac.authorization.k8s.io/v1/Role": true, "rbac.authorization.k8s.io/v1/RoleBinding": true,
				"rbac.authorization.k8s.io/v1/ClusterRole": false, "rbac.authorization.k8s.io/v1/ClusterRoleBinding": false,
				"apiextensions.k8s.io/v1/CustomResourceDefinition": false,
			} {
				if _, exists := want[pair]; !exists {
					want[pair] = scope
				}
			}
			observer := &Observer{plan: plan}
			graph := newOwnerGraph(observer, nil, cs)
			if !reflect.DeepEqual(graph.scopes, want) {
				t.Fatal("owner graph scopes differ from whole signed objects and fixed known scopes")
			}
			for pair, scope := range map[string]bool{
				"v1/Namespace": false, "apiextensions.k8s.io/v1/CustomResourceDefinition": false,
				"rbac.authorization.k8s.io/v1/ClusterRole": false, "rbac.authorization.k8s.io/v1/ClusterRoleBinding": false,
				"rbac.authorization.k8s.io/v1/Role": true, "rbac.authorization.k8s.io/v1/RoleBinding": true,
				"apps/v1/Deployment": true, "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy": false,
				"admissionregistration.k8s.io/v1/ValidatingAdmissionPolicyBinding": false,
			} {
				if actual, exists := graph.scopes[pair]; !exists || actual != scope {
					t.Fatalf("wrong known scope for %s", pair)
				}
			}
			graph.scopes["v1/Namespace"] = true
			if !reflect.DeepEqual(newOwnerGraph(observer, nil, cs).scopes, want) {
				t.Fatal("one graph changed the sealed plan or a later graph")
			}
		})
	}
}

func TestOwnerGraphConstructionAvoidsWholeSchemaCopies(t *testing.T) {
	plan := ownerScopePlan(t, false, "isolated-scopes", installrender.Profile135)
	observer := &Observer{plan: plan}
	whole := testing.AllocsPerRun(3, func() { runtime.KeepAlive(plan.Resources()) })
	graph := testing.AllocsPerRun(3, func() { runtime.KeepAlive(newOwnerGraph(observer, nil, nil)) })
	if graph >= whole {
		t.Fatalf("graph still allocates whole-schema scale: graph=%.0f whole=%.0f", graph, whole)
	}
	t.Logf("allocations per local construction: graph=%.0f whole signed objects=%.0f", graph, whole)
}
