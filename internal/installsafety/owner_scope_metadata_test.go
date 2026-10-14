// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"runtime"
	"strings"
	"testing"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func emptyOwnerScopeSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	_, s, _ := safetyFixture(t)
	s.Owners = nil
	s.Policies.Items = nil
	s.Bindings.Items = nil
	s.Secrets.Items = nil
	return s
}

func TestOwnerClosureScopesMatchWholeSignedObjects(t *testing.T) {
	base := emptyOwnerScopeSnapshot(t)
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
			want := map[string]bool{"v1/ConfigMap": true, "apps/v1/ReplicaSet": true}
			// Independent oracle: scope comes from full signed objects.
			for _, r := range plan.Resources() {
				want[r.Object.GetAPIVersion()+"/"+r.Object.GetKind()] = r.Object.GetNamespace() != ""
			}
			for _, kind := range []string{"GameServer", "GameBackup", "GameRestore", "GameDestroy", "ArcadeOperation"} {
				want[arcade.GroupVersion.String()+"/"+kind] = true
			}
			for _, pair := range []string{"batch/v1/Job", "v1/Pod", "coordination.k8s.io/v1/Lease", "v1/PersistentVolumeClaim", "v1/Secret"} {
				want[pair] = true
			}
			for pair, scope := range want {
				t.Run(pair, func(t *testing.T) {
					i := strings.LastIndex(pair, "/")
					key := installstate.Key{APIVersion: pair[:i], Kind: pair[i+1:], Name: "scope-evidence"}
					if scope {
						key.Namespace = plan.Namespace()
					}
					s := cloneSnapshot(base)
					s.Owners = []OwnerNode{{Key: key, Metadata: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace, UID: "scope-uid", ResourceVersion: "1"}}}
					// This unreferenced-node fixture tests scope, not retention authority.
					if err := validateOwnerClosure(plan, s, nil, nil, nil); err != nil {
						t.Fatalf("signed object scope refused: %v", err)
					}
					if scope {
						s.Owners[0].Key.Namespace = ""
					} else {
						s.Owners[0].Key.Namespace = plan.Namespace()
					}
					s.Owners[0].Metadata.Namespace = s.Owners[0].Key.Namespace
					if err := validateOwnerClosure(plan, s, nil, nil, nil); !errors.Is(err, ErrOwnership) {
						t.Fatalf("opposite REST scope accepted: %v", err)
					}
				})
			}
		})
	}
}

func TestOwnerClosureScopeValidationAvoidsWholeSchemaCopies(t *testing.T) {
	plan := ownerScopePlan(t, false, "isolated-scopes", installrender.Profile135)
	s := emptyOwnerScopeSnapshot(t)
	if err := validateOwnerClosure(plan, s, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	whole := testing.AllocsPerRun(3, func() { runtime.KeepAlive(plan.Resources()) })
	var err error
	closure := testing.AllocsPerRun(3, func() { err = validateOwnerClosure(plan, s, nil, nil, nil) })
	if err != nil || closure >= whole {
		t.Fatalf("closure still allocates whole-schema scale: closure=%.0f whole=%.0f err=%v", closure, whole, err)
	}
	t.Logf("allocations per local empty closure: closure=%.0f whole signed objects=%.0f", closure, whole)
}
