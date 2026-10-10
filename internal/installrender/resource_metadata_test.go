// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installrender

import (
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestResourceMetadataMatchesSignedParameterizedResourcesAndIsDefensive(t *testing.T) {
	for _, tc := range []struct {
		legacy             bool
		namespace, profile string
	}{
		{false, DefaultNamespace, Profile135}, {false, DefaultNamespace, Profile137},
		{false, "isolated-metadata", Profile135}, {false, "isolated-metadata", Profile137},
		{false, strings.Repeat("a", 63), Profile135}, {true, DefaultNamespace, Profile137},
	} {
		t.Run(tc.namespace+"/"+tc.profile+map[bool]string{false: "/current", true: "/predecessor"}[tc.legacy], func(t *testing.T) {
			p := mustCompile(t, tc.legacy, tc.namespace, tc.profile)
			objects := p.Resources()
			want := make([]ResourceMetadata, len(objects))
			for i, r := range objects {
				want[i] = ResourceMetadata{APIVersion: r.Object.GetAPIVersion(), Kind: r.Object.GetKind(), Namespace: r.Object.GetNamespace(), Name: r.Object.GetName(), Retained: r.Retained, Phase: r.Phase}
			}
			if len(want) != 38 || !reflect.DeepEqual(p.ResourceMetadata(), want) {
				t.Fatal("metadata differs from whole signed resources")
			}
			returned := p.ResourceMetadata()
			for i := range returned {
				returned[i] = ResourceMetadata{APIVersion: "foreign", Kind: "foreign", Namespace: "foreign", Name: "foreign", Retained: !want[i].Retained, Phase: "foreign"}
			}
			for i := range objects {
				objects[i].Object.SetName("foreign")
				objects[i].Object.SetNamespace("foreign")
				objects[i].Retained = !objects[i].Retained
				objects[i].Phase = "foreign"
			}
			if !reflect.DeepEqual(p.ResourceMetadata(), want) {
				t.Fatal("returned metadata/objects changed the sealed plan")
			}
			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() {
					for range 10 {
						copy := p.ResourceMetadata()
						if !reflect.DeepEqual(copy, want) {
							t.Error("concurrent immutable metadata changed")
						}
						copy[0].Name = "local-mutation"
					}
				})
			}
			wg.Wait()
		})
	}
	var absent *Plan
	if absent.ResourceMetadata() != nil {
		t.Fatal("nil plan produced metadata")
	}
}

func TestResourceMetadataAllocationProfile(t *testing.T) {
	p := mustCompile(t, false, "isolated-metadata", Profile135)
	whole := testing.AllocsPerRun(3, func() { runtime.KeepAlive(p.Resources()) })
	metadata := testing.AllocsPerRun(3, func() { runtime.KeepAlive(p.ResourceMetadata()) })
	t.Logf("allocations per complete read: whole objects=%.0f metadata=%.0f", whole, metadata)
}
