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

// Independent old-path oracle: copy every signed object before filtering.
func wholeResourcesByKind(p *Plan, kinds ...string) []Resource {
	var result []Resource
	for _, r := range p.Resources() {
		for _, kind := range kinds {
			if r.Object.GetKind() == kind {
				result = append(result, r)
				break
			}
		}
	}
	return result
}

// Change every nested scalar in the returned maps/slices, not just metadata.
func mutateSelectedJSON(value any) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			switch child.(type) {
			case map[string]any, []any:
				mutateSelectedJSON(child)
			default:
				value[key] = "local-mutation"
			}
		}
	case []any:
		for i, child := range value {
			switch child.(type) {
			case map[string]any, []any:
				mutateSelectedJSON(child)
			default:
				value[i] = "local-mutation"
			}
		}
	}
}

func TestResourcesByKindMatchesWholeFilterAndIsDefensive(t *testing.T) {
	for _, tc := range []struct {
		legacy             bool
		namespace, profile string
	}{
		{false, DefaultNamespace, Profile135}, {false, DefaultNamespace, Profile137},
		{false, "isolated-kind-union", Profile135}, {false, "isolated-kind-union", Profile137},
		{false, strings.Repeat("a", 63), Profile135}, {true, DefaultNamespace, Profile137},
	} {
		t.Run(tc.namespace+"/"+tc.profile+map[bool]string{false: "/current", true: "/predecessor"}[tc.legacy], func(t *testing.T) {
			p := mustCompile(t, tc.legacy, tc.namespace, tc.profile)
			before := p.Resources()
			for _, kinds := range [][]string{
				nil, {""}, {"unknown", "service"}, {"Service"},
				{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"},
				{"ValidatingAdmissionPolicyBinding", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "unknown"},
				{"CustomResourceDefinition", "Deployment", "Role", "Service", "ConfigMap"},
			} {
				want := wholeResourcesByKind(p, kinds...)
				got := p.ResourcesByKind(kinds...)
				if !reflect.DeepEqual(got, want) {
					t.Fatal("selected whole resources differ in order, object or contract flags")
				}
				for i := range got {
					mutateSelectedJSON(got[i].Object.Object)
					got[i].Retained = !got[i].Retained
					got[i].Phase = "local-mutation"
				}
				if !reflect.DeepEqual(p.Resources(), before) || !reflect.DeepEqual(p.ResourcesByKind(kinds...), want) {
					t.Fatal("returned nested objects or flags changed the sealed plan")
				}
				var wg sync.WaitGroup
				for range 4 {
					wg.Go(func() {
						for range 3 {
							copy := p.ResourcesByKind(kinds...)
							if !reflect.DeepEqual(copy, want) {
								t.Error("concurrent immutable kind union changed")
							}
							for i := range copy {
								mutateSelectedJSON(copy[i].Object.Object)
								copy[i].Phase = "local-mutation"
							}
						}
					})
				}
				wg.Wait()
			}
		})
	}
	var absent *Plan
	if absent.ResourcesByKind("Service") != nil || (&Plan{}).ResourcesByKind("Service") != nil {
		t.Fatal("absent plan produced desired resources")
	}
}

func TestResourcesByKindAvoidsDiscardedSchemaAllocations(t *testing.T) {
	for _, profile := range []string{Profile135, Profile137} {
		t.Run(profile, func(t *testing.T) {
			p := mustCompile(t, false, "isolated-kind-allocation", profile)
			for _, kinds := range [][]string{{"Service"}, {"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}} {
				whole := testing.AllocsPerRun(3, func() { runtime.KeepAlive(wholeResourcesByKind(p, kinds...)) })
				selected := testing.AllocsPerRun(3, func() { runtime.KeepAlive(p.ResourcesByKind(kinds...)) })
				if selected >= whole {
					t.Fatal("kind filtering did not avoid discarded schema allocations")
				}
				t.Logf("kind union %v allocations: whole-then-filter=%.0f selected=%.0f", kinds, whole, selected)
			}
		})
	}
}
