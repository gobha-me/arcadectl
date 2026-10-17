// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/types"
)

// Independent old-path oracle: derive addresses and flags from full signed
// objects, not from the value-only projection being tested.
func wholeObjectInventoryContract(plan *installrender.Plan, inventory []installstate.Resource) (map[installstate.Key]types.UID, map[types.UID]bool, error) {
	if len(inventory) == 0 || len(inventory) > installstate.MaxResources {
		return nil, nil, ErrOwnership
	}
	contracts := map[installstate.Key]installrender.Resource{}
	for _, r := range plan.Resources() {
		o := r.Object
		contracts[installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}] = r
	}
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		contracts[installstate.Key{APIVersion: "v1", Kind: "Secret", Namespace: plan.Namespace(), Name: name}] = installrender.Resource{Retained: true, Phase: installrender.API}
	}
	owned, removable, seen := map[installstate.Key]types.UID{}, map[types.UID]bool{}, map[types.UID]bool{}
	for _, r := range inventory {
		contract, ok := contracts[r.Key]
		if !ok || r.UID == "" || len(r.UID) > 128 || strings.ContainsAny(string(r.UID), "\r\n\x00") || seen[r.UID] || owned[r.Key] != "" || r.Retained != contract.Retained || r.Phase != contract.Phase {
			return nil, nil, ErrOwnership
		}
		owned[r.Key], seen[r.UID] = r.UID, true
		if !r.Retained {
			removable[r.UID] = true
		}
	}
	if owned[installstate.Key{APIVersion: "v1", Kind: "Namespace", Name: plan.Namespace()}] == "" {
		return nil, nil, ErrOwnership
	}
	return owned, removable, nil
}

func TestInventoryMetadataMatchesWholeSignedContract(t *testing.T) {
	for _, tc := range []struct {
		legacy             bool
		namespace, profile string
	}{
		{false, installrender.DefaultNamespace, installrender.Profile135},
		{false, installrender.DefaultNamespace, installrender.Profile137},
		{false, "isolated-inventory", installrender.Profile135},
		{false, "isolated-inventory", installrender.Profile137},
		{false, strings.Repeat("a", 63), installrender.Profile135},
		{true, installrender.DefaultNamespace, installrender.Profile137},
	} {
		name := tc.namespace + "/" + tc.profile
		if tc.legacy {
			name += "/predecessor"
		}
		t.Run(name, func(t *testing.T) {
			plan := ownerScopePlan(t, tc.legacy, tc.namespace, tc.profile)
			var inventory []installstate.Resource
			for i, r := range plan.Resources() {
				o := r.Object
				inventory = append(inventory, installstate.Resource{Key: installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}, UID: types.UID(fmt.Sprintf("original-%d", i)), Retained: r.Retained, Phase: r.Phase})
			}
			for i, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
				inventory = append(inventory, installstate.Resource{Key: installstate.Key{APIVersion: "v1", Kind: "Secret", Namespace: plan.Namespace(), Name: name}, UID: types.UID(fmt.Sprintf("credential-%d", i)), Retained: true, Phase: installrender.API})
			}
			for label, change := range map[string]func([]installstate.Resource) []installstate.Resource{
				"whole": func(v []installstate.Resource) []installstate.Resource { return v },
				"empty": func([]installstate.Resource) []installstate.Resource { return nil },
				"oversized": func(v []installstate.Resource) []installstate.Resource {
					return make([]installstate.Resource, installstate.MaxResources+1)
				},
				"missing-uid": func(v []installstate.Resource) []installstate.Resource { v[0].UID = ""; return v },
				"oversized-uid": func(v []installstate.Resource) []installstate.Resource {
					v[0].UID = types.UID(strings.Repeat("a", 129))
					return v
				},
				"control-uid":    func(v []installstate.Resource) []installstate.Resource { v[0].UID = "invalid\nuid"; return v },
				"duplicate-uid":  func(v []installstate.Resource) []installstate.Resource { v[1].UID = v[0].UID; return v },
				"duplicate-key":  func(v []installstate.Resource) []installstate.Resource { v[1].Key = v[0].Key; return v },
				"unknown-key":    func(v []installstate.Resource) []installstate.Resource { v[0].Key.Name = "unowned"; return v },
				"wrong-retained": func(v []installstate.Resource) []installstate.Resource { v[0].Retained = !v[0].Retained; return v },
				"wrong-phase":    func(v []installstate.Resource) []installstate.Resource { v[0].Phase = "unrecognized"; return v },
				"missing-namespace": func(v []installstate.Resource) []installstate.Resource {
					result := v[:0]
					for _, r := range v {
						if r.Key.Kind != "Namespace" {
							result = append(result, r)
						}
					}
					return result
				},
				"wrong-secret-retention": func(v []installstate.Resource) []installstate.Resource { v[len(v)-1].Retained = false; return v },
				"wrong-secret-phase":     func(v []installstate.Resource) []installstate.Resource { v[len(v)-2].Phase = "unrecognized"; return v },
			} {
				t.Run(label, func(t *testing.T) {
					input := change(append([]installstate.Resource(nil), inventory...))
					saved := append([]installstate.Resource(nil), input...)
					wantOwned, wantRemovable, wantErr := wholeObjectInventoryContract(plan, input)
					owned, removable, err := inventoryContract(plan, input)
					if err != wantErr || !reflect.DeepEqual(owned, wantOwned) || !reflect.DeepEqual(removable, wantRemovable) || !reflect.DeepEqual(input, saved) {
						t.Fatal("value-only inventory changed whole-object ownership contract or input")
					}
					if (err == nil) != (label == "whole") {
						t.Fatal("inventory control did not isolate the expected acceptance/refusal")
					}
				})
			}
			full := testing.AllocsPerRun(3, func() { _, _, _ = wholeObjectInventoryContract(plan, inventory) })
			metadata := testing.AllocsPerRun(3, func() { _, _, _ = inventoryContract(plan, inventory) })
			if metadata >= full/2 {
				t.Fatal("inventory metadata derivation still copies whole signed schemas")
			}
			t.Logf("local inventory construction allocations metadata=%.0f whole=%.0f", metadata, full)
		})
	}
}
