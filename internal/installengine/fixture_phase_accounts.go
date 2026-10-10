// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"reflect"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type phaseServiceAccounts struct {
	observation *installobserve.ServiceAccountsObservation
	whole       map[installstate.Key]*unstructured.Unstructured
}

func fixtureAccountsRecipeMatches(d fixtureLedgerDocument, phase *fixturePhaseBaseline) bool {
	return validFixtureRecipe(d) && phase != nil && (d.Recipe == fixtureRecipeV3) == (phase.Accounts != nil)
}

// The complete raw LIST and every uncached whole GET must agree exactly.
// Administrator discovery/SSAR and original journal/namespace barriers are
// fresh; no runtime actor rights, token reads or ordinary-effect exemption.
func (a *ClusterAdmission) collectPhaseServiceAccounts(ctx context.Context, request LifecycleCheck) (*phaseServiceAccounts, error) {
	if ctx == nil || a == nil || a.prerequisites == nil || request.Snapshot == nil || request.Target == nil {
		return nil, ErrFixtures
	}
	p := a.prerequisites
	key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: request.Snapshot.Anchor().Namespace, Name: "default"}
	permission, err := publicPermission(key, "list")
	discovery, discoveryErr := p.access.discover(ctx, "v1")
	if err != nil || discoveryErr != nil || !discoveredPermission(discovery, permission) || p.access.authorize(ctx, permission.spec) != nil || p.original(ctx, request.Snapshot) != nil {
		return nil, ErrFixtures
	}
	observer, err := installobserve.New(p.access.readConfig(), p.engine.journal, request.Target)
	if err != nil {
		return nil, ErrFixtures
	}
	observation, err := observer.CollectServiceAccounts(ctx, request.Snapshot.Anchor())
	if err != nil || observation == nil || observation.Journal() == nil || observation.Journal().ResourceVersion() != request.Snapshot.ResourceVersion() || !bytes.Equal(observation.Journal().Bytes(), request.Snapshot.Bytes()) {
		return nil, ErrFixtures
	}
	accounts, raw := observation.Accounts(), observation.Whole()
	if accounts == nil || raw == nil || len(accounts.Items) != len(raw) {
		return nil, ErrFixtures
	}
	whole := make(map[installstate.Key]*unstructured.Unstructured, len(raw))
	for i, listed := range raw {
		key.Name = listed.GetName()
		permission, err := publicPermission(key, "get")
		if err != nil || !discoveredPermission(discovery, permission) || p.access.authorize(ctx, permission.spec) != nil {
			return nil, ErrFixtures
		}
		live, err := p.access.Get(ctx, key)
		var decoded corev1.ServiceAccount
		if err != nil || live == nil || !reflect.DeepEqual(listed.Object, live.Object) || decodeServing(live, &decoded) != nil || !reflect.DeepEqual(&accounts.Items[i], &decoded) || whole[key] != nil {
			return nil, ErrFixtures
		}
		whole[key] = live
	}
	if p.original(ctx, request.Snapshot) != nil {
		return nil, ErrFixtures
	}
	return &phaseServiceAccounts{observation, whole}, nil
}

func (accounts *phaseServiceAccounts) baseline(public []fixtureWorldRow, f *fixtureLedger) (*fixtureAccountBaseline, error) {
	if accounts == nil || accounts.observation == nil || accounts.observation.Accounts() == nil || accounts.whole == nil {
		return nil, ErrFixtures
	}
	publicAccounts := map[installstate.Key]fixtureWorldRow{}
	for _, row := range public {
		if row.Key.APIVersion == "v1" && row.Key.Kind == "ServiceAccount" {
			publicAccounts[row.Key] = row
		}
	}
	floor := &fixtureAccountBaseline{Version: "service-accounts-v1", Rows: []fixtureWorldRow{}}
	for key, object := range accounts.whole {
		if f != nil && key == f.document.Entries[fixtureTokenlessAccount].Key {
			continue
		}
		row, err := phaseRow(key, object.GetUID(), object.GetResourceVersion(), object.Object)
		if err != nil {
			return nil, ErrFixtures
		}
		if original, ok := publicAccounts[key]; ok {
			if original != row {
				return nil, ErrFixtures
			}
			delete(publicAccounts, key)
		} else {
			floor.Rows = append(floor.Rows, row)
		}
	}
	if len(publicAccounts) != 0 {
		return nil, ErrFixtures
	}
	sortFixtureWorlds(floor.Rows)
	return floor, nil
}

func phaseCollectionsWithAccounts(o *installobserve.Observation, accounts *phaseServiceAccounts) []phaseCollection {
	collections := phaseCollections(o)
	if accounts != nil && accounts.observation != nil {
		collections = append(collections, phaseCollection{"v1", "ServiceAccount", accounts.observation.Accounts()})
	}
	return collections
}

func samePhaseServiceAccounts(before, after *phaseServiceAccounts) bool {
	return before != nil && after != nil && reflect.DeepEqual(before.whole, after.whole)
}
