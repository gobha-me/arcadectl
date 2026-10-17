// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"strings"
	"sync"

	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
)

// Private GET-only scheduling within one public inventory observation. Callers
// still supply all original opening/closing fences; no previous observation is
// reused and this function grants no effect or lifecycle authority. Two fixed
// serial lanes retain relative input order, then join before any row is returned.
func (a *ClusterAdmission) phasePublicInventoryTwoLanes(ctx context.Context, request LifecycleCheck, gcRows []installobserve.GCObject) ([]fixtureWorldRow, error) {
	e := a.prerequisites.engine
	d := request.Snapshot.Document()
	type originalRow struct {
		entry    installstate.Resource
		template *installcontract.Template
		target   *installcontract.Template
	}
	frozen := make([]originalRow, 0, len(d.Resources))
	for _, resource := range d.Resources {
		key := resource.Key
		if key.Kind == "Secret" || phaseCollectionKey(key) {
			continue
		}
		entry, template := e.inventory(d, key)
		if entry == nil || template == nil {
			return nil, ErrFixtures
		}
		row := originalRow{entry: *entry, template: template}
		if key.Kind == "CustomResourceDefinition" {
			var err error
			row.target, err = e.contracts[d.TargetPackage].Template(key, false)
			if err != nil {
				return nil, ErrFixtures
			}
		}
		frozen = append(frozen, row)
	}
	rows := make([]fixtureWorldRow, len(frozen))
	var failures [2]error
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var readers sync.WaitGroup
	for lane := range 2 {
		readers.Go(func() {
			fail := func() { failures[lane] = ErrFixtures; cancel() }
			for index := lane; index < len(frozen); index += 2 {
				if readCtx.Err() != nil {
					fail()
					return
				}
				original := frozen[index]
				key := original.entry.Key
				live, err := e.access.Get(readCtx, key)
				if err != nil {
					fail()
					return
				}
				if key.Kind == "Namespace" {
					err = original.template.MatchNamespace(live, request.Snapshot)
				} else if key.Kind == "CustomResourceDefinition" {
					err = original.template.CheckCRD(live, original.entry.UID, original.target)
				} else {
					err = original.template.MatchLive(live, original.entry.UID)
				}
				if err != nil {
					fail()
					return
				}
				if gcRows != nil && key.Namespace != "" {
					path, err := resourcePath(key, true)
					if err != nil {
						fail()
						return
					}
					plural := path[strings.LastIndex(path, "/")+1:]
					matches := 0
					for _, observed := range gcRows {
						if observed.Metadata.UID == live.GetUID() || observed.Source.Kind == key.Kind && observed.Source.GVR.GroupVersion().String() == key.APIVersion && observed.Metadata.Namespace == key.Namespace && observed.Metadata.Name == key.Name {
							if observed.Source.Kind != key.Kind || observed.Source.GVR.GroupVersion().String() != key.APIVersion || observed.Source.GVR.Resource != plural || !reflect.DeepEqual(observed.Metadata, fixtureGCMetadata(live)) {
								fail()
								return
							}
							matches++
						}
					}
					if matches != 1 {
						fail()
						return
					}
				}
				row, err := phaseRow(key, live.GetUID(), live.GetResourceVersion(), live)
				if err != nil {
					fail()
					return
				}
				rows[index] = row
			}
		})
	}
	readers.Wait()
	if failures[0] != nil || failures[1] != nil || ctx.Err() != nil {
		return nil, ErrFixtures
	}
	sortFixtureWorlds(rows)
	return rows, nil
}
