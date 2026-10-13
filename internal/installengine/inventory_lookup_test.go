// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
)

func TestInventoryLookupPreservesFirstMatchTemplateAndDetachedRow(t *testing.T) {
	key := installstate.Key{APIVersion: "v1", Kind: "Service", Namespace: "isolated", Name: "original"}
	template := &installcontract.Template{} // Lookup only, never effect authority.
	e := &Engine{templates: map[installstate.Key]map[string]*installcontract.Template{key: {"original-hash": template}}}
	want := installstate.Resource{Key: key, UID: "original-uid", TemplateSHA256: "original-hash", Retained: true, Phase: installrender.Anchors}
	for _, index := range []int{0, 2, 4} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			d := installstate.Document{Resources: make([]installstate.Resource, 5)}
			d.Resources[index] = want
			before := append([]installstate.Resource(nil), d.Resources...)
			got, matched := e.inventory(d, key)
			if got == nil || *got != want || matched != template {
				t.Fatal("lookup changed original row/template binding")
			}
			*got = installstate.Resource{Key: installstate.Key{Name: "changed"}, UID: "changed", TemplateSHA256: "changed", Phase: installrender.Controllers}
			if !reflect.DeepEqual(d.Resources, before) {
				t.Fatal("returned inventory row aliases caller document")
			}
			got, _ = e.inventory(d, key)
			d.Resources[index] = installstate.Resource{}
			if got == nil || *got != want {
				t.Fatal("input mutation changed detached inventory row")
			}
		})
	}
	d := installstate.Document{Resources: []installstate.Resource{want, {Key: key, UID: "replacement", TemplateSHA256: "other"}}}
	got, matched := e.inventory(d, key)
	if got == nil || *got != want || matched != template {
		t.Fatal("duplicate keys no longer select first recorded row")
	}
	d.Resources[0].TemplateSHA256 = "unregistered"
	got, matched = e.inventory(d, key)
	if got == nil || got.TemplateSHA256 != "unregistered" || matched != nil {
		t.Fatal("lookup substituted another template or skipped original first row")
	}
	if got, matched := e.inventory(d, installstate.Key{Name: "absent"}); got != nil || matched != nil {
		t.Fatal("missing inventory key manufactured a row/template")
	}
}

var inventoryAllocationResult *installstate.Resource

func TestInventoryLookupAllocationDoesNotGrowWithScanLength(t *testing.T) {
	e := &Engine{}
	for _, size := range []int{1, 16, 512} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			d := installstate.Document{Resources: make([]installstate.Resource, size)}
			key := installstate.Key{Name: "last"}
			d.Resources[size-1] = installstate.Resource{Key: key, UID: "original"}
			allocs := testing.AllocsPerRun(100, func() { inventoryAllocationResult, _ = e.inventory(d, key) })
			if allocs != 1 || inventoryAllocationResult == nil || inventoryAllocationResult.UID != "original" {
				t.Fatalf("detached last-row lookup allocations=%g", allocs)
			}
			allocs = testing.AllocsPerRun(100, func() { inventoryAllocationResult, _ = e.inventory(d, installstate.Key{Name: "absent"}) })
			if allocs != 0 || inventoryAllocationResult != nil {
				t.Fatalf("absent-row lookup allocations=%g", allocs)
			}
		})
	}
}
