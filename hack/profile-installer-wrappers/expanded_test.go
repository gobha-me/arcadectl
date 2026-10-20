// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestExpandedVocabularyExactOnlyAndFlatConservation(t *testing.T) {
	root := targets[0].root
	seen := map[string]bool{}
	for symbol, id := range functions {
		if seen[id] || id == "" || strings.ContainsAny(id, "/. \t\r\n") {
			t.Fatal("nonunique or nonclosed identifier")
		}
		seen[id] = true
		if symbol == root {
			continue
		}
		for _, item := range []struct{ kind, sampleType, unit string }{{"cpu-nanoseconds", "cpu", "ns"}, {"sampled-alloc-bytes", "alloc_space", "B"}} {
			for _, exact := range []bool{true, false} {
				selected := symbol
				if !exact {
					selected += ".PROVIDER-CANARY"
				}
				body := fmt.Sprintf("Type: %s\nflat flat%% sum%% cum cum%%\n0 0%% 0%% 100%s 100%% %s\n100%s 100%% 100%% 100%s 100%% %s\n", item.sampleType, item.unit, root, item.unit, item.unit, selected)
				m, err := parseTop([]byte(body), root, item.kind)
				if err != nil || m.ReportedFlatSum != 100 || m.RootCumulative != 100 {
					t.Fatal("numeric accounting changed")
				}
				known := float64(0)
				for _, row := range m.Rows {
					known += row.Flat
				}
				if known+m.UnknownFlat != m.ReportedFlatSum || exact && (m.UnknownFlat != 0 || len(m.Rows) != 2) || !exact && (m.UnknownFlat != 100 || len(m.Rows) != 1) {
					t.Fatal("unknown remainder or exact matching changed")
				}
				out, err := json.Marshal(m)
				if err != nil || strings.Contains(string(out), "CANARY") || strings.Contains(string(out), symbol) {
					t.Fatal("raw symbol escaped")
				}
			}
		}
	}
}

func TestExpandedProfileScopesKeepWholeProcessSeparate(t *testing.T) {
	root := targets[0].root
	for _, whole := range []bool{false, true} {
		args := pprofArguments(root, "cpu", "ns", whole)
		focuses := 0
		for _, arg := range args {
			if strings.HasPrefix(arg, "-focus=") {
				focuses++
			}
		}
		if whole && focuses != 0 || !whole && focuses != 1 || args[len(args)-1] != "/proc/self/fd/0" {
			t.Fatal("whole and root scope conflated")
		}
		joined := strings.Join(args, " ")
		for _, fixed := range []string{"-nodecount=0", "-nodefraction=0", "-edgefraction=0", "-symbolize=none", "-sample_index=cpu", "-unit=ns"} {
			if !strings.Contains(joined, fixed) {
				t.Fatal("closed untruncated projection changed")
			}
		}
	}
}

func TestExpandedProfileRefusesAggregateOverflow(t *testing.T) {
	root := targets[0].root
	body := fmt.Sprintf("Type: cpu\nflat flat%% sum%% cum cum%%\n0 0%% 0%% 1000000000000000000ns 100%% %s\n600000000000000000ns 60%% 60%% 600000000000000000ns 60%% first-unknown\n600000000000000000ns 60%% 100%% 600000000000000000ns 60%% second-unknown\n", root)
	if _, err := parseTop([]byte(body), root, "cpu-nanoseconds"); err == nil {
		t.Fatal("individually valid rows bypassed aggregate bound")
	}
}

func TestV3UnknownLeafCategoriesPreserveClosedPartition(t *testing.T) {
	root := targets[0].root
	for _, item := range []struct{ symbol, category string }{
		{"runtime.gcAssistAlloc.PROVIDER-CANARY", "runtime-gc"},
		{"runtime.scanobject.PROVIDER-CANARY", "runtime-gc"},
		{"runtime.mallocgc.PROVIDER-CANARY", "runtime-allocation"},
		{"internal/runtime/maps.put.PROVIDER-CANARY", "runtime-maps"},
		{"runtime.other.PROVIDER-CANARY", "runtime-other"},
		{"encoding/json.decode.PROVIDER-CANARY", "standard-json"},
		{"sigs.k8s.io/json/internal/parser.PROVIDER-CANARY", "strict-json"},
		{"github.com/gobha-me/arcadectl/internal/canonicaljson.extra.PROVIDER-CANARY", "canonical-json"},
		{"github.com/gobha-me/arcadectl/internal/installstate.extra.PROVIDER-CANARY", "project-state"},
		{"github.com/gobha-me/arcadectl/internal/installcontract.extra.PROVIDER-CANARY", "project-contract"},
		{"github.com/gobha-me/arcadectl/internal/installobserve.extra.PROVIDER-CANARY", "project-observe"},
		{"github.com/gobha-me/arcadectl/internal/installengine.extra.PROVIDER-CANARY", "project-engine"},
		{"github.com/gobha-me/arcadectl/internal/other.extra.PROVIDER-CANARY", "project-other"},
		{"github.com/gobha-me/arcadectl-foreign/extra.PROVIDER-CANARY", "other"},
		{"k8s.io/client-go/example.PROVIDER-CANARY", "client-go"},
		{"k8s.io/apimachinery/runtime.PROVIDER-CANARY", "api-machinery"},
		{"net/http.worker.PROVIDER-CANARY", "http"},
		{"net.worker.PROVIDER-CANARY", "network"},
		{"unknown[go.shape.struct { PRIVATE string }].PROVIDER-CANARY", "other"},
	} {
		if got := unknownFlatCategory(item.symbol); got != item.category {
			t.Fatal("category precedence or fallback changed")
		}
		for _, unit := range []string{"ns", "B"} {
			kind, sampleType := "cpu-nanoseconds", "cpu"
			if unit == "B" {
				kind, sampleType = "sampled-alloc-bytes", "alloc_space"
			}
			body := fmt.Sprintf("Type: %s\nflat flat%% sum%% cum cum%%\n0 0%% 0%% 100%s 100%% %s\n30%s 30%% 30%% 30%s 30%% encoding/json.Marshal\n70%s 70%% 100%% 70%s 70%% %s\n", sampleType, unit, root, unit, unit, unit, unit, item.symbol)
			m, err := parseTop([]byte(body), root, kind)
			if err != nil || m.ReportedFlatSum != 100 || m.UnknownFlat != 70 || len(m.UnknownFlatByCategory) != 1 || m.UnknownFlatByCategory[item.category] != 70 {
				t.Fatal("unknown classification changed known/total accounting")
			}
			if len(m.Rows) != 2 || m.Rows[1].ID != "json-marshal" || m.Rows[1].Flat != 30 {
				t.Fatal("known function row was reclassified")
			}
			out, err := json.Marshal(m)
			if err != nil || strings.Contains(string(out), "CANARY") || strings.Contains(string(out), item.symbol) || strings.Contains(string(out), "PRIVATE") {
				t.Fatal("unknown symbol leaked")
			}
		}
	}
}
