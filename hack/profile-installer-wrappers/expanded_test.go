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
