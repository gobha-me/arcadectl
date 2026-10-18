// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nativeTranscript() string {
	return "=== RUN   " + nativeRoot + "\n=== RUN   " + nativeRoot + "/" + nativeProfile + "\n=== RUN   " + nativeLeaf + "\n" +
		"    admission_effective_kind_test.go:45: creating checksum-pinned disposable cluster\n" +
		"    admission_effective_kind_test.go:45: building digest-pinned arcadectl-api image with serialized, concurrency-limited Go build\n" +
		"    admission_effective_kind_test.go:45: building digest-pinned arcadectl-controller image with serialized, concurrency-limited Go build\n" +
		"    admission_effective_kind_test.go:76: running all 55 production cases, persistent setups, original-only cleanup and retirement\n" +
		"--- PASS: " + nativeRoot + " (700.00s)\n    --- PASS: " + nativeRoot + "/" + nativeProfile + " (699.00s)\n        --- PASS: " + nativeLeaf + " (698.00s)\nPASS\n"
}

func TestNativeTranscriptRequiresExactSingleCompleteProof(t *testing.T) {
	valid := nativeTranscript()
	if !nativeOutput([]byte(valid)) || !nativeOutput([]byte(strings.ReplaceAll(valid, "\n", "\r\n"))) {
		t.Fatal("complete closed native transcript refused")
	}
	for _, invalid := range []string{
		"", strings.Replace(valid, "warm", "cold", 1), strings.Replace(valid, "kubernetes-1.37.0", "kubernetes-1.35.8", 1),
		strings.Replace(valid, "=== RUN   "+nativeLeaf+"\n", "", 1), strings.Replace(valid, "--- PASS: "+nativeLeaf, "--- SKIP: "+nativeLeaf, 1),
		strings.Replace(valid, "--- PASS: "+nativeRoot, "--- FAIL: "+nativeRoot, 1), valid + "PASS\n", valid + "=== RUN   OTHER\n",
		valid + "--- PASS: OTHER (0.00s)\n", valid + "PRIVATE-PROVIDER-CANARY\n", valid + "    target_auth_kind_test.go:1: PRIVATE-PROVIDER-CANARY\n",
		strings.Replace(valid, "retirement", "retirement PRIVATE-PROVIDER-CANARY", 1), valid + "=== RUN   " + nativeLeaf + "\n",
		strings.Replace(valid, "\nPASS\n", "\n", 1), valid + strings.Repeat("x", captureLimit),
	} {
		if nativeOutput([]byte(invalid)) {
			t.Fatal("incomplete, skipped, duplicate or private transcript accepted")
		}
	}
}

func TestNativeCatalogIsFrozenOwnedAndIndependent(t *testing.T) {
	catalog := nativeCatalog()
	if len(catalog) != 36 || len(functions) != 19 {
		t.Fatal("native catalogue or original catalogue membership changed")
	}
	ids := map[string]bool{}
	for name, id := range catalog {
		if name == "" || id == "" || ids[id] {
			t.Fatal("catalogue contains empty or duplicate identifier")
		}
		ids[id] = true
	}
	for _, id := range []string{"admission-complete", "sdk-request", "engine-wire-transport", "engine-wire-limits", "engine-wire-strict-decode", "engine-wire-memo", "observer-wire-transport", "observer-wire-json"} {
		if !ids[id] {
			t.Fatal("required native discriminator missing")
		}
	}
	catalog[enginePackage+"(*fixtureAdmissionDriver).complete"] = "PRIVATE-PROVIDER-CANARY"
	delete(catalog, "encoding/json.Marshal")
	if nativeCatalog()[enginePackage+"(*fixtureAdmissionDriver).complete"] != "admission-complete" || functions["encoding/json.Marshal"] != "json-marshal" {
		t.Fatal("catalogue mutation escaped its caller")
	}
}

func TestNativeProjectionDoesNotPromoteNamesOrChangeLegacyCatalog(t *testing.T) {
	root := enginePackage + "(*fixtureAdmissionDriver).complete"
	text := "Type: cpu\n      flat  flat%   sum%        cum   cum%\n      10ns 10.00% 10.00%      100ns 100.00%  " + root + "\n      30ns 30.00% 40.00%       40ns 40.00%  " + enginePackage + "(*HTTPAccess).requestAt\n      60ns 60.00% 100.00%      60ns 60.00%  PRIVATE-PROVIDER-CANARY\n"
	m, err := parseTopWithCatalog([]byte(text), root, "cpu-nanoseconds", nativeCatalog())
	if err != nil || m.RootCumulative != 100 || m.UnknownFlat != 60 || len(m.Rows) != 2 {
		t.Fatal("native exact projection refused")
	}
	encoded, err := json.Marshal(m)
	if err != nil || bytes.Contains(encoded, []byte("PRIVATE-PROVIDER-CANARY")) || bytes.Contains(encoded, []byte(root)) {
		t.Fatal("native projection exported private source text")
	}
	for _, name := range []string{root + " PRIVATE-PROVIDER-CANARY", "PRIVATE-PROVIDER-CANARY[go.shape.struct { private string }].call"} {
		candidate := strings.Replace(text, "PRIVATE-PROVIDER-CANARY\n", name+"\n", 1)
		got, err := parseTopWithCatalog([]byte(candidate), root, "cpu-nanoseconds", nativeCatalog())
		if err != nil || got.UnknownFlat != 60 || len(got.Rows) != 2 {
			t.Fatal("native profile-controlled name acquired an identifier")
		}
	}
	legacy, err := parseTop([]byte(text), root, "cpu-nanoseconds")
	if err != nil || legacy.UnknownFlat != 100 || len(legacy.Rows) != 0 {
		t.Fatal("native catalogue silently changed legacy projection")
	}
}

func TestNativeV2CatalogAddsOnlyExactOwnedCollectionAndCopySymbols(t *testing.T) {
	v1, v2 := nativeCatalog(), nativeCatalogV2()
	extras := map[string]string{
		enginePackage + "(*ClusterPrerequisites).collectOriginalObservation":                               "original-observation-collect",
		enginePackage + "(*ClusterAdmission).configured":                                                   "admission-configured",
		enginePackage + "(*ClusterAdmission).phasePublicInventoryAgainstGC":                                "phase-public-inventory",
		enginePackage + "(*fixtureWire).getPhaseLocked":                                                    "phase-named-get",
		"github.com/gobha-me/arcadectl/internal/installobserve.(*Observer).Collect":                        "observer-collect",
		"github.com/gobha-me/arcadectl/internal/installobserve.(*Observer).collectListWithPagesDiagnostic": "observer-collection-decode",
		"github.com/gobha-me/arcadectl/internal/installobserve.(*GCReader).Discover":                       "gc-discovery",
		"github.com/gobha-me/arcadectl/internal/installobserve.(*GCReader).collect":                        "gc-collect",
		"github.com/gobha-me/arcadectl/internal/installobserve.(*Observation).Snapshot":                    "observation-snapshot-copy",
		"github.com/gobha-me/arcadectl/internal/installobserve.(*Observation).Runtime":                     "observation-runtime-copy",
		"github.com/gobha-me/arcadectl/internal/installobserve.(*GCObservation).Objects":                   "gc-objects-copy",
		"github.com/gobha-me/arcadectl/internal/installcontract.(*Template).matchWithAdmissionResult":      "contract-match",
		"github.com/gobha-me/arcadectl/internal/installcontract.(*Template).decodeObservedMode":            "contract-observed-decode",
		"github.com/gobha-me/arcadectl/internal/installsafety.(*RuntimeSnapshot).DeepCopy":                 "runtime-snapshot-copy",
	}
	if len(v1) != 36 || len(v2) != 50 || len(functions) != 19 {
		t.Fatal("versioned catalogue membership changed")
	}
	ids := map[string]bool{}
	for name, id := range v2 {
		if id == "" || ids[id] || (v1[name] != id && extras[name] != id) {
			t.Fatal("v2 contains a changed, duplicate or unowned mapping")
		}
		ids[id] = true
	}
	for name, id := range v1 {
		if v2[name] != id {
			t.Fatal("v2 reinterpreted a v1 identifier")
		}
	}
	for name, id := range extras {
		if v2[name] != id || v1[name] != "" || functions[name] != "" {
			t.Fatal("v2 mapping missing or escaped to a frozen catalogue")
		}
	}
	v2[enginePackage+"(*fixtureWire).getPhaseLocked"] = "PRIVATE-PROVIDER-CANARY"
	delete(v2, "encoding/json.Marshal")
	v1[enginePackage+"(*fixtureAdmissionDriver).complete"] = "PRIVATE-PROVIDER-CANARY"
	if nativeCatalogV2()[enginePackage+"(*fixtureWire).getPhaseLocked"] != "phase-named-get" || nativeCatalogV2()["encoding/json.Marshal"] != "json-marshal" || nativeCatalogV2()[enginePackage+"(*fixtureAdmissionDriver).complete"] != "admission-complete" || nativeCatalog()[enginePackage+"(*fixtureAdmissionDriver).complete"] != "admission-complete" {
		t.Fatal("versioned catalogue mutation escaped its caller")
	}
}

func TestNativeV2ProjectionDoesNotChangeV1OrPromoteNearMatches(t *testing.T) {
	root := enginePackage + "(*fixtureAdmissionDriver).complete"
	copySymbol := "github.com/gobha-me/arcadectl/internal/installobserve.(*Observation).Snapshot"
	text := "Type: cpu\n      flat  flat%   sum%        cum   cum%\n      10ns 10.00% 10.00%      100ns 100.00%  " + root + "\n      30ns 30.00% 40.00%       40ns 40.00%  " + copySymbol + "\n      60ns 60.00% 100.00%      60ns 60.00%  " + copySymbol + " PRIVATE-PROVIDER-CANARY\n"
	v2, err := parseTopWithCatalog([]byte(text), root, "cpu-nanoseconds", nativeCatalogV2())
	if err != nil || v2.UnknownFlat != 60 || len(v2.Rows) != 2 {
		t.Fatal("v2 exact discriminator failed")
	}
	v1, err := parseTopWithCatalog([]byte(text), root, "cpu-nanoseconds", nativeCatalog())
	if err != nil || v1.UnknownFlat != 90 || len(v1.Rows) != 1 {
		t.Fatal("v2 projection changed frozen native v1")
	}
	body, err := json.Marshal(v2)
	if err != nil || bytes.Contains(body, []byte("PRIVATE-PROVIDER-CANARY")) || bytes.Contains(body, []byte(copySymbol)) || !bytes.Contains(body, []byte("observation-snapshot-copy")) {
		t.Fatal("v2 exported provider names or omitted exact identifier")
	}
}

func TestNativeRefusalSchemasAreExplicitlyVersioned(t *testing.T) {
	for _, tc := range []struct {
		mode, schema string
		native       bool
	}{
		{"native-component", "arcadectl-native-component-screen-refusal-v1", true},
		{"native-component-v2", "arcadectl-native-component-screen-refusal-v2", true},
		{"unknown", "arcadectl-wrapper-screen-refusal-v1", false},
	} {
		if schema, native := refusalSchema(tc.mode); schema != tc.schema || native != tc.native {
			t.Fatal("diagnostic mode silently reinterpreted a refusal version")
		}
	}
}

func TestNativeWorkingDirectoryHelper(t *testing.T) {
	if os.Getenv("ARCADECTL_NATIVE_DIRECTORY_HELPER") != "1" {
		return
	}
	wd, err := os.Getwd()
	if err != nil || filepath.Base(wd) != "owned-native-directory" {
		os.Exit(2)
	}
	fmt.Print("native-directory-bound\n")
	os.Exit(0)
}

func TestNativeCommandUsesPackageWorkingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned-native-directory")
	if os.Mkdir(path, 0700) != nil {
		t.Fatal("owned directory unavailable")
	}
	t.Setenv("ARCADECTL_NATIVE_DIRECTORY_HELPER", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	body, err := commandAt(context.Background(), 5*time.Second, nil, nil, path, binary, "-test.run=^TestNativeWorkingDirectoryHelper$")
	defer clear(body)
	if err != nil || string(body) != "native-directory-bound\n" {
		t.Fatal("native child lost package working directory")
	}
}
