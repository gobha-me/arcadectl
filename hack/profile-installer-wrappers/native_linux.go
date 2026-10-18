// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const nativeRoot = "TestKindAdmissionEffectiveV3WithBaseline"
const nativeProfile = "kubernetes-1.37.0"
const nativeLeaf = nativeRoot + "/" + nativeProfile + "/warm"
const nativeSelector = "^" + nativeRoot + "$/^kubernetes-1[.]37[.]0$/^warm$"

// Frozen v3 exact-symbol catalogue plus the complete-driver root. It never
// converts profile-controlled names into new identifiers or mutates v1.
func nativeCatalog() map[string]string {
	catalog := make(map[string]string, len(functions)+17)
	for name, id := range functions {
		catalog[name] = id
	}
	for name, id := range map[string]string{
		enginePackage + "(*baselineActors).probe":                                       "baseline-actor-probe",
		enginePackage + "(*baselineActors).verifyWithProbe":                             "baseline-actor-verify",
		enginePackage + "(*baselineActors).verifyContainment":                           "baseline-actor-containment",
		enginePackage + "(*baselineActors).verifyDeniedComposition":                     "baseline-denied-composition",
		enginePackage + "(*baselineWorkflow).runtimeAccessWitness":                      "baseline-runtime-access",
		enginePackage + "(*baselineWorkflow).readOriginalRuntimeAccess":                 "baseline-original-access",
		enginePackage + "(*ClusterSecurityBaseline).configured":                         "baseline-configured",
		enginePackage + "(*ClusterSecurityBaseline).configuredPass":                     "baseline-configured-pass",
		enginePackage + "(*HTTPAccess).requestAt":                                       "sdk-request",
		enginePackage + "(*Lifecycle).original":                                         "lifecycle-original",
		enginePackage + "attemptTransport.RoundTrip":                                    "engine-wire-transport",
		enginePackage + "boundedJSONLimits":                                             "engine-wire-limits",
		enginePackage + "strictPublicReply":                                             "engine-wire-strict-decode",
		enginePackage + "(*publicReplyMemo).decode":                                     "engine-wire-memo",
		"github.com/gobha-me/arcadectl/internal/installobserve.readTransport.RoundTrip": "observer-wire-transport",
		"github.com/gobha-me/arcadectl/internal/installobserve.boundedJSON":             "observer-wire-json",
		enginePackage + "(*fixtureAdmissionDriver).complete":                            "admission-complete",
	} {
		catalog[name] = id
	}
	return catalog
}

type nativeView struct {
	ID      string   `json:"id"`
	Metrics []metric `json:"metrics"`
}

type nativeMeasurement struct {
	WallNS     int64        `json:"wallNS"`
	TestOutput custody      `json:"testOutput"`
	Views      []nativeView `json:"views"`
}

// Exact hierarchy, one fresh execution and only the fixture's fixed narrative
// messages. Never export a transcript, provider text, image name or path.
func nativeOutput(body []byte) bool {
	if len(body) == 0 || len(body) > captureLimit {
		return false
	}
	names := []string{nativeRoot, nativeRoot + "/" + nativeProfile, nativeLeaf}
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	counts := map[string]int{}
	log := regexp.MustCompile(`^(?:admission_effective_kind_test|target_auth_kind_test)[.]go:[1-9][0-9]*: (.+)$`)
	pass := regexp.MustCompile(`^--- PASS: ([^ ]+) [(][0-9]+[.][0-9]+s[)]$`)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "=== RUN   "):
			name := strings.TrimPrefix(line, "=== RUN   ")
			if !allowed[name] {
				return false
			}
			counts["run:"+name]++
		case pass.MatchString(line):
			name := pass.FindStringSubmatch(line)[1]
			if !allowed[name] {
				return false
			}
			counts["pass:"+name]++
		case line == "PASS":
			counts["whole"]++
		default:
			m := log.FindStringSubmatch(line)
			if len(m) != 2 {
				return false
			}
			switch m[1] {
			case "creating checksum-pinned disposable cluster",
				"building digest-pinned arcadectl-api image with serialized, concurrency-limited Go build",
				"building digest-pinned arcadectl-controller image with serialized, concurrency-limited Go build",
				"running all 55 production cases, persistent setups, original-only cleanup and retirement":
			default:
				return false
			}
		}
	}
	for _, name := range names {
		if counts["run:"+name] != 1 || counts["pass:"+name] != 1 {
			return false
		}
	}
	return counts["whole"] == 1
}

// One native run supplies BOTH profiles for all views. The fixture's existing
// 40m context, 45m Go-test limit, proof and cleanup assertions stay unchanged.
func runNative(ctx context.Context, binary string) (nativeMeasurement, error) {
	analysisContext := ctx
	ctx, cancel := context.WithTimeout(ctx, 46*time.Minute)
	defer cancel()
	var reads, writes []*os.File
	var captures []*bounded
	var readers sync.WaitGroup
	defer func() {
		for _, f := range reads {
			_ = f.Close()
		}
		for _, f := range writes {
			_ = f.Close()
		}
		readers.Wait()
		for _, b := range captures {
			b.wipe()
		}
	}()
	for range 2 {
		r, w, err := os.Pipe()
		if err != nil {
			return nativeMeasurement{}, errScreen
		}
		reads, writes = append(reads, r), append(writes, w)
		b := &bounded{cancel: cancel}
		captures = append(captures, b)
		readers.Add(1)
		go func() {
			defer readers.Done()
			if _, err := io.Copy(b, r); err != nil {
				cancel()
			}
		}()
	}
	start := time.Now()
	body, err := commandAt(ctx, 46*time.Minute, nil, writes, filepath.Join("internal", "installengine"), binary,
		"-test.run="+nativeSelector, "-test.count=1", "-test.v", "-test.timeout=45m",
		"-test.cpuprofile=/proc/self/fd/3", "-test.memprofile=/proc/self/fd/4", "-test.memprofilerate=8192")
	defer clear(body)
	joined := joinReaders(ctx, reads, &readers)
	if err != nil {
		return nativeMeasurement{}, refused("native-test-child", "native-v3-warm", "", err)
	}
	if !joined {
		return nativeMeasurement{}, refused("native-profile-reader-join", "native-v3-warm", "", errScreen)
	}
	if !nativeOutput(body) {
		return nativeMeasurement{}, refused("native-test-transcript", "native-v3-warm", "", errScreen)
	}
	measurement := nativeMeasurement{WallNS: time.Since(start).Nanoseconds(), TestOutput: describe(body)}
	catalog := nativeCatalog()
	for _, view := range []struct{ id, root string }{
		{"complete", enginePackage + "(*fixtureAdmissionDriver).complete"},
		{"phase", enginePackage + "(*fixtureWire).observePhaseLocked"},
		{"engine-request", enginePackage + "(*HTTPAccess).requestAt"},
		{"observer-transport", "github.com/gobha-me/arcadectl/internal/installobserve.readTransport.RoundTrip"},
	} {
		result := nativeView{ID: view.id}
		for i, kind := range []string{"cpu-nanoseconds", "sampled-alloc-bytes"} {
			if captures[i].overflow || len(captures[i].body) == 0 {
				return nativeMeasurement{}, refused("native-profile-capture", view.id, kind, errScreen)
			}
			m, err := analyzeWithCatalog(analysisContext, captures[i].body, view.root, kind, catalog)
			if err != nil {
				return nativeMeasurement{}, refused("", view.id, kind, err)
			}
			result.Metrics = append(result.Metrics, m)
		}
		measurement.Views = append(measurement.Views, result)
	}
	return measurement, nil
}

func nativeScreen(parent context.Context, expected string) error {
	ctx, cancel := context.WithTimeout(parent, 65*time.Minute)
	defer cancel()
	if err := source(ctx, expected); err != nil {
		return refused("native-opening-source", "", "", err)
	}
	dir, err := os.MkdirTemp("", "arcadectl-native-component-")
	if err != nil {
		return refused("native-scratch-create", "", "", err)
	}
	identity, err := os.Stat(dir)
	if err != nil {
		return refused("native-scratch-identity", "", "", err)
	}
	defer func() {
		if now, e := os.Lstat(dir); e == nil && os.SameFile(identity, now) {
			_ = os.RemoveAll(dir)
		}
	}()
	previousTmp := os.Getenv("TMPDIR")
	if os.Setenv("TMPDIR", dir) != nil {
		return refused("native-scratch-environment", "", "", errScreen)
	}
	defer os.Setenv("TMPDIR", previousTmp)
	binary := filepath.Join(dir, "installengine.test")
	out, err := command(ctx, 10*time.Minute, nil, nil, "go", "test", "-c", "-tags=kindinstall", "-p", "1", "-o", binary, "./internal/installengine")
	clear(out)
	if err != nil {
		return refused("native-build-child", "", "", err)
	}
	digest, err := binaryDigest(binary)
	if err != nil {
		return refused("native-opening-binary", "", "", err)
	}
	measurement, err := runNative(ctx, binary)
	if err != nil {
		return err
	}
	if err := source(ctx, expected); err != nil {
		return refused("native-closing-source", "", "", err)
	}
	if closing, err := binaryDigest(binary); err != nil || closing != digest {
		return refused("native-closing-binary", "", "", errScreen)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Schema         string            `json:"schema"`
		Source         string            `json:"source"`
		BinarySHA256   string            `json:"binarySHA256"`
		Profile        string            `json:"profile"`
		Mode           string            `json:"mode"`
		Runs           int               `json:"runs"`
		MemProfileRate int               `json:"memProfileRate"`
		Scope          string            `json:"scope"`
		Measurement    nativeMeasurement `json:"measurement"`
	}{"arcadectl-native-component-screen-v1", expected, digest, nativeProfile, "warm", 1, 8192,
		"native-install-mode-v3-component-only; directly-prepared-journal-and-baseline; not-CLI-Upgrade-or-transition-certification; focused-synchronous-CPU-and-sampled-allocations; rounded-values; cumulative-overlaps; excludes-async-remote-CPU-and-wait; profiling-perturbs-execution", measurement})
}
