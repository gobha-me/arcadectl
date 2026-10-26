//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestKindAdmissionMatrixFailureSummary(t *testing.T) {
	testKindAdmissionMatrixFailureSummary(t)
}

// Deliberately use direct table assertions, NOT t.Run: the actual native roots
// invoke this pure preflight before profile/mode branches under anchored -run
// filters. The same producer formatter is exercised without a cluster or a
// LifecycleDiagnostic hook; existing HTTPS refusal/custody tests stay separate.
func testKindAdmissionMatrixFailureSummary(t *testing.T) {
	t.Helper()
	testKindAdmissionMatrixFailureSummaryWiring(t)
	const old = `diagnostic stage=case-post-observation index=9 phase=original-row-floor slot=-1 typed-metadata="kind=Pod field=resource-version" phase-floor="category=rows kind=Pod membership=false identity=false resource-version=true hash=true other=false"`
	for _, test := range []struct {
		name, label string
		edit        func(*corev1.Pod)
		unavailable bool
	}{
		{"rv-only", "change=rv-only", nil, false},
		{"body-beyond-rv", "change=body-beyond-rv", func(p *corev1.Pod) { p.Status.Reason = "PRIVATE-POD-CANARY" }, false},
		{"unavailable", "change=unavailable", nil, true},
	} {
		trace := &admissionTrace{}
		ctx := context.WithValue(context.Background(), admissionTraceKey{}, trace)
		if ctx.Value(lifecycleDiagnosticKey{}) != nil {
			t.Fatal("matrix producer control accidentally acquired a lifecycle hook")
		}
		traceAdmission(ctx, admissionCasePostObservation, 9)
		traceAdmissionPhase(ctx, admissionPhaseRowFloor, -1)
		before, after, observed := testPhaseFloorPodPair(t, false, test.edit)
		pod := observed[after.Rows[0].UID].(*corev1.Pod)
		wantedMetadata := pod.ObjectMeta.DeepCopy()
		wantedMetadata.ResourceVersion = before.Rows[0].ResourceVersion
		beginTypedMetadataDiagnostic(ctx)("Pod", pod.ObjectMeta, *wantedMetadata)
		recorder := beginPhaseFloorDiagnostic(ctx)
		recorder.difference(before, after)
		if samePhaseBaseline(before, after) {
			t.Fatal("producer control lost its actual typed whole-row refusal")
		}
		if test.unavailable {
			observed = nil
		}
		recorder.recordPodDifference(before, after, observed)
		want := old + ` phase-floor-pod=` + strconv.Quote(test.label)
		got := kindAdmissionMatrixFailureSummary(trace)
		if got != want || trace.phaseFloorPodSnapshot() != test.label || strings.Contains(got, "CANARY") {
			t.Fatalf("bare-trace native producer lost fixed %s classification or changed old summary bytes", test.name)
		}
		// The public CLI view delegates to the same private formatter. It is
		// deliberately NOT installed in ctx or used to prepare the bare trace.
		lifecycle := &LifecycleDiagnostic{}
		lifecycle.admission.phaseFloor.Store(trace.phaseFloor.Load())
		if lifecycle.PhaseFloorPodSnapshot() != trace.phaseFloorPodSnapshot() {
			t.Fatal("CLI and bare native trace produced different fixed Pod labels")
		}
		for _, corrupt := range []uint32{0, 4, 255, 0xffffffff} {
			recorder.pod.Store(corrupt)
			if got := kindAdmissionMatrixFailureSummary(trace); got != old+` phase-floor-pod=""` || strings.Contains(got, "CANARY") {
				t.Fatal("absent/unreviewed Pod label changed old native fields or escaped its closed domain")
			}
		}
		traceAdmission(ctx, admissionCasePostObservation, 9)
		const reset = `diagnostic stage=case-post-observation index=9 phase=unknown slot=-1 typed-metadata="" phase-floor="" phase-floor-pod=""`
		if kindAdmissionMatrixFailureSummary(trace) != reset || trace.phaseFloorPodSnapshot() != "" {
			t.Fatal("new native attempt retained old Pod diagnostic or old field state")
		}
		// A late completion writes only its detached old recorder.
		recorder.recordPodDifference(before, after, observed)
		if kindAdmissionMatrixFailureSummary(trace) != reset {
			t.Fatal("late old Pod writer republished a native failure field")
		}
	}
	const empty = `diagnostic stage=unknown index=-1 phase=unknown slot=-1 typed-metadata="" phase-floor="" phase-floor-pod=""`
	if kindAdmissionMatrixFailureSummary(nil) != empty || kindAdmissionMatrixFailureSummary(&admissionTrace{}) != empty || (*admissionTrace)(nil).phaseFloorPodSnapshot() != "" {
		t.Fatal("nil/empty native trace invented diagnostics or changed old summary defaults")
	}
}

func testKindAdmissionMatrixFailureSummaryWiring(t *testing.T) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "admission_effective_kind_test.go", nil, 0)
	if err != nil {
		t.Fatal("actual native matrix producer source unavailable")
	}
	var producer *ast.FuncDecl
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "proveKindAdmissionMatrix" {
			producer = function
		}
	}
	if producer == nil {
		t.Fatal("actual native producer declaration missing")
	}
	nativeFatals, preflightCalls := 0, 0
	var preflightPosition, clusterPosition token.Pos
	ast.Inspect(producer.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if function, ok := call.Fun.(*ast.Ident); ok {
			if function.Name == "testKindAdmissionMatrixFailureSummary" {
				preflightCalls++
				preflightPosition = call.Pos()
			}
			if function.Name == "targetKindFixtureImagesV2" {
				clusterPosition = call.Pos()
			}
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Fatalf" || len(call.Args) == 0 {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || receiver.Name != "t" {
			return true
		}
		format, ok := call.Args[0].(*ast.BasicLit)
		if !ok || format.Kind != token.STRING {
			return true
		}
		text, err := strconv.Unquote(format.Value)
		if err != nil || !strings.HasPrefix(text, "full matrix driver refused:") {
			return true
		}
		nativeFatals++
		if text != "full matrix driver refused: %s" || len(call.Args) != 2 {
			t.Fatal("actual native fatal bypassed the reviewed common failure formatter")
			return true
		}
		summary, ok := call.Args[1].(*ast.CallExpr)
		if !ok || len(summary.Args) != 1 {
			t.Fatal("actual native fatal omitted its same-trace formatter")
			return true
		}
		function, ok := summary.Fun.(*ast.Ident)
		argument, sameTrace := summary.Args[0].(*ast.Ident)
		if !ok || function.Name != "kindAdmissionMatrixFailureSummary" || !sameTrace || argument.Name != "trace" {
			t.Fatal("actual native fatal formatted a different trace or unused helper")
		}
		return true
	})
	if nativeFatals != 1 || preflightCalls != 1 || preflightPosition == 0 || clusterPosition == 0 || preflightPosition >= clusterPosition {
		t.Fatal("native producer lost its sole shared fatal or unfiltered pure preflight before cluster creation")
	}
}
