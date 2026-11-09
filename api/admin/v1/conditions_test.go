// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestEveryStableGameServerReasonSurvivesProjection(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(source), "..", "..", "v1alpha1", "gameserver_types.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	ast.Inspect(file, func(node ast.Node) bool {
		declaration, ok := node.(*ast.GenDecl)
		if !ok || declaration.Tok != token.CONST {
			return true
		}
		for _, spec := range declaration.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || !strings.HasPrefix(value.Names[0].Name, "Reason") || len(value.Values) != 1 {
				continue
			}
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("stable reason is no longer an explicit string constant")
			}
			input, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			if reason, _ := ConditionGuidance(input); reason != input {
				t.Errorf("stable reason %s was lost", value.Names[0].Name)
			}
			count++
		}
		return false
	})
	if count < 20 {
		t.Fatal("stable controller reason inventory was not inspected")
	}
}

func TestConditionGuidanceIsClosedAndDoesNotCertifyProgress(t *testing.T) {
	for _, input := range []string{"", "SECRET-CANARY", "Ready\nSECRET-CANARY", "ready"} {
		reason, action := ConditionGuidance(input)
		if reason != "Unknown" || action == "" || strings.Contains(reason+action, "SECRET-CANARY") {
			t.Fatal("unknown reason crossed the closed projection")
		}
	}
	for _, input := range []string{"RetainedDataConflict", "RetainedDataMissing", "PlayerEndpointPending", "ResourceCollision", "WorkerFailed", "InvalidSpec", "ReconcileFailed"} {
		if reason, action := ConditionGuidance(input); reason != input || action == "" {
			t.Fatal("actionable failure has no safe guidance")
		}
	}
	for _, input := range []string{"Ready", "Valid", "WorkloadAvailable", "ClaimsReady", "PreflightVerified", "Succeeded"} {
		if reason, action := ConditionGuidance(input); reason != input || action != "" {
			t.Fatal("successful progress acquired unsolicited remediation")
		}
	}
}
