// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Independent literal scenario-to-wrapper oracle. The former aggregate trees
// must not survive alongside wrappers, silently repeat or omit a scenario.
func TestInstallerWholeProviderScenarioShardsPreserveLiteralCoverage(t *testing.T) {
	cases := []struct {
		file, helper, prefix string
		want                 map[string]string
	}{
		{"baseline_behavior_provider_test.go", "testBaselineBehaviorWholeProvider", "TestBaselineBehaviorWholeProvider", map[string]string{
			"TestBaselineBehaviorWholeProviderHealthy":                              "healthy",
			"TestBaselineBehaviorWholeProviderPendingService":                       "pending-service",
			"TestBaselineBehaviorWholeProviderPendingParent":                        "pending-parent",
			"TestBaselineBehaviorWholeProviderCompleteInstall":                      "complete-install",
			"TestBaselineBehaviorWholeProviderCompleteUpgrade":                      "complete-upgrade",
			"TestBaselineBehaviorWholeProviderCompleteRollback":                     "complete-rollback",
			"TestBaselineBehaviorWholeProviderWrongPodFamily":                       "wrong-pod-family",
			"TestBaselineBehaviorWholeProviderMissingDenial":                        "missing-denial",
			"TestBaselineBehaviorWholeProviderProducerDenialBefore":                 "producer-denial-before",
			"TestBaselineBehaviorWholeProviderProducerDenialAfter":                  "producer-denial-after",
			"TestBaselineBehaviorWholeProviderBadPositive":                          "bad-positive",
			"TestBaselineBehaviorWholeProviderClosingNewPod":                        "closing-new-pod",
			"TestBaselineBehaviorWholeProviderClosingProxyGrant":                    "closing-proxy-grant",
			"TestBaselineBehaviorWholeProviderClosingServiceRv":                     "closing-service-rv",
			"TestBaselineBehaviorWholeProviderFinalCatalogFirstServiceRv":           "final-catalog-first-service-rv",
			"TestBaselineBehaviorWholeProviderFinalCatalogSecondServiceRv":          "final-catalog-second-service-rv",
			"TestBaselineBehaviorWholeProviderFinalReceiptReplacement":              "final-receipt-replacement",
			"TestBaselineBehaviorWholeProviderFinalParentReceiptReplacement":        "final-parent-receipt-replacement",
			"TestBaselineBehaviorWholeProviderRuntimeHealthy":                       "runtime-healthy",
			"TestBaselineBehaviorWholeProviderRuntimeClosingProxyGrant":             "runtime-closing-proxy-grant",
			"TestBaselineBehaviorWholeProviderRuntimeClosingNewPod":                 "runtime-closing-new-pod",
			"TestBaselineBehaviorWholeProviderRuntimeFinalReceiptReplacement":       "runtime-final-receipt-replacement",
			"TestBaselineBehaviorWholeProviderRuntimeFinalParentReceiptReplacement": "runtime-final-parent-receipt-replacement",
			"TestBaselineBehaviorWholeProviderRuntimeFinalCloseOrderService":        "runtime-final-close-order-service",
			"TestBaselineBehaviorWholeProviderRuntimeFinalCloseOrderParent":         "runtime-final-close-order-parent",
		}},
		{"baseline_retired_http_test.go", "testBaselineRetiredHTTPSClosesWholeEvidenceWithoutAuthority", "TestBaselineRetiredHTTPS", map[string]string{
			"TestBaselineRetiredHTTPSHealthy":                            "healthy",
			"TestBaselineRetiredHTTPSHarmlessTerminalPod":                "harmless-terminal-pod",
			"TestBaselineRetiredHTTPSPartiallyWithdrawnOriginalAccess":   "partially-withdrawn-original-access",
			"TestBaselineRetiredHTTPSPendingOriginalAccessDelete":        "pending-original-access-delete",
			"TestBaselineRetiredHTTPSPendingAccessReplaced":              "pending-access-replaced",
			"TestBaselineRetiredHTTPSReceiptReplacedBetweenCores":        "receipt-replaced-between-cores",
			"TestBaselineRetiredHTTPSFirstColdReservedAlias":             "first-cold-reserved-alias",
			"TestBaselineRetiredHTTPSSecondColdControllerImage":          "second-cold-controller-image",
			"TestBaselineRetiredHTTPSOpeningRawControllerImage":          "opening-raw-controller-image",
			"TestBaselineRetiredHTTPSClosingRawReservedName":             "closing-raw-reserved-name",
			"TestBaselineRetiredHTTPSSecondColdWorldChange":              "second-cold-world-change",
			"TestBaselineRetiredHTTPSLastListDenied":                     "last-list-denied",
			"TestBaselineRetiredHTTPSReviewDenied":                       "review-denied",
			"TestBaselineRetiredHTTPSLateListReviewDenied":               "late-list-review-denied",
			"TestBaselineRetiredHTTPSLateGetReviewDenied":                "late-get-review-denied",
			"TestBaselineRetiredHTTPSLateRuntimePolicyRv":                "late-runtime-policy-rv",
			"TestBaselineRetiredHTTPSLateBaselinePolicyRv":               "late-baseline-policy-rv",
			"TestBaselineRetiredHTTPSLateFixture":                        "late-fixture",
			"TestBaselineRetiredHTTPSLateJournal":                        "late-journal",
			"TestBaselineRetiredHTTPSCompleteHealthy":                    "complete-healthy",
			"TestBaselineRetiredHTTPSCompleteListDenied":                 "complete-list-denied",
			"TestBaselineRetiredHTTPSCompleteRootGetDenied":              "complete-root-get-denied",
			"TestBaselineRetiredHTTPSCompleteReceiptReplaced":            "complete-receipt-replaced",
			"TestBaselineRetiredHTTPSCompleteRemovedAccessRecreated":     "complete-removed-access-recreated",
			"TestBaselineRetiredHTTPSCompleteRetainedCrdReplaced":        "complete-retained-crd-replaced",
			"TestBaselineRetiredHTTPSCompleteRetainedSecretDeleting":     "complete-retained-secret-deleting",
			"TestBaselineRetiredHTTPSCompleteLateJournal":                "complete-late-journal",
			"TestBaselineRetiredHTTPSCompleteWorldChange":                "complete-world-change",
			"TestBaselineRetiredHTTPSRuntimeHealthy":                     "runtime-healthy",
			"TestBaselineRetiredHTTPSRuntimePendingOriginalAccessDelete": "runtime-pending-original-access-delete",
			"TestBaselineRetiredHTTPSRuntimeReceiptReplacedBetweenCores": "runtime-receipt-replaced-between-cores",
			"TestBaselineRetiredHTTPSRuntimeCompleteHealthy":             "runtime-complete-healthy",
			"TestBaselineRetiredHTTPSRuntimeCompleteReceiptReplaced":     "runtime-complete-receipt-replaced",
		}},
	}
	weightsBody, err := os.ReadFile("../../hack/installengine-race-weights.txt")
	if err != nil {
		t.Fatal(err)
	}
	weights := map[string]int{}
	for _, line := range strings.Split(string(weightsBody), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatal("malformed scheduling row")
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n <= 0 || n > 1200 || weights[fields[0]] != 0 {
			t.Fatal("invalid scheduling estimate")
		}
		weights[fields[0]] = n
	}
	for _, c := range cases {
		source, err := parser.ParseFile(token.NewFileSet(), c.file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		helperCount := 0
		for _, decl := range source.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Name.Name == c.helper {
				helperCount++
				continue
			}
			if !strings.HasPrefix(fn.Name.Name, c.prefix) {
				continue
			}
			scenario, exists := c.want[fn.Name.Name]
			if !exists || seen[fn.Name.Name] || weights[fn.Name.Name] <= 0 || fn.Body == nil || len(fn.Body.List) != 1 {
				t.Fatal("missing, duplicate, unweighted or nonliteral scenario wrapper", fn.Name.Name)
			}
			stmt, ok := fn.Body.List[0].(*ast.ExprStmt)
			if !ok {
				t.Fatal("wrapper not an unconditional helper call")
			}
			call, ok := stmt.X.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				t.Fatal("wrapper changed complete helper call")
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok || name.Name != c.helper {
				t.Fatal("wrapper did not call original complete proof helper")
			}
			argument, ok := call.Args[0].(*ast.Ident)
			if !ok || argument.Name != "t" {
				t.Fatal("wrapper changed its own test owner")
			}
			literal, ok := call.Args[1].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("scenario argument not literal")
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil || value != scenario {
				t.Fatal("scenario no longer matches independent literal catalog")
			}
			seen[fn.Name.Name] = true
		}
		if helperCount != 1 || len(seen) != len(c.want) {
			t.Fatal("complete original scenario coverage missing", c.file, len(seen), len(c.want))
		}
	}
}
