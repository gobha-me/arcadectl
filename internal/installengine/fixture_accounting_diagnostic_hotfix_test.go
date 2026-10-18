// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"k8s.io/apimachinery/pkg/types"
)

// Freeze the exact accounting body from 15c63004, independent of its new name
// and signature. Removing ONLY the closed diagnostic calls must recover that
// original token stream, preserving literal bytes and inserted semicolons.
func TestHistoricalAccountingDiagnosticErasesToOriginal(t *testing.T) {
	source, err := os.ReadFile("fixture_phase.go")
	if err != nil || len(source) > 262144 {
		t.Fatal("accounting source unavailable")
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "fixture_phase.go", source, parser.ParseComments)
	if err != nil {
		t.Fatal("accounting source invalid")
	}
	var body *ast.BlockStmt
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "accountPhaseTraced" {
			if body != nil {
				t.Fatal("accounting source ambiguous")
			}
			body = function.Body
		}
	}
	if body == nil {
		t.Fatal("traced accounting source missing")
	}
	start, end := set.Position(body.Pos()).Offset, set.Position(body.End()).Offset
	removed := make([]bool, end-start)
	remove := func(first, last token.Pos) {
		a, b := set.Position(first).Offset, set.Position(last).Offset
		if a < start || b > end || b < a {
			t.Fatal("diagnostic source range invalid")
		}
		for index := a; index < b; index++ {
			removed[index-start] = true
		}
	}
	labels := map[string]bool{
		"admissionPhaseRowInput": true, "admissionPhaseRowCollection": true,
		"admissionPhaseRowUID": true, "admissionPhaseRowAddress": true,
		"admissionPhaseRowFixtureIdentity": true, "admissionPhaseRowFixtureMissing": true,
		"admissionPhaseRowLeaderChain": true, "admissionPhaseRowLeaderShape": true,
		"admissionPhaseRowShape": true, "admissionPhaseRowFinalCheck": true,
	}
	calls := 0
	ast.Inspect(body, func(node ast.Node) bool {
		statement, ok := node.(*ast.ExprStmt)
		if !ok {
			return true
		}
		call, ok := statement.X.(*ast.CallExpr)
		if !ok {
			return true
		}
		function, ok := call.Fun.(*ast.Ident)
		if !ok || function.Name != "traceAdmissionPhase" {
			return true
		}
		if len(call.Args) != 3 || call.Ellipsis.IsValid() {
			t.Fatal("diagnostic call shape changed")
		}
		ctx, ctxOK := call.Args[0].(*ast.Ident)
		label, labelOK := call.Args[1].(*ast.Ident)
		slot, slotOK := call.Args[2].(*ast.UnaryExpr)
		if !ctxOK || ctx.Name != "ctx" || !labelOK || !labels[label.Name] || !slotOK || slot.Op != token.SUB {
			t.Fatal("diagnostic call escaped closed arguments")
		}
		literal, ok := slot.X.(*ast.BasicLit)
		if !ok || literal.Kind != token.INT || literal.Value != "1" {
			t.Fatal("diagnostic call escaped fixed slot")
		}
		remove(statement.Pos(), statement.End())
		calls++
		return false
	})
	var normalized []byte
	for index, value := range source[start:end] {
		if !removed[index] {
			normalized = append(normalized, value)
		}
	}
	if calls != 11 || historicalAccountingTokenDigest(t, normalized) != "1fc5a27a4d507d1e775c0d47b3622c28d59cdb683f2ff55e8934a8783b59304d" {
		t.Fatal("diagnostic erasure changed original accounting")
	}
}

func historicalAccountingTokenDigest(t *testing.T, source []byte) string {
	t.Helper()
	var lexer scanner.Scanner
	set := token.NewFileSet()
	lexer.Init(set.AddFile("accounting-body", -1, len(source)), source, func(token.Position, string) {
		t.Fatal("accounting tokens invalid")
	}, 0)
	var encoded bytes.Buffer
	for {
		_, kind, literal := lexer.Scan()
		if kind == token.EOF {
			break
		}
		fmt.Fprintf(&encoded, "%s:%q\n", kind.String(), literal)
	}
	digest := sha256.Sum256(encoded.Bytes())
	return hex.EncodeToString(digest[:])
}

func TestHistoricalAccountingTokenOraclePreservesSemanticWhitespace(t *testing.T) {
	for _, pair := range [][2]string{
		{"{ if value == \"admission-phase-v1\" { return } }", "{ if value == \"admission-phase-v1 \" { return } }"},
		{"{ if value == `admission-phase-v1` { return } }", "{ if value == `admission-phase-v1 ` { return } }"},
		{"{ if value == ' ' { return } }", "{ if value == '\t' { return } }"},
		{"{ return value }", "{ return\nvalue }"},
	} {
		if historicalAccountingTokenDigest(t, []byte(pair[0])) == historicalAccountingTokenDigest(t, []byte(pair[1])) {
			t.Fatal("semantic token change escaped frozen oracle")
		}
	}
	original := historicalAccountingTokenDigest(t, []byte("{ if value == \"admission-phase-v1\" { return } }"))
	if historicalAccountingTokenDigest(t, []byte("{ /* comment */ if value == \"admission-phase-v1\" { return } }")) != original {
		t.Fatal("nonsemantic comment changed token oracle")
	}
}

func TestHistoricalAccountingDiagnosticMatchesUntracedResult(t *testing.T) {
	newPhase := fixturePhaseFactoryWithSetup(t, func(h *fixturePhaseTest) {
		instrumentFreshFixtureRecipeV2(h.test, h.f.wire.ledger)
	})
	for _, scenario := range []string{"planned", "original", "nil-observation", "nil-receiver", "invalid-floor", "invalid-recipe", "fixture-uid", "fixture-missing", "unknown-create", "ordinary-row-rv"} {
		t.Run(scenario, func(t *testing.T) {
			h := newPhase(t)
			ledger := h.f.wire.ledger
			if ledger.document.Recipe != fixtureRecipeV2 || len(ledger.document.Entries) != 11 {
				t.Fatal("historical recipe V2 unavailable")
			}
			if scenario == "original" || scenario == "fixture-uid" || scenario == "fixture-missing" {
				acknowledgeAllRecipeFixtures(t, ledger)
				created := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
				for slot := range ledger.document.Entries {
					h.f.objects[slot] = fixtureResultExample(t, ledger, slot, fixtureStableResult, created)
				}
			}
			if scenario == "fixture-missing" {
				h.hide[fixturePlainPod] = true
			}
			worlds, err := ledger.readOriginalWorlds(false)
			if err != nil || worlds.Phase == nil {
				t.Fatal("original companion unavailable")
			}
			observation, err := h.f.actor.admission.prerequisites.observe(t.Context(), h.f.actor.request)
			if err != nil {
				t.Fatal("sealed original observation unavailable")
			}
			// Pure classifier only, not a wire, mutation capability or recovery.
			classifier := &fixtureLedger{document: ledger.document}
			classifier.document.Entries = append([]fixtureEntry{}, ledger.document.Entries...)
			floor := *worlds.Phase
			floor.Rows = append([]fixtureWorldRow{}, floor.Rows...)
			argument := observation
			receiver := classifier
			want := "original-rows"
			switch scenario {
			case "nil-observation":
				argument, want = nil, "original-row-input"
			case "nil-receiver":
				receiver, want = nil, "original-row-input"
			case "invalid-floor":
				floor.Rows, want = nil, "original-row-input"
			case "invalid-recipe":
				classifier.document.Recipe, want = "invalid", "original-row-input"
			case "fixture-uid":
				classifier.document.Entries[fixturePlainPod].OriginalUID = types.UID("b0000000-0000-4000-8000-000000000001")
				want = "original-row-fixture-identity"
			case "fixture-missing":
				want = "original-row-missing-fixture"
			case "unknown-create":
				classifier.document.Entries[fixturePlainPod].State = fixtureCreateAttempted
				want = "original-row-missing-fixture"
			case "ordinary-row-rv":
				if len(floor.Rows) == 0 {
					t.Fatal("ordinary original rows unavailable")
				}
				rv, err := strconv.ParseUint(floor.Rows[0].ResourceVersion, 10, 64)
				if err != nil || rv == ^uint64(0) {
					t.Fatal("original row RV unavailable")
				}
				floor.Rows[0].ResourceVersion = strconv.FormatUint(rv+1, 10)
				want = "original-row-final-check"
			}
			encode := func(value any) []byte {
				body, err := json.Marshal(value)
				if err != nil {
					t.Fatal("before-image unavailable")
				}
				return body
			}
			image := func(o *installobserve.Observation) []byte {
				return encode([]any{o.Snapshot(), o.Runtime(), o.Journal().Bytes(), o.Journal().Anchor(), o.Journal().ResourceVersion(), floor, classifier.document})
			}
			before, wal, identity := image(observation), bytes.Clone(ledger.body), ledger.identity
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			traceAdmissionPhase(ctx, admissionPhaseRows, -1)
			now := time.Now().UTC()
			phase, objects, err := receiver.accountPhaseTraced(ctx, argument, floor, now)
			plainPhase, plainObjects, plainErr := receiver.accountPhase(argument, floor, now)
			label, slot := diagnostic.admission.phaseSnapshot()
			valid := scenario == "planned" || scenario == "original"
			if (err == nil) != valid || !valid && err != ErrFixtures || err != plainErr || !reflect.DeepEqual(phase, plainPhase) || !reflect.DeepEqual(objects, plainObjects) || label != want || slot != -1 {
				t.Fatal("diagnostic changed accounting result or closed refusal")
			}
			if scenario == "original" && objects[fixtureVerifiedCancelledDestroy] == nil {
				t.Fatal("historical eleventh original omitted")
			}
			if !bytes.Equal(before, image(observation)) || !bytes.Equal(wal, ledger.body) || identity != ledger.identity || classifier.phaseFloor != nil || ledger.phaseFloor != nil || h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 {
				t.Fatal("diagnostic mutated inputs, WAL, floor or effects")
			}
		})
	}
}

func TestHistoricalAccountingDiagnosticWarmV2(t *testing.T) {
	newPhase := fixtureWarmPhaseFactory(t, func(h *fixturePhaseTest) {
		instrumentFreshFixtureRecipeV2(h.test, h.f.wire.ledger)
	})
	for _, stale := range []bool{false, true} {
		t.Run(strconv.FormatBool(stale), func(t *testing.T) {
			h := newPhase(t)
			ledger := h.f.wire.ledger
			worlds, err := ledger.readOriginalWorlds(false)
			if err != nil || worlds.Phase == nil || len(worlds.Phase.Leaders) != 2 || ledger.document.Recipe != fixtureRecipeV2 || len(ledger.document.Entries) != 11 {
				t.Fatal("historical warm V2 floor unavailable")
			}
			observation, err := h.f.actor.admission.prerequisites.observe(t.Context(), h.f.actor.request)
			if err != nil {
				t.Fatal("sealed warm observation unavailable")
			}
			var now time.Time
			for _, leader := range worlds.Phase.Leaders {
				renewed, err := time.Parse(time.RFC3339Nano, leader.RenewTime)
				if err != nil {
					t.Fatal("original renewal floor unavailable")
				}
				if renewed.After(now) {
					now = renewed
				}
			}
			now = now.Add(time.Second)
			want := "original-rows"
			if stale {
				now, want = now.Add(30*time.Second), "original-row-leader-shape"
			}
			encode := func(value any) []byte {
				body, err := json.Marshal(value)
				if err != nil {
					t.Fatal("warm before-image unavailable")
				}
				return body
			}
			image := func() []byte {
				return encode([]any{observation.Snapshot(), observation.Runtime(), observation.Journal().Bytes(), observation.Journal().Anchor(), observation.Journal().ResourceVersion(), worlds.Phase, ledger.document})
			}
			before, wal, identity := image(), bytes.Clone(ledger.body), ledger.identity
			classifier := &fixtureLedger{document: ledger.document}
			ctx, diagnostic := WithLifecycleDiagnostic(t.Context())
			traceAdmissionPhase(ctx, admissionPhaseRows, -1)
			phase, objects, err := classifier.accountPhaseTraced(ctx, observation, *worlds.Phase, now)
			plainPhase, plainObjects, plainErr := classifier.accountPhase(observation, *worlds.Phase, now)
			label, slot := diagnostic.admission.phaseSnapshot()
			if (err != nil) != stale || stale && err != ErrFixtures || err != plainErr || !reflect.DeepEqual(phase, plainPhase) || !reflect.DeepEqual(objects, plainObjects) || label != want || slot != -1 {
				t.Fatal("warm diagnostic changed accounting or fixed refusal")
			}
			if !bytes.Equal(before, image()) || !bytes.Equal(wal, ledger.body) || identity != ledger.identity || classifier.phaseFloor != nil || ledger.phaseFloor != nil || h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 {
				t.Fatal("warm diagnostic mutated original evidence or effects")
			}
		})
	}
}

func TestHistoricalAccountingDiagnosticPreservesOriginalPhaseNumbers(t *testing.T) {
	stages := []admissionPhaseStep{
		admissionPhaseOriginal, admissionPhaseWorlds, admissionPhaseConfigured,
		admissionPhaseOpening, admissionPhaseTyped, admissionPhaseRows,
		admissionPhasePublicBefore, admissionPhaseNamedGet, admissionPhaseWholeFixture,
		admissionPhaseStorage, admissionPhaseGC, admissionPhaseLeaders,
		admissionPhaseOwners, admissionPhasePublicAfter, admissionPhaseFixtureCorrelation,
		admissionPhaseFinalConfigured, admissionPhaseFinalPublic, admissionPhaseGCOpening,
		admissionPhaseGCMetadataPages, admissionPhaseGCMetadataShape, admissionPhaseGCMetadataUIDs,
		admissionPhaseGCLeasePages, admissionPhaseGCLeaseMembership, admissionPhaseGCLeaseCorrelation,
		admissionPhaseGCLeaseSource, admissionPhaseGCClosing, admissionPhaseGCEventAliasRV,
		admissionPhaseGCEventAliasMetadata, admissionPhaseGCGraphBound, admissionPhaseComplete,
		admissionPhaseRowInput, admissionPhaseRowCollection, admissionPhaseRowUID,
		admissionPhaseRowAddress, admissionPhaseRowFixtureIdentity, admissionPhaseRowFixtureMissing,
		admissionPhaseRowLeaderChain, admissionPhaseRowLeaderShape, admissionPhaseRowShape,
		admissionPhaseRowFinalCheck,
	}
	for index, stage := range stages {
		if int(stage) != index+1 {
			t.Fatal("historical phase number changed")
		}
	}
}
