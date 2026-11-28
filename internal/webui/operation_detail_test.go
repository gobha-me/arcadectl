// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"golang.org/x/net/html"
)

func receiptIDForTest(letter string) string { return "ao-" + strings.Repeat(letter, 52) }

func renderDetailPage(t *testing.T, operation adminv1.Operation) (string, *html.Node) {
	t.Helper()
	var output bytes.Buffer
	if err := RenderOperationDetail(&output, operation); err != nil {
		t.Fatalf("RenderOperationDetail: %v", err)
	}
	doc, err := html.Parse(strings.NewReader(output.String()))
	if err != nil {
		t.Fatalf("parse operation detail: %v", err)
	}
	return output.String(), doc
}

func detailValues(t *testing.T, doc *html.Node) map[string]string {
	t.Helper()
	terms, descriptions := elements(doc, "dt"), elements(doc, "dd")
	if len(terms) != len(descriptions) {
		t.Fatal("receipt field labels and values do not correspond")
	}
	values := make(map[string]string, len(terms))
	for i, term := range terms {
		label := nodeText(term)
		if _, exists := values[label]; exists {
			t.Fatalf("duplicate receipt field %q", label)
		}
		values[label] = nodeText(descriptions[i])
	}
	return values
}

func assertLocalNavigation(t *testing.T, doc *html.Node, refreshText, refreshPath string) {
	t.Helper()
	navigation := elements(doc, "nav")
	if len(navigation) != 1 || attribute(navigation[0], "aria-label") != "Primary" {
		t.Fatal("page must have one labelled primary navigation landmark")
	}
	links := elements(navigation[0], "a")
	if len(links) != 2 || nodeText(links[0]) != "Servers" || attribute(links[0], "href") != "/" || nodeText(links[1]) != "Operations" || attribute(links[1], "href") != "/operations" {
		t.Fatal("primary navigation must link locally to server status and operations")
	}
	refresh := 0
	for _, link := range elements(doc, "a") {
		if nodeText(link) == refreshText {
			refresh++
			if attribute(link, "href") != refreshPath || attribute(link, "tabindex") == "-1" {
				t.Fatal("refresh must be a keyboard-reachable link to this exact local page")
			}
		}
		href := attribute(link, "href")
		if href != "/" && href != "/operations" && href != "#main-content" && href != refreshPath {
			t.Errorf("unexpected page destination %q", href)
		}
	}
	if refresh != 1 {
		t.Fatalf("page has %d refresh links, want exactly one", refresh)
	}
	assertPassivePage(t, doc)
}

func TestReadOnlyListNavigationAndManualRefresh(t *testing.T) {
	_, servers := renderPage(t, adminv1.ServerList{})
	assertLocalNavigation(t, servers, "Refresh server status", "/")
	_, operations := renderOperationsPage(t, adminv1.OperationList{})
	assertLocalNavigation(t, operations, "Refresh operations", "/operations")
}

func TestOperationDetailAccessibleStructureAndAllowlistedFields(t *testing.T) {
	id := receiptIDForTest("b")
	_, doc := renderDetailPage(t, adminv1.Operation{
		OperationID: id, Action: "server.stop", Phase: "Failed", Generation: 2, ObservedGeneration: 2,
		StartedAt: "2026-11-23T12:00:00Z", CompletedAt: "2026-11-23T12:00:01Z",
		Failure: &adminv1.Failure{Code: "target_changed", Retryable: true, SuggestedAction: "Inspect the exact server."},
	})
	if nodes := elements(doc, "html"); len(nodes) != 1 || attribute(nodes[0], "lang") != "en" {
		t.Fatal("receipt page must declare English")
	}
	if nodes := elements(doc, "title"); len(nodes) != 1 || nodeText(nodes[0]) != "Arcadectl operation receipt" {
		t.Fatal("receipt page must have a meaningful title")
	}
	if nodes := elements(doc, "h1"); len(nodes) != 1 || nodeText(nodes[0]) != "Operation receipt" {
		t.Fatal("receipt page must have exactly one h1")
	}
	mains := elements(doc, "main")
	if len(mains) != 1 || attribute(mains[0], "id") != "main-content" {
		t.Fatal("receipt page must have one named main landmark")
	}
	skip := false
	for _, link := range elements(doc, "a") {
		if nodeText(link) == "Skip to operation detail" && attribute(link, "href") == "#main-content" {
			skip = true
		}
	}
	if !skip {
		t.Fatal("receipt page skip link must target main")
	}
	want := map[string]string{
		"Operation ID": id, "Action": "server.stop", "Reported phase": "Failed", "Currentness": "Current generation",
		"Status": "Failed", "Started": "2026-11-23T12:00:00Z", "Completed": "2026-11-23T12:00:01Z",
		"Failure": "target_changed; retryable; Inspect the exact server.",
	}
	if got := detailValues(t, doc); !reflect.DeepEqual(got, want) {
		t.Fatalf("receipt fields = %#v, want %#v", got, want)
	}
	assertLocalNavigation(t, doc, "Refresh receipt", "/operations/"+id)
}

func TestOperationDetailCurrentnessAndTerminalEvidence(t *testing.T) {
	tests := []struct {
		name, phase, completed, currentness, status string
		generation, observed                        int64
	}{
		{"queued", "Accepted", "", "Current generation", "Queued", 1, 1},
		{"pending", "Pending", "", "Current generation", "Queued", 1, 1},
		{"planning", "Planning", "", "Current generation", "Queued", 1, 1},
		{"running", "Running", "", "Current generation", "Running", 2, 2},
		{"stale success", "Succeeded", "2026-11-23T12:00:01Z", "Stale or unavailable", "Completion unconfirmed", 2, 1},
		{"future observation", "Succeeded", "2026-11-23T12:00:01Z", "Stale or unavailable", "Completion unconfirmed", 2, 3},
		{"zero generation", "Succeeded", "2026-11-23T12:00:01Z", "Stale or unavailable", "Completion unconfirmed", 0, 0},
		{"negative generation", "Succeeded", "2026-11-23T12:00:01Z", "Stale or unavailable", "Completion unconfirmed", -1, -1},
		{"current success", "Succeeded", "2026-11-23T12:00:01.12Z", "Current generation", "Completed successfully", 2, 2},
		{"current failure", "Failed", "2026-11-23T12:00:01Z", "Current generation", "Failed", 2, 2},
		{"current cancellation", "Cancelled", "2026-11-23T12:00:01Z", "Current generation", "Cancelled", 2, 2},
		{"success without completion", "Succeeded", "", "Current generation", "Completion unconfirmed", 2, 2},
		{"failure without completion", "Failed", "", "Current generation", "Completion unconfirmed", 2, 2},
		{"cancellation without completion", "Cancelled", "", "Current generation", "Completion unconfirmed", 2, 2},
		{"invalid completion", "Succeeded", "not a timestamp", "Current generation", "Completion unconfirmed", 2, 2},
		{"awaiting confirmation", "AwaitingConfirmation", "", "Current generation", "Awaiting confirmation", 2, 2},
		{"unknown phase", "unrecognized", "2026-11-23T12:00:01Z", "Current generation", "Completion unconfirmed", 2, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, doc := renderDetailPage(t, adminv1.Operation{
				OperationID: receiptIDForTest("c"), Phase: test.phase,
				Generation: test.generation, ObservedGeneration: test.observed, CompletedAt: test.completed,
			})
			values := detailValues(t, doc)
			if values["Currentness"] != test.currentness || values["Status"] != test.status || values["Reported phase"] != test.phase {
				t.Fatalf("receipt interpretation = %#v, want %q / %q / %q", values, test.currentness, test.status, test.phase)
			}
			if values["Started"] != "Not recorded" || values["Failure"] != "None" {
				t.Fatal("missing receipt observations need explicit neutral text")
			}
			if !strings.Contains(nodeText(doc), "Receipt admission and progress do not establish current server readiness.") {
				t.Fatal("receipt page must distinguish operation evidence from runtime readiness")
			}
		})
	}
}

func TestOperationListLinksOnlyExactValidReceiptIDsInSortedOrder(t *testing.T) {
	a, b := receiptIDForTest("a"), receiptIDForTest("b")
	invalid := []string{"", "ao-" + strings.Repeat("a", 51), "ao-" + strings.Repeat("a", 53), "ao-" + strings.Repeat("0", 52), "ao-" + strings.Repeat("A", 52), "../" + a, a + "/extra", a + "?next=https://example.com", "%2e%2e", "https://example.com/"}
	items := []adminv1.Operation{
		{OperationID: b, StartedAt: "2026-11-23T12:00:00Z", PollURL: "https://example.com/private"},
		{OperationID: a, StartedAt: "2026-11-23T12:00:01Z", PollURL: "/v1/destroy-operations/forged/confirm"},
	}
	for _, id := range invalid {
		items = append(items, adminv1.Operation{OperationID: id})
	}
	_, doc := renderOperationsPage(t, adminv1.OperationList{Items: items})
	bodies := elements(doc, "tbody")
	links := elements(bodies[0], "a")
	if len(links) != 2 {
		t.Fatalf("operation links = %d, want exactly two valid receipts", len(links))
	}
	for i, id := range []string{a, b} {
		if nodeText(links[i]) != id || attribute(links[i], "href") != "/operations/"+id {
			t.Errorf("receipt link %d is not the exact ordered local destination", i)
		}
	}
	assertPassivePage(t, doc)
}

func TestOperationDetailEscapesUntrustedFieldsAndOmitsPrivateData(t *testing.T) {
	attack := `<script>alert(1)</script>"onmouseover=`
	private := []string{"PRIVATE-UID", "PRIVATE-CHALLENGE", "PRIVATE-MESSAGE-SETTINGS", "https://example.com/PRIVATE-POLL", "PRIVATE-CHILD", "PRIVATE-VERSION"}
	page, doc := renderDetailPage(t, adminv1.Operation{
		OperationID: receiptIDForTest("d"), Version: private[5], UID: private[0], Action: attack, Phase: attack,
		Generation: 1, ObservedGeneration: 1, StartedAt: attack, CompletedAt: attack, PollURL: private[3],
		Failure:        &adminv1.Failure{Code: attack, Retryable: false, SuggestedAction: attack, Message: private[2]},
		DestroyPreview: &adminv1.DestroyPreview{Challenge: private[1]},
		Child:          &adminv1.OperationChild{Kind: private[4], Name: private[4], UID: private[4]},
	})
	for _, sentinel := range private {
		if strings.Contains(page, sentinel) {
			t.Errorf("private receipt field %q leaked", sentinel)
		}
	}
	if got := strings.Count(nodeText(doc), attack); got != 6 {
		t.Fatalf("untrusted display values did not survive as text: got %d, want 6", got)
	}
	if got := detailValues(t, doc)["Failure"]; got != attack+"; not retryable; "+attack {
		t.Fatal("failure retryability or escaped safe guidance is missing")
	}
	assertLocalNavigation(t, doc, "Refresh receipt", "/operations/"+receiptIDForTest("d"))
}

func TestOperationDetailInvalidIDWritesNothing(t *testing.T) {
	for _, id := range []string{"", "ao-short", receiptIDForTest("a") + "/x", "https://example.com", `<script>alert(1)</script>`} {
		var output bytes.Buffer
		err := RenderOperationDetail(&output, adminv1.Operation{OperationID: id})
		if err == nil || err.Error() != "invalid operation receipt ID" || output.Len() != 0 {
			t.Fatalf("invalid receipt ID generated output or an unsafe error: %v / %q", err, output.String())
		}
	}
}

func TestOperationDetailFailureWithoutSuggestedAction(t *testing.T) {
	_, doc := renderDetailPage(t, adminv1.Operation{
		OperationID: receiptIDForTest("e"), Generation: 1, ObservedGeneration: 1,
		Failure: &adminv1.Failure{Code: "waiting", Retryable: true},
	})
	if got := detailValues(t, doc)["Failure"]; got != "waiting; retryable" {
		t.Fatalf("failure without guidance = %q", got)
	}
}

func TestOperationDetailPropagatesWriterFailure(t *testing.T) {
	want := errors.New("detail writer unavailable")
	if err := RenderOperationDetail(failedWriter{want}, adminv1.Operation{OperationID: receiptIDForTest("a")}); !errors.Is(err, want) {
		t.Fatalf("detail writer error = %v, want %v", err, want)
	}
}
