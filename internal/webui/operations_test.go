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

func renderOperationsPage(t *testing.T, list adminv1.OperationList) (string, *html.Node) {
	t.Helper()
	var output bytes.Buffer
	if err := RenderOperationList(&output, list); err != nil {
		t.Fatalf("RenderOperationList: %v", err)
	}
	doc, err := html.Parse(strings.NewReader(output.String()))
	if err != nil {
		t.Fatalf("parse operations page: %v", err)
	}
	return output.String(), doc
}

func operationCells(t *testing.T, doc *html.Node) [][]string {
	t.Helper()
	bodies := elements(doc, "tbody")
	if len(bodies) != 1 {
		t.Fatal("operations page must have exactly one table body")
	}
	var result [][]string
	for _, row := range elements(bodies[0], "tr") {
		var cells []string
		for _, cell := range elements(row, "td") {
			cells = append(cells, nodeText(cell))
		}
		result = append(result, cells)
	}
	return result
}

func TestOperationListAccessibleStructure(t *testing.T) {
	_, doc := renderOperationsPage(t, adminv1.OperationList{})
	if nodes := elements(doc, "html"); len(nodes) != 1 || attribute(nodes[0], "lang") != "en" {
		t.Fatal("operations page must declare English")
	}
	if titles := elements(doc, "title"); len(titles) != 1 || nodeText(titles[0]) != "Arcadectl operations" {
		t.Fatal("operations page must have a meaningful title")
	}
	if headings := elements(doc, "h1"); len(headings) != 1 || nodeText(headings[0]) != "Operations" {
		t.Fatal("operations page must have exactly one Operations heading")
	}
	mains := elements(doc, "main")
	if len(mains) != 1 || attribute(mains[0], "id") == "" {
		t.Fatal("operations page must have one named main landmark")
	}
	skip := false
	for _, link := range elements(doc, "a") {
		if attribute(link, "href") == "#"+attribute(mains[0], "id") && nodeText(link) == "Skip to operations" {
			skip = true
		}
	}
	if !skip {
		t.Fatal("operations skip link must target the main landmark")
	}
	tables := elements(mains[0], "table")
	if len(tables) != 1 {
		t.Fatal("main must contain one operations table")
	}
	if captions := elements(tables[0], "caption"); len(captions) != 1 || nodeText(captions[0]) != "Operation status" {
		t.Fatal("operations table must have a caption")
	}
	headers := elements(tables[0], "th")
	want := []string{"Operation ID", "Action", "Phase", "Started", "Completed", "Failure"}
	if len(headers) != len(want) {
		t.Fatalf("headers = %d, want %d", len(headers), len(want))
	}
	for i, header := range headers {
		if attribute(header, "scope") != "col" || nodeText(header) != want[i] {
			t.Errorf("operations header %d lacks its column name or scope", i)
		}
	}
	assertPassivePage(t, doc)
}

func TestOperationListSortedRowsAndEveryCell(t *testing.T) {
	list := adminv1.OperationList{Version: "v1", Items: []adminv1.Operation{
		{OperationID: "zeta", Action: "server.stop", Phase: "Failed", StartedAt: "2026-11-23T12:00:01Z", CompletedAt: "2026-11-23T12:00:03Z", Failure: &adminv1.Failure{Code: "target_changed", Retryable: false, SuggestedAction: "Read the current server before retrying."}},
		{OperationID: "older", Action: "server.start", Phase: "Succeeded", StartedAt: "2026-11-23T12:00:00Z", CompletedAt: "2026-11-23T12:00:02Z"},
		{OperationID: "alpha", Action: "server.restart", Phase: "Running", StartedAt: "2026-11-23T12:00:01Z", Failure: &adminv1.Failure{Code: "waiting", Retryable: true, SuggestedAction: "Poll this operation."}},
	}}
	_, doc := renderOperationsPage(t, list)
	want := [][]string{
		{"alpha", "server.restart", "Running", "2026-11-23T12:00:01Z", "Not recorded", "waiting; retryable; Poll this operation."},
		{"zeta", "server.stop", "Failed", "2026-11-23T12:00:01Z", "2026-11-23T12:00:03Z", "target_changed; not retryable; Read the current server before retrying."},
		{"older", "server.start", "Succeeded", "2026-11-23T12:00:00Z", "2026-11-23T12:00:02Z", "None"},
	}
	if got := operationCells(t, doc); !reflect.DeepEqual(got, want) {
		t.Fatalf("operation rows = %#v, want %#v", got, want)
	}
	if got := []string{list.Items[0].OperationID, list.Items[1].OperationID, list.Items[2].OperationID}; !reflect.DeepEqual(got, []string{"zeta", "older", "alpha"}) {
		t.Fatal("renderer reordered the caller's operations")
	}
}

func TestOperationListOrdersInstantsAndUndatedReceipts(t *testing.T) {
	list := adminv1.OperationList{Items: []adminv1.Operation{
		{OperationID: "undated-z"},
		{OperationID: "fraction-zero", StartedAt: "2026-11-23T12:00:01Z"},
		{OperationID: "offset", StartedAt: "2026-11-23T08:00:00-05:00"},
		{OperationID: "fraction-later", StartedAt: "2026-11-23T12:00:01.1Z"},
		{OperationID: "invalid-a", StartedAt: "not a timestamp"},
		{OperationID: "utc", StartedAt: "2026-11-23T12:00:00Z"},
	}}
	_, doc := renderOperationsPage(t, list)
	var got []string
	for _, cells := range operationCells(t, doc) {
		got = append(got, cells[0])
	}
	want := []string{"offset", "fraction-later", "fraction-zero", "utc", "invalid-a", "undated-z"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chronological order = %v, want %v", got, want)
	}
}

func TestOperationListTreatsAllDisplayFieldsAsTextAndOmitsPrivateFields(t *testing.T) {
	attack := `<script>alert(1)</script>"onmouseover=`
	private := []string{"PRIVATE-UID", "PRIVATE-CHALLENGE", "PRIVATE-MESSAGE", "PRIVATE-POLL-URL", "PRIVATE-CHILD", "PRIVATE-VERSION"}
	page, doc := renderOperationsPage(t, adminv1.OperationList{Version: private[5], Items: []adminv1.Operation{{
		Version: private[5], OperationID: attack, UID: private[0], Action: attack, Phase: attack,
		StartedAt: attack, CompletedAt: attack, PollURL: private[3],
		Failure:        &adminv1.Failure{Code: attack, SuggestedAction: attack, Message: private[2]},
		DestroyPreview: &adminv1.DestroyPreview{Challenge: private[1]},
		Child:          &adminv1.OperationChild{Kind: private[4], Name: private[4], UID: private[4]},
	}}})
	for _, sentinel := range private {
		if strings.Contains(page, sentinel) {
			t.Errorf("private operation field %q escaped into the page", sentinel)
		}
	}
	if got := strings.Count(nodeText(doc), attack); got != 7 {
		t.Fatalf("untrusted display values did not survive as literal text: got %d, want 7", got)
	}
	assertPassivePage(t, doc)
}

func TestOperationListEmptyStates(t *testing.T) {
	for _, items := range [][]adminv1.Operation{nil, {}} {
		_, doc := renderOperationsPage(t, adminv1.OperationList{Items: items})
		if !strings.Contains(nodeText(doc), "No operations yet") {
			t.Fatal("empty operations page lacks its empty-state message")
		}
		cells := operationCells(t, doc)
		if len(cells) != 1 || len(cells[0]) != 1 {
			t.Fatalf("empty operations page has extra rows or cells: %v", cells)
		}
		if cell := elements(doc, "td")[0]; attribute(cell, "colspan") != "6" {
			t.Fatal("empty-state cell must span all six operation columns")
		}
		assertPassivePage(t, doc)
	}
}

func TestOperationListAbsentTimestampsAndSuggestedAction(t *testing.T) {
	_, doc := renderOperationsPage(t, adminv1.OperationList{Items: []adminv1.Operation{{OperationID: "pending", Failure: &adminv1.Failure{Code: "pending", Retryable: true}}}})
	want := [][]string{{"pending", "", "", "Not recorded", "Not recorded", "pending; retryable"}}
	if got := operationCells(t, doc); !reflect.DeepEqual(got, want) {
		t.Fatalf("absent observations = %#v, want %#v", got, want)
	}
}

func TestOperationListPropagatesWriterFailure(t *testing.T) {
	want := errors.New("operations writer unavailable")
	if err := RenderOperationList(failedWriter{want}, adminv1.OperationList{}); !errors.Is(err, want) {
		t.Fatalf("operations writer error = %v, want %v", err, want)
	}
}
