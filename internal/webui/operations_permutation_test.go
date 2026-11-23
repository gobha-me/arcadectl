// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package webui_test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/webui"
	"golang.org/x/net/html"
)

func TestOperationListChronologicalOrderAcrossEveryPermutation(t *testing.T) {
	t.Parallel()

	// The middle two receipts started at the same instant. Their different
	// offsets and fractional precision must not take precedence over the ID
	// tie-break. The other two instants differ from them by one nanosecond.
	fixture := []adminv1.Operation{
		{OperationID: "newest", StartedAt: "2026-11-23T12:00:00.100000001Z"},
		{OperationID: "tie-a", StartedAt: "2026-11-23T07:00:00.1-05:00"},
		{OperationID: "tie-z", StartedAt: "2026-11-23T13:00:00.100+01:00"},
		{OperationID: "oldest", StartedAt: "2026-11-23T12:00:00.099999999Z"},
	}
	want := []string{"newest", "tie-a", "tie-z", "oldest"}
	indices := []int{0, 1, 2, 3}
	permutations := 0
	var visit func(int)
	visit = func(position int) {
		if position != len(indices) {
			for next := position; next < len(indices); next++ {
				indices[position], indices[next] = indices[next], indices[position]
				visit(position + 1)
				indices[position], indices[next] = indices[next], indices[position]
			}
			return
		}
		permutations++
		t.Run(fmt.Sprint(indices), func(t *testing.T) {
			items := make([]adminv1.Operation, len(indices))
			for position, index := range indices {
				items[position] = fixture[index]
			}
			var output bytes.Buffer
			if err := webui.RenderOperationList(&output, adminv1.OperationList{Version: "v1", Items: items}); err != nil {
				t.Fatal(err)
			}
			document, err := html.Parse(strings.NewReader(output.String()))
			if err != nil {
				t.Fatal(err)
			}
			if got := permutationOperationIDs(document); !reflect.DeepEqual(got, want) {
				t.Fatalf("chronological row IDs = %q; want %q", got, want)
			}
		})
	}
	visit(0)
	if permutations != 24 {
		t.Fatalf("permutations rendered = %d; want all 24", permutations)
	}
}

func permutationOperationIDs(document *html.Node) []string {
	var ids []string
	var text func(*html.Node) string
	text = func(node *html.Node) string {
		if node.Type == html.TextNode {
			return node.Data
		}
		var content strings.Builder
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			content.WriteString(text(child))
		}
		return content.String()
	}
	var visit func(*html.Node, bool)
	visit = func(node *html.Node, inBody bool) {
		inBody = inBody || node.Type == html.ElementNode && node.Data == "tbody"
		if inBody && node.Type == html.ElementNode && node.Data == "tr" {
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				if child.Type == html.ElementNode && child.Data == "td" {
					ids = append(ids, strings.TrimSpace(text(child)))
					break
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child, inBody)
		}
	}
	visit(document, false)
	return ids
}

func TestOperationListPublicCellsAndAccessibleLandmarks(t *testing.T) {
	t.Parallel()
	items := []adminv1.Operation{
		{OperationID: "middle", Action: "server.stop", Phase: "Running", StartedAt: "2026-11-23T12:00:01Z"},
		{OperationID: "oldest", Action: "server.start", Phase: "Succeeded", StartedAt: "2026-11-23T12:00:00Z", CompletedAt: "2026-11-23T12:00:01Z"},
		{OperationID: "newest", Action: "server.backup", Phase: "Failed", StartedAt: "2026-11-23T12:00:02Z", CompletedAt: "2026-11-23T12:00:03Z", Failure: &adminv1.Failure{Code: "backup_unavailable", Retryable: true, SuggestedAction: "Inspect the backup target."}},
	}
	var output bytes.Buffer
	if err := webui.RenderOperationList(&output, adminv1.OperationList{Version: "v1", Items: items}); err != nil {
		t.Fatal(err)
	}
	document, err := html.Parse(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var rows [][]string
	var mainIDs, linkTargets []string
	var h1s, captions, headers int
	lang := ""
	operationWalk(document, func(node *html.Node) {
		switch node.Data {
		case "html":
			lang = operationAttr(node, "lang")
		case "h1":
			h1s++
		case "main":
			mainIDs = append(mainIDs, operationAttr(node, "id"))
		case "a":
			linkTargets = append(linkTargets, operationAttr(node, "href"))
		case "caption":
			captions++
			if operationText(node) == "" {
				t.Error("empty operations table caption")
			}
		case "th":
			headers++
			if operationAttr(node, "scope") != "col" {
				t.Error("header lacks column scope")
			}
		case "tr":
			var cells []string
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				if child.Type == html.ElementNode && child.Data == "td" {
					cells = append(cells, operationText(child))
				}
			}
			if len(cells) != 0 {
				rows = append(rows, cells)
			}
		}
	})
	if lang != "en" || h1s != 1 || captions != 1 || headers != 6 || len(mainIDs) != 1 || mainIDs[0] == "" {
		t.Fatalf("accessibility landmarks: lang=%q h1=%d captions=%d headers=%d mainIDs=%q", lang, h1s, captions, headers, mainIDs)
	}
	foundSkip := false
	for _, target := range linkTargets {
		foundSkip = foundSkip || target == "#"+mainIDs[0]
	}
	if !foundSkip {
		t.Fatal("no skip link targets the main landmark")
	}
	if len(rows) != 3 {
		t.Fatalf("data rows=%d, want 3", len(rows))
	}
	for i, operation := range []adminv1.Operation{items[2], items[0], items[1]} {
		if len(rows[i]) != 6 {
			t.Fatalf("row %d cells=%d, want 6", i, len(rows[i]))
		}
		for column, value := range []string{operation.OperationID, operation.Action, operation.Phase, operation.StartedAt, operation.CompletedAt} {
			if value != "" && rows[i][column] != value {
				t.Errorf("row %d column %d=%q, want %q", i, column, rows[i][column], value)
			}
		}
	}
	failureText := strings.Join(strings.Fields(rows[0][5]), " ")
	if strings.Contains(failureText, "not retryable") {
		t.Error("retryable failure rendered as not retryable")
	}
	for _, value := range []string{"backup_unavailable", "retryable", "Inspect the backup target."} {
		if !strings.Contains(rows[0][5], value) {
			t.Errorf("failure cell %q omits %q", rows[0][5], value)
		}
	}
}

func TestOperationListEscapesPublicFieldsAndExcludesPrivateFields(t *testing.T) {
	t.Parallel()
	attack := `<script>alert(1)</script>"onmouseover=`
	operation := adminv1.Operation{
		OperationID: "escaped-operation", Action: attack, Phase: attack,
		UID: "PRIVATE-OPERATION-UID", StartedAt: "2026-11-23T12:00:00Z",
		Failure:        &adminv1.Failure{Code: attack, Retryable: false, SuggestedAction: attack, Message: "PRIVATE-FAILURE-MESSAGE"},
		DestroyPreview: &adminv1.DestroyPreview{Challenge: "PRIVATE-DESTROY-CHALLENGE"},
	}
	var output bytes.Buffer
	if err := webui.RenderOperationList(&output, adminv1.OperationList{Version: "v1", Items: []adminv1.Operation{operation}}); err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{operation.UID, operation.Failure.Message, operation.DestroyPreview.Challenge} {
		if strings.Contains(output.String(), private) {
			t.Errorf("output exposes private field %q", private)
		}
	}
	document, err := html.Parse(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	operationWalk(document, func(node *html.Node) {
		if node.Data == "script" {
			t.Error("API input created a script element")
		}
		for _, attribute := range node.Attr {
			if strings.HasPrefix(strings.ToLower(attribute.Key), "on") {
				t.Errorf("API input created event attribute %q", attribute.Key)
			}
		}
	})
	visible := operationText(document)
	if strings.Count(visible, attack) != 4 || !strings.Contains(visible, "not retryable") {
		t.Fatalf("public text lost escaping or retryability: %q", visible)
	}
}

func TestOperationListEmptyCollections(t *testing.T) {
	t.Parallel()
	for _, items := range [][]adminv1.Operation{nil, {}} {
		var output bytes.Buffer
		if err := webui.RenderOperationList(&output, adminv1.OperationList{Version: "v1", Items: items}); err != nil {
			t.Fatal(err)
		}
		document, err := html.Parse(bytes.NewReader(output.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(operationText(document), "No operations yet") {
			t.Fatal("empty operations collection lacks empty-state text")
		}
	}
}

func TestOperationListReportsOutputFailure(t *testing.T) {
	want := errors.New("independent output boundary failed")
	err := webui.RenderOperationList(operationListFailingWriter{err: want}, adminv1.OperationList{Version: "v1"})
	if !errors.Is(err, want) {
		t.Fatalf("render output error=%v, want writer failure %v", err, want)
	}
}

type operationListFailingWriter struct{ err error }

func (writer operationListFailingWriter) Write([]byte) (int, error) { return 0, writer.err }

func operationWalk(node *html.Node, visit func(*html.Node)) {
	if node.Type == html.ElementNode {
		visit(node)
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		operationWalk(child, visit)
	}
}

func operationAttr(node *html.Node, key string) string {
	for _, attribute := range node.Attr {
		if attribute.Key == key {
			return attribute.Val
		}
	}
	return ""
}

func operationText(node *html.Node) string {
	var output strings.Builder
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.TextNode {
			output.WriteString(node.Data)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(node)
	return strings.TrimSpace(output.String())
}
