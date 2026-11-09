// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"golang.org/x/net/html"
)

func renderPage(t *testing.T, list adminv1.ServerList) (string, *html.Node) {
	t.Helper()
	var output bytes.Buffer
	if err := RenderServerList(&output, list); err != nil {
		t.Fatalf("RenderServerList: %v", err)
	}
	doc, err := html.Parse(strings.NewReader(output.String()))
	if err != nil {
		t.Fatalf("parse page: %v", err)
	}
	return output.String(), doc
}

func elements(root *html.Node, tag string) []*html.Node {
	var found []*html.Node
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == tag {
			found = append(found, node)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(root)
	return found
}

func attribute(node *html.Node, key string) string {
	for _, attr := range node.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func nodeText(node *html.Node) string {
	var text strings.Builder
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.TextNode {
			text.WriteString(node.Data)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(node)
	return strings.TrimSpace(text.String())
}

func TestServerListAccessibleStructure(t *testing.T) {
	_, doc := renderPage(t, adminv1.ServerList{})
	if nodes := elements(doc, "html"); len(nodes) != 1 || attribute(nodes[0], "lang") != "en" {
		t.Fatal("page must declare English")
	}
	if titles := elements(doc, "title"); len(titles) != 1 || nodeText(titles[0]) != "Arcadectl server status" {
		t.Fatal("page must have a meaningful title")
	}
	if headings := elements(doc, "h1"); len(headings) != 1 || nodeText(headings[0]) != "Servers" {
		t.Fatal("page must have exactly one Servers heading")
	}
	mains := elements(doc, "main")
	if len(mains) != 1 || attribute(mains[0], "id") == "" {
		t.Fatal("page must have one named main landmark")
	}
	skip := false
	for _, link := range elements(doc, "a") {
		if attribute(link, "href") == "#"+attribute(mains[0], "id") && nodeText(link) == "Skip to server status" {
			skip = true
		}
	}
	if !skip {
		t.Fatal("skip link must target the main landmark")
	}
	tables := elements(mains[0], "table")
	if len(tables) != 1 {
		t.Fatal("main must contain one status table")
	}
	if captions := elements(tables[0], "caption"); len(captions) != 1 || nodeText(captions[0]) != "Server status" {
		t.Fatal("status table must have a caption")
	}
	headers := elements(tables[0], "th")
	want := []string{"Name", "Game", "Phase", "Desired state", "Ready", "Player endpoints"}
	if len(headers) != len(want) {
		t.Fatalf("headers = %d, want %d", len(headers), len(want))
	}
	for i, header := range headers {
		if attribute(header, "scope") != "col" || nodeText(header) != want[i] {
			t.Errorf("header %d lacks its column name or scope", i)
		}
	}
}

func TestServerListSortedRowsAndEveryCell(t *testing.T) {
	list := adminv1.ServerList{Items: []adminv1.Server{
		{Name: "zeta", Game: "game-b", Phase: "Stopped", DesiredState: "Stopped", Conditions: []adminv1.Condition{{Type: "Ready", Status: "False", Reason: "Paused"}}, Endpoints: []adminv1.Endpoint{{Address: "host.example", Port: 8080, Protocol: "UDP"}}},
		{Name: "alpha", Game: "game-a", Phase: "Running", DesiredState: "Running", Conditions: []adminv1.Condition{{Type: "Other", Status: "False", Reason: "not-readiness"}, {Type: "Ready", Status: "True"}}, Endpoints: []adminv1.Endpoint{{Address: "127.0.0.1", Port: 1234, Protocol: "TCP"}, {Address: "::1", Port: 1234, Protocol: "UDP"}}},
	}}
	_, doc := renderPage(t, list)
	bodies := elements(doc, "tbody")
	if len(bodies) != 1 {
		t.Fatal("missing table body")
	}
	rows := elements(bodies[0], "tr")
	want := [][]string{
		{"alpha", "game-a", "Running", "Running", "Ready: True", "127.0.0.1:1234/TCP[::1]:1234/UDP"},
		{"zeta", "game-b", "Stopped", "Stopped", "Ready: False (Paused)", "host.example:8080/UDP"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows = %d, want %d", len(rows), len(want))
	}
	for i, row := range rows {
		cells := elements(row, "td")
		var got []string
		for _, cell := range cells {
			got = append(got, nodeText(cell))
		}
		if !reflect.DeepEqual(got, want[i]) {
			t.Errorf("row %d = %#v, want %#v", i, got, want[i])
		}
	}
	if list.Items[0].Name != "zeta" || list.Items[1].Name != "alpha" {
		t.Fatal("rendering reordered the caller's list")
	}
}

func TestServerListTreatsAllAPIStringsAsTextAndOmitsPrivateFields(t *testing.T) {
	attack := `<script>alert(1)</script>"onmouseover=`
	private := "PRIVATE-SETTINGS-SENTINEL"
	uid := "PRIVATE-UID-SENTINEL"
	settings, err := json.Marshal(map[string]string{"value": private})
	if err != nil {
		t.Fatal(err)
	}
	page, doc := renderPage(t, adminv1.ServerList{Items: []adminv1.Server{{
		Name: attack, Game: attack, Phase: attack, DesiredState: attack, UID: uid, Settings: settings,
		Conditions: []adminv1.Condition{{Type: "Ready", Status: "False", Reason: attack}},
		Endpoints:  []adminv1.Endpoint{{Address: attack, Port: 8080, Protocol: attack}},
	}}})
	if strings.Contains(page, private) || strings.Contains(page, uid) || strings.Contains(page, `"settings"`) {
		t.Fatal("settings, UID or raw JSON escaped into the page")
	}
	if got := strings.Count(nodeText(doc), attack); got != 7 {
		t.Fatalf("untrusted strings did not survive as literal text: got %d, want 7", got)
	}
	assertPassivePage(t, doc)
}

func assertPassivePage(t *testing.T, node *html.Node) {
	t.Helper()
	if node.Type == html.ElementNode {
		if node.Data == "script" || node.Data == "style" || node.Data == "link" || node.Data == "form" {
			t.Errorf("unexpected active or external-resource element %q", node.Data)
		}
		for _, attr := range node.Attr {
			if strings.HasPrefix(strings.ToLower(attr.Key), "on") || attr.Key == "style" || attr.Key == "src" {
				t.Errorf("unexpected event/style/resource attribute %q", attr.Key)
			}
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		assertPassivePage(t, child)
	}
}

func TestServerListEmptyStates(t *testing.T) {
	for _, items := range [][]adminv1.Server{nil, {}} {
		_, doc := renderPage(t, adminv1.ServerList{Items: items})
		text := nodeText(doc)
		if !strings.Contains(text, "No servers yet") || !strings.Contains(text, "arcadectl server create") {
			t.Fatal("empty page lacks status and creation guidance")
		}
		assertPassivePage(t, doc)
	}
}

func TestServerListMissingReadinessAndEndpoints(t *testing.T) {
	_, doc := renderPage(t, adminv1.ServerList{Items: []adminv1.Server{{Name: "quiet"}}})
	text := nodeText(doc)
	if !strings.Contains(text, "Ready: Unknown") || !strings.Contains(text, "None") {
		t.Fatal("missing observations must have explicit text")
	}
}

type failedWriter struct{ err error }

func (w failedWriter) Write([]byte) (int, error) { return 0, w.err }

func TestServerListPropagatesWriterFailure(t *testing.T) {
	want := errors.New("writer unavailable")
	if err := RenderServerList(failedWriter{want}, adminv1.ServerList{}); !errors.Is(err, want) {
		t.Fatalf("writer error = %v, want %v", err, want)
	}
}
