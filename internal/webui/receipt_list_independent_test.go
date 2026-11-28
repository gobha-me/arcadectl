// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
)

func TestOperationListReceiptLinkBelongsToDisplayedOperation(t *testing.T) {
	older := "ao-" + strings.Repeat("2", 51) + "a"
	newer := "ao-" + strings.Repeat("7", 51) + "q"
	invalid := older + "?view=status"
	const pollCanary = "fixture-private-poll-route"
	list := adminv1.OperationList{Items: []adminv1.Operation{
		{OperationID: older, Action: "server.start", Phase: "Running", StartedAt: "2026-11-23T11:00:00Z",
			PollURL: "/v1/operations/" + newer},
		{OperationID: newer, Action: "server.stop", Phase: "Failed", StartedAt: "2026-11-23T07:00:00-05:00",
			PollURL: "https://example.invalid/" + pollCanary},
		{OperationID: invalid, Action: "server.restart", Phase: "Pending", StartedAt: "2026-11-23T13:00:00Z",
			PollURL: "/v1/operations/" + older},
	}}
	page, doc := renderOperationsPage(t, list)
	if strings.Contains(page, pollCanary) {
		t.Error("API polling URL appeared in the operations page")
	}
	bodies := elements(doc, "tbody")
	if len(bodies) != 1 {
		t.Fatalf("table bodies = %d, want one", len(bodies))
	}
	rows := elements(bodies[0], "tr")
	want := []struct {
		id, action, phase, href string
	}{
		{invalid, "server.restart", "Pending", ""},
		{newer, "server.stop", "Failed", "/operations/" + newer},
		{older, "server.start", "Running", "/operations/" + older},
	}
	if len(rows) != len(want) {
		t.Fatalf("receipt rows = %d, want %d", len(rows), len(want))
	}
	for i, row := range rows {
		expected := want[i]
		cells := elements(row, "td")
		if len(cells) < 3 {
			t.Fatalf("row %d has only %d cells", i, len(cells))
		}
		if id, action, phase := nodeText(cells[0]), nodeText(cells[1]), nodeText(cells[2]); id != expected.id || action != expected.action || phase != expected.phase {
			t.Errorf("row %d shows %q / %q / %q, want %q / %q / %q", i, id, action, phase, expected.id, expected.action, expected.phase)
		}
		links := elements(row, "a")
		if expected.href == "" {
			if len(links) != 0 {
				t.Errorf("invalid receipt row has %d links, want none", len(links))
			}
			continue
		}
		if len(links) != 1 || len(elements(cells[0], "a")) != 1 {
			t.Errorf("row %d must link from its operation ID cell", i)
			continue
		}
		if href, label := attribute(links[0], "href"), nodeText(links[0]); href != expected.href || label != expected.id {
			t.Errorf("row %d link = %q to %q, want %q to %q", i, label, href, expected.id, expected.href)
		}
	}
}
