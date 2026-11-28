// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"strings"
	"testing"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
)

func TestOperationDetailCompletionTimeAloneDoesNotProveCompletion(t *testing.T) {
	tests := []struct {
		phase, currentness, status string
		observed                   int64
	}{
		{phase: "Running", observed: 2, currentness: "Current generation", status: "Running"},
		{phase: "Verifying", observed: 2, currentness: "Current generation", status: "Completion unconfirmed"},
		{phase: "Deleting", observed: 2, currentness: "Current generation", status: "Completion unconfirmed"},
		{phase: "Failed", observed: 1, currentness: "Stale or unavailable", status: "Completion unconfirmed"},
		{phase: "Cancelled", observed: 1, currentness: "Stale or unavailable", status: "Completion unconfirmed"},
	}
	for _, test := range tests {
		t.Run(test.phase, func(t *testing.T) {
			_, doc := renderDetailPage(t, adminv1.Operation{
				OperationID: receiptIDForTest("7"), Phase: test.phase,
				Generation: 2, ObservedGeneration: test.observed,
				StartedAt: "2026-11-23T12:00:00Z", CompletedAt: "2026-11-23T12:00:01Z",
			})
			fields := detailValues(t, doc)
			if fields["Reported phase"] != test.phase || fields["Currentness"] != test.currentness || fields["Status"] != test.status {
				t.Errorf("reported phase/currentness/status = %q / %q / %q, want %q / %q / %q",
					fields["Reported phase"], fields["Currentness"], fields["Status"], test.phase, test.currentness, test.status)
			}
		})
	}
}

func TestOperationDetailTerminalStatusRequiresRecordedCompletion(t *testing.T) {
	// The zero time survives an RFC3339 round trip but records no completion.
	var unrecorded time.Time
	const started = "2026-11-23T12:00:00Z"
	for _, terminal := range []struct{ phase, status string }{
		{phase: "Succeeded", status: "Completed successfully"},
		{phase: "Failed", status: "Failed"},
		{phase: "Cancelled", status: "Cancelled"},
	} {
		t.Run(terminal.phase+"/zero time", func(t *testing.T) {
			_, doc := renderDetailPage(t, adminv1.Operation{
				OperationID: receiptIDForTest("z"), Phase: terminal.phase,
				Generation: 1, ObservedGeneration: 1,
				StartedAt: started, CompletedAt: unrecorded.Format(time.RFC3339Nano),
			})
			if got := detailValues(t, doc)["Status"]; got != "Completion unconfirmed" {
				t.Errorf("status with zero completion time = %q, want Completion unconfirmed", got)
			}
		})
		t.Run(terminal.phase+"/same second", func(t *testing.T) {
			_, doc := renderDetailPage(t, adminv1.Operation{
				OperationID: receiptIDForTest("z"), Phase: terminal.phase,
				Generation: 1, ObservedGeneration: 1,
				StartedAt: started, CompletedAt: started,
			})
			if got := detailValues(t, doc)["Status"]; got != terminal.status {
				t.Errorf("status with completion in the start second = %q, want %q", got, terminal.status)
			}
		})
	}
}

func TestOperationDetailAwaitingConfirmationOffersOnlyManualReads(t *testing.T) {
	id := receiptIDForTest("2")
	page, doc := renderDetailPage(t, adminv1.Operation{
		OperationID: id, UID: "receipt-private-uid", Action: "world.destroy.preview",
		Phase: "AwaitingConfirmation", Generation: 1, ObservedGeneration: 1,
		PollURL: "https://example.invalid/receipt-private-poll",
		DestroyPreview: &adminv1.DestroyPreview{
			Challenge:       "receipt-private-challenge",
			ExpiresAt:       "2026-11-23T12:00:02Z",
			RestoreGuidance: "receipt-private-restore-guidance",
			BackupRef:       adminv1.ExactReference{Name: "receipt-private-backup", UID: "receipt-private-backup-uid"},
			Target: adminv1.DestroyTarget{
				Namespace:      "receipt-private-namespace",
				OriginalServer: adminv1.ExactReference{Name: "receipt-private-server", UID: "receipt-private-server-uid"},
				DataIdentity:   "receipt-private-data",
				Claims: []adminv1.RetainedClaim{{
					Path: "receipt-private-path", ClaimRef: adminv1.ExactReference{Name: "receipt-private-claim", UID: "receipt-private-claim-uid"},
				}},
			},
		},
	})
	if strings.Contains(page, "receipt-private-") || strings.Contains(page, "2026-11-23T12:00:02Z") {
		t.Error("receipt exposed a field outside the detail allowlist")
	}
	if got := detailValues(t, doc)["Status"]; got != "Awaiting confirmation" {
		t.Errorf("preview status = %q, want Awaiting confirmation", got)
	}
	if !strings.Contains(nodeText(doc), "cannot confirm or cancel") {
		t.Error("preview does not explain the read-only boundary")
	}
	assertLocalNavigation(t, doc, "Refresh receipt", "/operations/"+id)
	for _, meta := range elements(doc, "meta") {
		if strings.EqualFold(strings.TrimSpace(attribute(meta, "http-equiv")), "refresh") {
			t.Error("receipt automatically refreshes through a meta directive")
		}
	}
	for _, tag := range []string{"button", "input"} {
		if len(elements(doc, tag)) > 0 {
			t.Errorf("read-only preview has an unexpected <%s> control", tag)
		}
	}
}
