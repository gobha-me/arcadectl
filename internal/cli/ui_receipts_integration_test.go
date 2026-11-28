// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"fmt"
	"strings"
	"testing"
)

func TestUIReceiptCommandUsesRealSavedContextAndAPI(t *testing.T) {
	fixture := newUIFixture(t)
	code, output, stderr := fixture.run(t, "--context", "ui-fixture", "--output", "json", "--no-wait", "server", "stop", "factory")
	if code != 0 || stderr != "" {
		t.Fatal("receipt setup failed")
	}
	id := integrationField(t, output, "operationID")
	url := fixture.start(t, false)
	before := len(fixture.snapshot())
	mutations := fixture.mutationCount()
	for _, path := range []string{"operations", "operations/" + id} {
		status, headers, body := uiRequest(t, "GET", url+path, "")
		if status != 200 || !strings.Contains(body, id) {
			t.Fatal("operation view unavailable through real context/API")
		}
		assertUIHeaders(t, headers)
		fixture.assertSafe(t, body+fmt.Sprint(headers))
	}
	requests := fixture.snapshot()[before:]
	if len(requests) != 2 || requests[0] != "GET /v1/operations" || requests[1] != "GET /v1/operations/"+id || fixture.mutationCount() != mutations {
		t.Fatal("receipt navigation changed upstream read boundary")
	}
}
