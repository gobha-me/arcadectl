// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import "testing"

// Closed test-only vocabulary. Never render command arguments, private output,
// error text, endpoint, server/operation identity, or credential-file paths.
func nativeCLIStage(args []string) string {
	if len(args) > 0 && args[0] == "login" {
		return "login"
	}
	if len(args) > 1 {
		switch {
		case args[0] == "server" && args[1] == "status":
			return "server-status"
		case args[0] == "server" && args[1] == "start":
			return "server-start"
		case args[0] == "server" && args[1] == "stop":
			return "server-stop"
		case args[0] == "operation" && args[1] == "wait":
			return "operation-wait"
		}
	}
	return "unavailable"
}

func TestNativeCLIStageIsClosedAndCredentialFree(t *testing.T) {
	for _, fixture := range []struct {
		args []string
		want string
	}{
		{nil, "unavailable"},
		{[]string{"PRIVATE-CANARY"}, "unavailable"},
		{[]string{"server"}, "unavailable"},
		{[]string{"server", "PRIVATE-CANARY"}, "unavailable"},
		{[]string{"PRIVATE-CANARY", "wait"}, "unavailable"},
		{[]string{"login", "PRIVATE-CANARY", "--credential-file", "PRIVATE-CANARY"}, "login"},
		{[]string{"server", "status", "PRIVATE-CANARY"}, "server-status"},
		{[]string{"server", "start", "PRIVATE-CANARY", "--no-wait"}, "server-start"},
		{[]string{"server", "stop", "PRIVATE-CANARY"}, "server-stop"},
		{[]string{"operation", "wait", "PRIVATE-CANARY"}, "operation-wait"},
	} {
		if nativeCLIStage(fixture.args) != fixture.want {
			t.Fatal("fixed native CLI stage escaped its closed vocabulary")
		}
	}
}
