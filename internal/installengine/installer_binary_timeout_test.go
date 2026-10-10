// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import "testing"

// Test-fixture caller configuration only: this cannot change a production
// default, nested proof deadline or enclosing fixture/test/job context.
func installerBinaryCallerBudget(mode, command string, historical bool) string {
	if mode == "fresh" && !historical && command == "install" {
		return "3h"
	}
	return "2h"
}

func TestInstallerBinaryCallerBudgetKeepsNonFreshCommandsUnchanged(t *testing.T) {
	// The one enlarged configuration is literal test data, not the helper's
	// branch copied into a second classifier.
	enlarged := map[[3]string]string{{"fresh", "current", "install"}: "3h"}
	for _, mode := range []string{"fresh", "transition"} {
		for _, historical := range []bool{false, true} {
			identity := "current"
			if historical {
				identity = "historical"
			}
			for _, command := range []string{"install", "enroll-baseline", "upgrade", "rollback", "uninstall", "resume"} {
				want := "2h"
				if selected := enlarged[[3]string{mode, identity, command}]; selected != "" {
					want = selected
				}
				if installerBinaryCallerBudget(mode, command, historical) != want {
					t.Fatal("test caller budget escaped its selected current fresh install command")
				}
			}
		}
	}
}
