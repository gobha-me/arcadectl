// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"strings"
	"testing"
)

func TestAdmissionRetirementLatchIsImmutableAndUninstallOnly(t *testing.T) {
	plan := testPlan(t)
	before := initialDocument(plan)
	before.Mode, before.Stage, before.Installed, before.ActivePackage = Uninstall, Applying, true, before.TargetPackage
	before.Resources = lifecycleResources(t, plan, false)
	before.Revision = 70
	next := lifecycleCopy(t, before)
	next.Revision++
	next.AdmissionRetirementRevision = before.Revision
	if !validTransition(before, next) {
		t.Fatal("observation-only original retirement latch rejected")
	}
	if _, err := Encode(next, plan); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"install", "upgrade", "rollback", "preparing", "quiescing", "verifying", "pending", "resources", "active", "revision", "target"} {
		t.Run(scenario, func(t *testing.T) {
			old, candidate := lifecycleCopy(t, before), lifecycleCopy(t, next)
			switch scenario {
			case "install", "upgrade", "rollback":
				old.Mode, candidate.Mode = Mode(scenario), Mode(scenario)
			case "preparing", "quiescing", "verifying":
				old.Stage, candidate.Stage = Stage(scenario), Stage(scenario)
			case "pending":
				old.Pending, candidate.Pending = &Pending{}, &Pending{}
			case "resources":
				candidate.Resources = candidate.Resources[1:]
			case "active":
				candidate.ActivePackage = strings.Repeat("e", 64)
			case "revision":
				candidate.AdmissionRetirementRevision--
			case "target":
				candidate.TargetPackage = strings.Repeat("e", 64)
			}
			if validTransition(old, candidate) {
				t.Fatal("invalid retirement latch accepted")
			}
		})
	}
	for _, marker := range []uint64{0, 69, 71} {
		bad := lifecycleCopy(t, next)
		bad.Revision++
		bad.AdmissionRetirementRevision = marker
		bad.Stage = Verifying
		if validTransition(next, bad) {
			t.Fatal("latched evidence changed during stage transition")
		}
	}
	legacy, err := Encode(before, plan)
	if err != nil || bytes.Contains(legacy, []byte("admissionRetirementRevision")) {
		t.Fatal("legacy canonical bytes gained an optional field")
	}
	decoded, err := Decode(legacy, plan)
	if err != nil || decoded.AdmissionRetirementRevision != 0 {
		t.Fatal("legacy omission was promoted into behavioral evidence")
	}
}
