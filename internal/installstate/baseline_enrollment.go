// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"encoding/json"
	"reflect"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
)

// BaselineEnrollmentProvenance identifies the literal original installed
// journal used by an explicit enrollment. It is immutable audit provenance,
// never permission to reuse that source inventory for later runtime effects.
// The engine separately proves protected source/bootstrap/CA ownership, live
// original resources, cold worlds and complete producer chains at effect edges.
type BaselineEnrollmentProvenance struct {
	SourceRevision      uint64 `json:"sourceRevision"`
	SourceJournalSHA256 string `json:"sourceJournalSha256"`
}

func baselineEnrollmentSource(d Document) bool {
	return d.Stage == Complete && d.Installed && d.Pending == nil && d.ActivePackage != "" && d.ActivePackage == d.TargetPackage && d.AdmissionRetirementRevision == 0 && d.AdmissionReinstall == nil &&
		(d.Mode == Install || d.Mode == Upgrade || d.Mode == Rollback)
}

func enrollmentProvenance(d Document) *BaselineEnrollmentProvenance {
	if d.SecurityBaseline == nil {
		return nil
	}
	return d.SecurityBaseline.Enrollment
}

func validateBaselineEnrollment(d Document) error {
	p := enrollmentProvenance(d)
	if p == nil {
		return nil
	}
	if p.SourceRevision == 0 || p.SourceRevision >= d.Revision || !digestID.MatchString(p.SourceJournalSHA256) {
		return ErrInvalid
	}
	if d.SecurityBaseline.Stage != BaselineVerified && !baselineEnrollmentSource(d) {
		return ErrInvalid // Incomplete enrollment cannot advance historical runtime.
	}
	return nil
}

// This gate precedes the baseline shortcut, so no baseline settlement, recovery,
// upgrade, rollback or retaining uninstall can introduce, erase or repin an
// already-established source. The initial pin changes no runtime field.
func validBaselineEnrollmentTransition(before, next Document) bool {
	a, b := enrollmentProvenance(before), enrollmentProvenance(next)
	if reflect.DeepEqual(a, b) {
		return true
	}
	if a != nil || b == nil || before.SecurityBaseline != nil || !baselineEnrollmentSource(before) || next.SecurityBaseline.Stage != BaselinePreparing || len(next.SecurityBaseline.Resources) != 0 || next.SecurityBaseline.Pending != nil || b.SourceRevision != before.Revision {
		return false
	}
	oldRuntime, newRuntime := before, next
	newRuntime.SecurityBaseline = nil
	newRuntime.Revision = oldRuntime.Revision
	if !reflect.DeepEqual(oldRuntime, newRuntime) {
		return false
	}
	body, err := json.Marshal(before)
	if err == nil {
		body, err = canonicaljson.CanonicalJSON(body)
	}
	return err == nil && len(body) <= MaxBytes && b.SourceJournalSHA256 == journalSHA256(body)
}
