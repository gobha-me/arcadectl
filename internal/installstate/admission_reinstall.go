// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
)

// ReinstallProvenance identifies the exact canonical completed-uninstall
// journal, not a live lookup by installation/namespace name. The engine must
// separately authenticate its protected source and original retirement receipt
// and reobserve cold retained identities before any nonexecuting recreation.
type ReinstallProvenance struct {
	SourceRevision      uint64 `json:"sourceRevision"`
	SourceJournalSHA256 string `json:"sourceJournalSha256"`
}

func validateAdmissionReinstall(d Document) error {
	p := d.AdmissionReinstall
	if p == nil {
		return nil
	}
	if p.SourceRevision == 0 || p.SourceRevision >= d.Revision || !digestID.MatchString(p.SourceJournalSHA256) ||
		d.Mode != Install || d.ActivePackage == "" || d.ActivePackage != d.TargetPackage || d.AdmissionRetirementRevision != 0 ||
		d.SecurityBaseline == nil || d.SecurityBaseline.Stage != BaselineVerified || d.SecurityBaseline.Pending != nil {
		return ErrInvalid
	}
	return nil
}

func journalSHA256(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

// This gate precedes all transition shortcuts, including baseline evolution.
// No change of stage, intent, settlement, recovery or baseline can erase or
// repin a reinstall's source. Legacy baseline omission remains historical.
func validReinstallTransition(before, next Document) bool {
	if before.Stage == Complete && !before.Installed && next.Mode == Install && before.SecurityBaseline != nil {
		if before.Mode != Uninstall || before.Pending != nil || before.AdmissionRetirementRevision == 0 || before.AdmissionRetirementRevision >= before.Revision ||
			before.SecurityBaseline.Stage != BaselineVerified || before.SecurityBaseline.Pending != nil || before.AdmissionReinstall != nil ||
			next.Stage != Preparing || next.Pending != nil || next.AdmissionReinstall == nil || next.AdmissionReinstall.SourceRevision != before.Revision ||
			next.AdmissionRetirementRevision != 0 || next.ActivePackage != before.ActivePackage || next.TargetPackage != before.ActivePackage ||
			!reflect.DeepEqual(before.SecurityBaseline, next.SecurityBaseline) || len(before.Resources) != 20 {
			return false
		}
		for _, resource := range before.Resources {
			if !resource.Retained {
				return false
			}
		}
		body, err := json.Marshal(before)
		if err != nil {
			return false
		}
		body, err = canonicaljson.CanonicalJSON(body)
		return err == nil && len(body) <= MaxBytes && next.AdmissionReinstall.SourceJournalSHA256 == journalSHA256(body)
	}
	if reflect.DeepEqual(before.AdmissionReinstall, next.AdmissionReinstall) {
		return true
	}
	// A completed installed reinstall may begin a subsequent operation, which
	// no longer uses the cold-retirement source. Existing Begin gates still
	// determine valid mode, package, inventory and revision changes.
	return before.AdmissionReinstall != nil && next.AdmissionReinstall == nil && before.Stage == Complete && before.Installed && next.Stage == Preparing && next.Mode != Install
}
