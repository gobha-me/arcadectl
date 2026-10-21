// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"reflect"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

// Authentication of original protected retirement evidence is separate from
// current-journal, live policy, access absence and coldness obligations. This
// witness never manufactures a historical Snapshot or grants runtime authority.
type retirementEvidence struct {
	name     string
	body     []byte
	identity privatefs.FileIdentity
	original installstate.Document
	receipt  retirementReceipt
	pin      *privatefs.FilePin
}

func (w *retirementEvidence) release() {
	if w != nil {
		_ = w.pin.Close()
	}
}

func (e *Engine) openRetirementEvidence(d installstate.Document) (*retirementEvidence, error) {
	if e == nil || e.files == nil || d.Mode != installstate.Uninstall || d.AdmissionRetirementRevision == 0 || d.AdmissionRetirementRevision >= d.Revision {
		return nil, ErrAdmission
	}
	name := retirementName(d, d.AdmissionRetirementRevision)
	body, identity, pin, err := e.files.Pin(name, retirementMaxBytes)
	if err != nil {
		return nil, ErrAdmission
	}
	transferred := false
	defer func() {
		if !transferred {
			_ = pin.Close()
		}
	}()
	if pin.Confirm() != nil {
		return nil, ErrAdmission
	}
	canonical, err := canonicaljson.CanonicalJSON(body)
	var receipt retirementReceipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err != nil || !bytes.Equal(canonical, body) || decoder.Decode(&receipt) != nil {
		return nil, ErrAdmission
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return nil, ErrAdmission
	}
	_, hasBaselineField := fields["baseline"]
	if d.SecurityBaseline == nil && (receipt.Version != "v1" || hasBaselineField) || d.SecurityBaseline != nil && (receipt.Version != "v2" || len(receipt.Baseline) != installbaseline.ResourceCount) {
		return nil, ErrAdmission
	}
	plans := make([]*installrender.Plan, 0, len(e.plans))
	for _, plan := range e.plans {
		plans = append(plans, plan)
	}
	original, err := installstate.DecodeWithBaseline(receipt.Journal, e.baselinePlan(), plans...)
	if err != nil || original.Mode != installstate.Uninstall || original.Stage != installstate.Applying || original.Pending != nil || original.AdmissionRetirementRevision != 0 ||
		original.Revision != d.AdmissionRetirementRevision || original.Namespace != d.Namespace || original.NamespaceUID != d.NamespaceUID || original.InstallationID != d.InstallationID ||
		original.ProfileID != d.ProfileID || original.TargetPackage != d.TargetPackage || original.ActivePackage != d.ActivePackage || original.PreviousPackage != d.PreviousPackage || !original.Installed || !reflect.DeepEqual(original.SecurityBaseline, d.SecurityBaseline) {
		return nil, ErrAdmission
	}
	plan := e.plans[d.TargetPackage]
	if !plan.IsTrusted() {
		return nil, ErrAdmission
	}
	for _, resource := range plan.Resources() {
		key := resourceKey(resource)
		entry, _ := e.inventory(original, key)
		if !resource.Retained && (accessRetirementKey(key) != (entry != nil)) {
			return nil, ErrAdmission
		}
	}
	// Authenticate every static row against the original signed inventory.
	// Current live equality is still the core's separate obligation. Source
	// authentication must not accept twelve wrong rows merely by their count.
	index := 0
	for _, resource := range original.Resources {
		if resource.Key.Kind != "ValidatingAdmissionPolicy" && resource.Key.Kind != "ValidatingAdmissionPolicyBinding" {
			continue
		}
		if index >= len(receipt.Policies) {
			return nil, ErrAdmission
		}
		row := receipt.Policies[index]
		if !resource.Retained || row.Key != resource.Key || row.Identity.UID != resource.UID || row.Identity.TemplateSHA256 != resource.TemplateSHA256 || !receiptUID.MatchString(row.Identity.ResourceVersion) {
			return nil, ErrAdmission
		}
		index++
	}
	if index != 12 || len(receipt.Policies) != index {
		return nil, ErrAdmission
	}
	if original.SecurityBaseline != nil {
		if len(receipt.Baseline) != len(original.SecurityBaseline.Resources) {
			return nil, ErrAdmission
		}
		for index, resource := range original.SecurityBaseline.Resources {
			row := receipt.Baseline[index]
			if row.Key != resource.Key || row.Identity.UID != resource.UID || row.Identity.TemplateSHA256 != resource.TemplateSHA256 || !receiptUID.MatchString(row.Identity.ResourceVersion) {
				return nil, ErrAdmission
			}
		}
	}
	transferred = true
	return &retirementEvidence{name, body, identity, original, receipt, pin}, nil
}

func (e *Engine) closeRetirementEvidence(witness *retirementEvidence) error {
	if e == nil || e.files == nil || witness == nil || witness.pin == nil {
		return ErrAdmission
	}
	body, identity, err := e.files.Read(witness.name, retirementMaxBytes)
	if err != nil || identity != witness.identity || !bytes.Equal(body, witness.body) || witness.pin.Confirm() != nil {
		return ErrAdmission
	}
	return nil
}
