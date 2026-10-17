// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/types"
)

// The operation remains a copied signed descriptor, not an owned handle.
// This separate witness holds the opening protected CREATE receipt and, for
// retained reinstall, both original source descriptors through the entire
// prerequisite proof or recovery settlement. Empty UID records establish only
// durable preparation; they cannot identify a present target. The source owner
// exists even before there is a pending CREATE.
type prerequisiteReceiptWitness struct {
	uid     types.UID
	receipt *baselineOriginalReceipt
	source  *reinstallSourceWitness
}

func (w *prerequisiteReceiptWitness) release() {
	if w != nil {
		w.receipt.release()
		w.source.release()
	}
}

func (e *Engine) openPrerequisiteReceipt(s *installstate.Snapshot, operation *baselinePrerequisite) (*prerequisiteReceiptWitness, error) {
	if _, err := e.prerequisiteContext(s, operation); err != nil {
		return nil, ErrSecurityBaseline
	}
	d := s.Document()
	witness := &prerequisiteReceiptWitness{}
	transferred := false
	defer func() {
		if !transferred {
			witness.release()
		}
	}()
	if d.ActivePackage != "" {
		var err error
		witness.source, err = e.openReinstallSource(s)
		if err != nil {
			return nil, ErrSecurityBaseline
		}
	}
	if d.Pending == nil {
		if witness.source == nil {
			return nil, nil // fresh, with no local evidence to own yet
		}
		if e.confirmPrerequisiteReceipt(s, operation, witness) != nil {
			return nil, ErrSecurityBaseline
		}
		transferred = true
		return witness, nil
	}
	if e.files == nil || !nonceID.MatchString(d.Pending.CreateNonce) {
		return nil, ErrSecurityBaseline
	}
	body, identity, pin, err := e.files.Pin("create-"+d.Pending.CreateNonce+".json", 4096)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	witness.receipt = &baselineOriginalReceipt{identity: identity, body: bytes.Clone(body), pin: pin}
	var record createReceipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil {
		return nil, ErrSecurityBaseline
	}
	want, err := receiptBody(d, record.OriginalUID)
	if err != nil || !bytes.Equal(want, body) || pin.Confirm() != nil {
		return nil, ErrSecurityBaseline
	}
	witness.uid = record.OriginalUID
	if e.confirmPrerequisiteReceipt(s, operation, witness) != nil {
		return nil, ErrSecurityBaseline
	}
	transferred = true
	return witness, nil
}

// Confirmation never releases or renews the original owned descriptor.
func (e *Engine) confirmPrerequisiteReceipt(s *installstate.Snapshot, operation *baselinePrerequisite, witness *prerequisiteReceiptWitness) error {
	if _, err := e.prerequisiteContext(s, operation); err != nil {
		return ErrSecurityBaseline
	}
	if operation.secrets != nil && (operation.secrets.confirm(s) != nil || operation.secrets.workflow.engine != e) {
		return ErrSecurityBaseline
	}
	d := s.Document()
	if d.ActivePackage != "" {
		if witness == nil || witness.source == nil || d.AdmissionReinstall == nil || witness.source.provenance != *d.AdmissionReinstall || e.closeReinstallSource(witness.source) != nil {
			return ErrSecurityBaseline
		}
	} else if witness != nil && witness.source != nil {
		return ErrSecurityBaseline
	}
	if d.Pending == nil {
		if witness != nil && (witness.source == nil || witness.receipt != nil || witness.uid != "") {
			return ErrSecurityBaseline
		}
		return nil
	}
	if e.files == nil || witness == nil || witness.receipt == nil || witness.receipt.pin == nil || !nonceID.MatchString(d.Pending.CreateNonce) {
		return ErrSecurityBaseline
	}
	want, err := receiptBody(d, witness.uid)
	if err != nil || !bytes.Equal(want, witness.receipt.body) {
		return ErrSecurityBaseline
	}
	body, identity, err := e.files.Read("create-"+d.Pending.CreateNonce+".json", 4096)
	if err != nil || identity != witness.receipt.identity || !bytes.Equal(body, witness.receipt.body) || witness.receipt.pin.Confirm() != nil {
		return ErrSecurityBaseline
	}
	return nil
}
