// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/types"
)

const baselineReceiptVersion = "arcadectl.install-security-create/v1"

// A distinct receipt domain/filename prevents runtime or foreign artifact
// evidence being reinterpreted as baseline ownership. Historical receipts are
// unchanged. Only public original identity is persisted, in protected storage.
type baselineCreateReceipt struct {
	Version         string               `json:"version"`
	Anchor          installstate.Anchor  `json:"anchor"`
	BaselineVersion string               `json:"baselineVersion"`
	ArtifactDigest  string               `json:"artifactDigest"`
	Pending         installstate.Pending `json:"pending"`
	OriginalUID     types.UID            `json:"originalUid"`
}

func (b *baselineWorkflow) receiptBody(document installstate.Document, uid types.UID) ([]byte, error) {
	if b == nil || !b.plan.IsTrusted() || b.contract == nil || document.Namespace != b.plan.Namespace() || document.ProfileID != b.plan.Profile() || !receiptUID.MatchString(string(document.NamespaceUID)) || !nonceID.MatchString(document.InstallationID) || document.Pending != nil || document.SecurityBaseline == nil || document.SecurityBaseline.ArtifactDigest != b.plan.Digest() || document.SecurityBaseline.Version != installbaseline.Version || uid != "" && !receiptUID.MatchString(string(uid)) {
		return nil, ErrOwnership
	}
	pending := document.SecurityBaseline.Pending
	if pending == nil || pending.Action != installstate.Create || !nonceID.MatchString(pending.CreateNonce) || pending.BeforeUID != "" || pending.BeforeResourceVersion != "" || pending.BeforeSHA256 != "" {
		return nil, ErrOwnership
	}
	template, err := b.contract.Template(pending.Key, false)
	if err != nil || template.Hash() != pending.AfterSHA256 {
		return nil, ErrOwnership
	}
	receipt := baselineCreateReceipt{Version: baselineReceiptVersion, Anchor: installstate.Anchor{Namespace: document.Namespace, UID: document.NamespaceUID, InstallationID: document.InstallationID}, BaselineVersion: installbaseline.Version, ArtifactDigest: b.plan.Digest(), Pending: *pending, OriginalUID: uid}
	body, err := json.Marshal(receipt)
	if err != nil || len(body) > 4096 {
		return nil, ErrOwnership
	}
	body, err = canonicaljson.CanonicalJSON(body)
	if err != nil {
		return nil, ErrOwnership
	}
	return body, nil
}

func (b *baselineWorkflow) receiptName(document installstate.Document) (string, error) {
	if _, err := b.receiptBody(document, ""); err != nil {
		return "", err
	}
	return "baseline-create-" + document.SecurityBaseline.Pending.CreateNonce + ".json", nil
}

func (b *baselineWorkflow) prepareReceipt(snapshot *installstate.Snapshot) error {
	if b == nil || b.engine == nil || snapshot == nil {
		return ErrInvalid
	}
	if err := b.engine.fixtureFence(snapshot); err != nil {
		return err
	}
	document := snapshot.Document()
	body, err := b.receiptBody(document, "")
	if err != nil {
		return err
	}
	name, err := b.receiptName(document)
	if err != nil {
		return err
	}
	if _, err := b.engine.files.CreateExclusive(name, body); err != nil {
		if errors.Is(err, privatefs.ErrExists) {
			return ErrOwnership
		}
		return ErrOutcomeUnknown
	}
	return nil
}

func (b *baselineWorkflow) pinReceiptUID(document installstate.Document, uid types.UID) error {
	if uid == "" {
		return ErrOwnership
	}
	body, err := b.receiptBody(document, uid)
	if err != nil {
		return err
	}
	name, err := b.receiptName(document)
	if err != nil {
		return err
	}
	old, identity, err := b.engine.files.Read(name, 4096)
	if err != nil {
		return ErrOutcomeUnknown
	}
	if bytes.Equal(old, body) {
		if b.engine.files.ConfirmDurable(name, identity) != nil {
			return ErrOutcomeUnknown
		}
		return nil
	}
	empty, err := b.receiptBody(document, "")
	if err != nil || !bytes.Equal(old, empty) {
		return ErrOwnership
	}
	if _, err := b.engine.files.AtomicWrite(name, body, &identity); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

func (b *baselineWorkflow) loadReceiptUID(document installstate.Document) (types.UID, error) {
	name, err := b.receiptName(document)
	if err != nil {
		return "", err
	}
	body, identity, err := b.engine.files.Read(name, 4096)
	if err != nil || b.engine.files.ConfirmDurable(name, identity) != nil {
		return "", ErrOutcomeUnknown
	}
	var receipt baselineCreateReceipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil {
		return "", ErrOwnership
	}
	want, err := b.receiptBody(document, receipt.OriginalUID)
	if err != nil || !bytes.Equal(body, want) || receipt.OriginalUID == "" {
		return "", ErrOwnership
	}
	return receipt.OriginalUID, nil
}
