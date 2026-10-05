// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/types"
)

// Only public original identity is stored, in protected/fsynced local files.
// No credentials, raw objects or private path appear in the namespace journal.
type createReceipt struct {
	Version       string               `json:"version"`
	Anchor        installstate.Anchor  `json:"anchor"`
	Pending       installstate.Pending `json:"pending"`
	TargetPackage string               `json:"targetPackage"`
	OriginalUID   types.UID            `json:"originalUid"`
}

var receiptUID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

func receiptBody(d installstate.Document, uid types.UID) ([]byte, error) {
	if d.Pending == nil || d.Pending.Action != installstate.Create || uid != "" && !receiptUID.MatchString(string(uid)) {
		return nil, ErrOwnership
	}
	r := createReceipt{Version: "v1", Anchor: installstate.Anchor{Namespace: d.Namespace, UID: d.NamespaceUID, InstallationID: d.InstallationID}, Pending: *d.Pending, TargetPackage: d.TargetPackage, OriginalUID: uid}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, ErrOwnership
	}
	body, err = canonicaljson.CanonicalJSON(body)
	if err != nil {
		return nil, ErrOwnership
	}
	return body, nil
}

func (e *Engine) saveCreateUID(d installstate.Document, uid types.UID) error {
	if uid == "" {
		return ErrOwnership
	}
	body, err := receiptBody(d, uid)
	if err != nil {
		return err
	}
	name := "create-" + d.Pending.CreateNonce + ".json"
	old, identity, readErr := e.files.Read(name, 4096)
	if readErr != nil {
		return ErrOutcomeUnknown
	}
	if bytes.Equal(old, body) {
		return nil
	}
	empty, err := receiptBody(d, "")
	if err != nil || !bytes.Equal(old, empty) {
		return ErrOwnership
	}
	if _, err := e.files.AtomicWrite(name, body, &identity); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

// Preparing an empty receipt proves protected durable storage is available
// BEFORE the real Create. Empty identity is not resumable ownership evidence.
func (e *Engine) prepareCreateReceipt(d installstate.Document) error {
	body, err := receiptBody(d, "")
	if err != nil {
		return err
	}
	if _, err := e.files.CreateExclusive("create-"+d.Pending.CreateNonce+".json", body); err != nil {
		if errors.Is(err, privatefs.ErrExists) {
			return ErrOwnership
		}
		return ErrOutcomeUnknown
	}
	return nil
}

func (e *Engine) loadCreateUID(d installstate.Document) (types.UID, error) {
	if d.Pending == nil || d.Pending.Action != installstate.Create {
		return "", ErrInvalid
	}
	body, _, err := e.files.Read("create-"+d.Pending.CreateNonce+".json", 4096)
	if err != nil {
		return "", ErrOutcomeUnknown
	}
	var r createReceipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil {
		return "", ErrOwnership
	}
	want, err := receiptBody(d, r.OriginalUID)
	if err != nil || !bytes.Equal(body, want) || r.OriginalUID == "" {
		return "", ErrOwnership
	}
	return r.OriginalUID, nil
}
