// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

const (
	reinstallReceiptVersion  = "arcadectl.install-retained-reinstall-source/v1"
	reinstallReceiptMaxBytes = installstate.MaxBytes + 256
)

type reinstallSourceReceipt struct {
	Version string          `json:"version"`
	Journal json.RawMessage `json:"journal"`
}

// Original protected source and retirement evidence, not a historical
// Snapshot, mutation capability or permanent assertion of world coldness.
type reinstallSourceWitness struct {
	name       string
	body       []byte
	identity   privatefs.FileIdentity
	source     installstate.Document
	provenance installstate.ReinstallProvenance
	retirement *retirementEvidence
	pin        *privatefs.FilePin
}

func (w *reinstallSourceWitness) release() {
	if w != nil {
		_ = w.pin.Close()
		w.retirement.release()
	}
}

func reinstallSourceName(id string, revision uint64) (string, error) {
	if !nonceID.MatchString(id) || revision == 0 || revision > 9007199254740991 {
		return "", ErrSecurityBaseline
	}
	return "retained-reinstall-source-" + id + "-" + strconv.FormatUint(revision, 10) + ".json", nil
}

func reinstallJournalSHA256(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func reinstallSourceBody(journal []byte) ([]byte, error) {
	if len(journal) == 0 || len(journal) > installstate.MaxBytes {
		return nil, ErrSecurityBaseline
	}
	body, err := json.Marshal(reinstallSourceReceipt{reinstallReceiptVersion, journal})
	if err == nil {
		body, err = canonicaljson.CanonicalJSON(body)
	}
	if err != nil || len(body) > reinstallReceiptMaxBytes {
		return nil, ErrSecurityBaseline
	}
	return body, nil
}

// Persist only the exact completed source. Full retirement/cold/secret proofs
// must surround this private filesystem primitive in lifecycle composition;
// existence or successful readback alone never authorizes access recreation.
func (e *Engine) saveReinstallSource(source *installstate.Snapshot) (*reinstallSourceWitness, error) {
	if e == nil || e.files == nil || source == nil || !e.baselineRetiredObservable(source.Document()) {
		return nil, ErrSecurityBaseline
	}
	d := source.Document()
	retirement, err := e.openRetirementEvidence(d)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	transferred := false
	defer func() {
		if !transferred {
			retirement.release()
		}
	}()
	for _, resource := range d.Resources {
		entry, _ := e.inventory(retirement.original, resource.Key)
		if entry == nil || *entry != resource {
			return nil, ErrSecurityBaseline
		}
	}
	name, err := reinstallSourceName(d.InstallationID, d.Revision)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	want, err := reinstallSourceBody(source.Bytes())
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	if _, err := e.files.CreateExclusive(name, want); err != nil && !errors.Is(err, privatefs.ErrExists) {
		return nil, ErrOutcomeUnknown
	}
	// A crash after exclusive publication is recoverable only by exact original
	// bytes and durable readback. No receipt overwrite or first-GET adoption.
	body, identity, pin, err := e.files.Pin(name, reinstallReceiptMaxBytes)
	if err != nil {
		return nil, ErrOutcomeUnknown
	}
	defer func() {
		if !transferred {
			_ = pin.Close()
		}
	}()
	if !bytes.Equal(body, want) || pin.Confirm() != nil {
		return nil, ErrOutcomeUnknown
	}
	if e.closeRetirementEvidence(retirement) != nil {
		return nil, ErrSecurityBaseline
	}
	transferred = true
	return &reinstallSourceWitness{name, body, identity, d,
		installstate.ReinstallProvenance{SourceRevision: d.Revision, SourceJournalSHA256: reinstallJournalSHA256(source.Bytes())}, retirement, pin}, nil
}

// Load the source from the current genuine Install journal's pin. It cannot
// authorize a stale Uninstall snapshot after Begin, nor reinterpret the old
// retirement revision as an Install exemption. Every original retained root
// and the separate baseline remain exact across the source/current documents.
func (e *Engine) openReinstallSource(current *installstate.Snapshot) (*reinstallSourceWitness, error) {
	if e == nil || e.files == nil || current == nil || e.baseline == nil || !e.baselinePlan().IsTrusted() {
		return nil, ErrSecurityBaseline
	}
	d := current.Document()
	pin := d.AdmissionReinstall
	if pin == nil || d.Mode != installstate.Install || d.ActivePackage == "" || d.ActivePackage != d.TargetPackage || d.AdmissionRetirementRevision != 0 ||
		pin.SourceRevision == 0 || pin.SourceRevision >= d.Revision {
		return nil, ErrSecurityBaseline
	}
	name, err := reinstallSourceName(d.InstallationID, pin.SourceRevision)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	body, identity, descriptor, err := e.files.Pin(name, reinstallReceiptMaxBytes)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	transferred := false
	defer func() {
		if !transferred {
			_ = descriptor.Close()
		}
	}()
	if descriptor.Confirm() != nil {
		return nil, ErrSecurityBaseline
	}
	canonical, err := canonicaljson.CanonicalJSON(body)
	var receipt reinstallSourceReceipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err != nil || !bytes.Equal(canonical, body) || decoder.Decode(&receipt) != nil || receipt.Version != reinstallReceiptVersion || reinstallJournalSHA256(receipt.Journal) != pin.SourceJournalSHA256 {
		return nil, ErrSecurityBaseline
	}
	plans := make([]*installrender.Plan, 0, len(e.plans))
	for _, plan := range e.plans {
		plans = append(plans, plan)
	}
	source, err := installstate.DecodeWithBaseline(receipt.Journal, e.baselinePlan(), plans...)
	if err != nil || !e.baselineRetiredObservable(source) || source.Revision != pin.SourceRevision || source.Namespace != d.Namespace || source.NamespaceUID != d.NamespaceUID ||
		source.InstallationID != d.InstallationID || source.ProfileID != d.ProfileID || source.ActivePackage != d.ActivePackage || source.TargetPackage != d.TargetPackage ||
		source.PreviousPackage != d.PreviousPackage || !reflect.DeepEqual(source.SecurityBaseline, d.SecurityBaseline) {
		return nil, ErrSecurityBaseline
	}
	for _, resource := range source.Resources {
		entry, _ := e.inventory(d, resource.Key)
		if entry == nil || *entry != resource {
			return nil, ErrSecurityBaseline
		}
	}
	retirement, err := e.openRetirementEvidence(source)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	defer func() {
		if !transferred {
			retirement.release()
		}
	}()
	// Authenticate the completed source's retained inventory against the old
	// pre-withdrawal journal without applying its old live-absence obligations
	// to newly ACK-bound access objects in the current Install.
	for _, resource := range source.Resources {
		entry, _ := e.inventory(retirement.original, resource.Key)
		if entry == nil || *entry != resource {
			return nil, ErrSecurityBaseline
		}
	}
	transferred = true
	return &reinstallSourceWitness{name, body, identity, source, *pin, retirement, descriptor}, nil
}

// Close locally after all current-journal/live observations. Both protected
// files must retain opening bytes, inode identity and confirmed durability.
func (e *Engine) closeReinstallSource(witness *reinstallSourceWitness) error {
	if e == nil || e.files == nil || witness == nil || witness.pin == nil || e.closeRetirementEvidence(witness.retirement) != nil {
		return ErrSecurityBaseline
	}
	body, identity, err := e.files.Read(witness.name, reinstallReceiptMaxBytes)
	if err != nil || identity != witness.identity || !bytes.Equal(body, witness.body) || witness.pin.Confirm() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

// The real whole retired verifier, not a caller check, brackets publication.
// Lifecycle.Begin must additionally prove retained Secret validity and bind
// this source in its single original Namespace CAS. This helper remains
// uncomposed until that full retained-reinstall lifecycle is implemented.
func (c *ClusterSecurityBaseline) prepareReinstallSource(ctx context.Context, source *installstate.Snapshot) (*reinstallSourceWitness, error) {
	if c == nil || c.engine == nil || ctx == nil || ctx.Err() != nil || source == nil || !c.engine.baselineRetiredObservable(source.Document()) {
		return nil, ErrSecurityBaseline
	}
	ctx, cancel := context.WithTimeout(ctx, baselineRuntimeTimeout)
	defer cancel()
	opening, err := c.engine.openRetirementEvidence(source.Document())
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	defer opening.release()
	if c.Verify(ctx, source) != nil {
		return nil, ErrSecurityBaseline
	}
	witness, err := c.engine.saveReinstallSource(source)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			witness.release()
		}
	}()
	if c.Verify(ctx, source) != nil {
		return nil, ErrSecurityBaseline
	}
	if _, err := (&Lifecycle{engine: c.engine}).original(ctx, source); err != nil || ctx.Err() != nil || c.engine.closeRetirementEvidence(opening) != nil || c.engine.closeReinstallSource(witness) != nil {
		return nil, ErrSecurityBaseline
	}
	transferred = true
	return witness, nil
}
