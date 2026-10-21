// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strconv"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

const baselineEnrollmentSourceVersion = "arcadectl.install-baseline-enrollment-source/v1"

// Same domain as the original installstate bootstrap receipt, not a Kubernetes
// object name. Existing uppercase/underscore receipt names remain usable.
var baselineEnrollmentBootstrapName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,111}$`)

type baselineEnrollmentBootstrap struct {
	ReceiptName   string `json:"receiptName"`
	PackageSHA256 string `json:"packageSha256"`
	SHA256        string `json:"sha256"`
}

// Only public identities and whole-object hashes are persisted. No raw world
// settings, PV sources, CA path, client credential or Secret contents belong in
// this immutable source envelope. Its full seal is separate from journal SHA.
type baselineEnrollmentSourceReceipt struct {
	Version                string                      `json:"version"`
	Journal                json.RawMessage             `json:"journal"`
	JournalResourceVersion string                      `json:"journalResourceVersion"`
	BaselineSHA256         string                      `json:"baselineSha256"`
	Bootstrap              baselineEnrollmentBootstrap `json:"bootstrap"`
	CASHA256               string                      `json:"caSha256"`
	Worlds                 []fixtureWorldRow           `json:"worlds"`
}

// Acquire these original inputs BEFORE the closed historical safety proof.
// This local owner supplies no coldness, runtime or baseline-effect authority.
type baselineEnrollmentInputs struct {
	self         *baselineEnrollmentInputs
	engine       *Engine
	anchor       installstate.Anchor
	bootstrap    baselineEnrollmentBootstrap
	caSHA256     string
	bootstrapPin *privatefs.FilePin
	caPin        *privatefs.FilePin
	bootstrapID  privatefs.FileIdentity
	caID         privatefs.FileIdentity
}

func (w *baselineEnrollmentInputs) release() {
	if w != nil && w.self == w {
		_ = w.bootstrapPin.Close()
		_ = w.caPin.Close()
	}
}

func (w *baselineEnrollmentInputs) confirm(ctx context.Context, e *Engine, anchor installstate.Anchor) error {
	if w == nil || w.self != w || ctx == nil || ctx.Err() != nil || e == nil || w.engine != e || w.anchor != anchor || w.bootstrapPin == nil || w.caPin == nil ||
		w.bootstrapPin.Confirm() != nil || w.caPin.Confirm() != nil || ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

type baselineEnrollmentSourceWitness struct {
	self       *baselineEnrollmentSourceWitness
	engine     *Engine
	name       string
	body       []byte
	identity   privatefs.FileIdentity
	source     installstate.Document
	receipt    baselineEnrollmentSourceReceipt
	provenance installstate.BaselineEnrollmentProvenance
	inputs     *baselineEnrollmentInputs
	pin        *privatefs.FilePin
}

func (w *baselineEnrollmentSourceWitness) release() {
	if w != nil && w.self == w {
		_ = w.pin.Close()
		w.inputs.release()
	}
}

func baselineEnrollmentSourceName(id string, revision uint64) (string, error) {
	if !nonceID.MatchString(id) || revision == 0 || revision > 9007199254740991 {
		return "", ErrSecurityBaseline
	}
	return "baseline-enrollment-source-" + id + "-" + strconv.FormatUint(revision, 10) + ".json", nil
}

func (e *Engine) historicalEnrollmentSource(d installstate.Document) bool {
	if e == nil || e.baseline == nil || !e.baselinePlan().IsTrusted() || !e.baselineObservable(d) || d.SecurityBaseline != nil || d.Stage != installstate.Complete ||
		!d.Installed || d.Pending != nil || d.AdmissionReinstall != nil || d.AdmissionRetirementRevision != 0 || d.ActivePackage != d.TargetPackage {
		return false
	}
	// Complete signed runtime inventory is a necessary source condition, never
	// a substitute for live original/Secret/producer-family/cold-world proofs.
	for _, row := range e.plans[d.TargetPackage].ResourceMetadata() {
		key := installstate.Key{APIVersion: row.APIVersion, Kind: row.Kind, Namespace: row.Namespace, Name: row.Name}
		entry, template := e.inventory(d, key)
		wanted, err := e.contracts[d.TargetPackage].Template(key, false)
		if entry == nil || template == nil || err != nil || entry.TemplateSHA256 != wanted.Hash() || entry.Retained != row.Retained || entry.Phase != row.Phase {
			return false
		}
	}
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		entry, _ := e.inventory(d, secretKey(d.Namespace, name))
		if entry == nil || !entry.Retained || entry.UID == "" {
			return false
		}
	}
	return true
}

func (e *Engine) openBaselineEnrollmentInputs(ctx context.Context, current *installstate.Snapshot, original *installrender.Plan, receiptName, caFile string) (*baselineEnrollmentInputs, error) {
	if e == nil || e.files == nil || e.baseline == nil || ctx == nil || ctx.Err() != nil || current == nil || !original.IsTrusted() {
		return nil, ErrSecurityBaseline
	}
	d := current.Document()
	if !e.baselineObservable(d) || d.Stage != installstate.Complete || d.AdmissionReinstall != nil || d.AdmissionRetirementRevision != 0 || original.Namespace() != d.Namespace || original.Profile().ID != d.ProfileID {
		return nil, ErrSecurityBaseline
	}
	w := &baselineEnrollmentInputs{engine: e, anchor: current.Anchor()}
	w.self = w
	transferred := false
	defer func() {
		if !transferred {
			w.release()
		}
	}()
	bootstrapBody, bootstrapID, bootstrapPin, err := e.files.Pin(receiptName, installstate.MaxBytes)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	w.bootstrapID, w.bootstrapPin = bootstrapID, bootstrapPin
	// Historical decoding rejects an already-baseline-pinned bootstrap. Never
	// rewrite it or call EnsureNamespace while enrolling an installed runtime.
	bootstrap, err := installstate.LoadBootstrap(e.files, receiptName, original)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	anchor, err := bootstrap.PinnedAnchor(ctx)
	if err != nil || anchor != current.Anchor() || bootstrapPin.Confirm() != nil {
		return nil, ErrSecurityBaseline
	}
	w.bootstrap = baselineEnrollmentBootstrap{receiptName, original.Digest(), fixtureWorldDigest(bootstrapBody)}
	caBody, caID, caPin, err := privatefs.PinAbsolute(caFile, 65536, privatefs.TrustedPublic)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	w.caID, w.caPin, w.caSHA256 = caID, caPin, fixtureWorldDigest(caBody)
	if w.confirm(ctx, e, current.Anchor()) != nil {
		return nil, ErrSecurityBaseline
	}
	transferred = true
	return w, nil
}

func (e *Engine) baselineEnrollmentSourceBody(receipt baselineEnrollmentSourceReceipt) ([]byte, installstate.Document, error) {
	if e == nil || e.baseline == nil || receipt.Version != baselineEnrollmentSourceVersion || !fixtureRV(receipt.JournalResourceVersion) ||
		receipt.BaselineSHA256 != e.baselinePlan().Digest() || !baselineEnrollmentBootstrapName.MatchString(receipt.Bootstrap.ReceiptName) ||
		!fixtureWorldsDigest.MatchString(receipt.Bootstrap.PackageSHA256) || !fixtureWorldsDigest.MatchString(receipt.Bootstrap.SHA256) || !fixtureWorldsDigest.MatchString(receipt.CASHA256) {
		return nil, installstate.Document{}, ErrSecurityBaseline
	}
	plans := make([]*installrender.Plan, 0, len(e.plans))
	for _, plan := range e.plans {
		plans = append(plans, plan)
	}
	source, err := installstate.Decode(receipt.Journal, plans...)
	if err != nil || !e.historicalEnrollmentSource(source) {
		return nil, installstate.Document{}, ErrSecurityBaseline
	}
	// Share the existing bounded immutable-row validator without manufacturing
	// a fixture journal, ledger, phase baseline or replay capability.
	if _, err := fixtureWorldsShapeBody(fixtureWorldsDocument{Rows: receipt.Worlds}, source.Namespace); err != nil {
		return nil, installstate.Document{}, ErrSecurityBaseline
	}
	body, err := json.Marshal(receipt)
	if err == nil {
		body, err = canonicaljson.CanonicalEvidenceJSON(body)
	}
	if err != nil || int64(len(body)) > privatefs.MaxEvidenceFileBytes {
		return nil, installstate.Document{}, ErrSecurityBaseline
	}
	return body, source, nil
}

func (e *Engine) decodeBaselineEnrollmentSource(body []byte) (baselineEnrollmentSourceReceipt, installstate.Document, error) {
	var receipt baselineEnrollmentSourceReceipt
	if len(body) == 0 || int64(len(body)) > privatefs.MaxEvidenceFileBytes {
		return receipt, installstate.Document{}, ErrSecurityBaseline
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil {
		return baselineEnrollmentSourceReceipt{}, installstate.Document{}, ErrSecurityBaseline
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return baselineEnrollmentSourceReceipt{}, installstate.Document{}, ErrSecurityBaseline
	}
	want, source, err := e.baselineEnrollmentSourceBody(receipt)
	if err != nil || !bytes.Equal(body, want) {
		return baselineEnrollmentSourceReceipt{}, installstate.Document{}, ErrSecurityBaseline
	}
	return receipt, source, nil
}

// Caller must surround this local exclusive-publication primitive with its
// full original source/Secret/family/cold proof. Existence never authorizes a
// CREATE, a journal CAS or recapture of a lost initial world inventory.
func (e *Engine) saveBaselineEnrollmentSource(ctx context.Context, source *installstate.Snapshot, inputs *baselineEnrollmentInputs, worlds *coldWorldTuple) (*baselineEnrollmentSourceWitness, error) {
	if source == nil || !e.historicalEnrollmentSource(source.Document()) || inputs.confirm(ctx, e, source.Anchor()) != nil {
		return nil, ErrSecurityBaseline
	}
	rows, err := worlds.fixtureWorldRows()
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	receipt := baselineEnrollmentSourceReceipt{baselineEnrollmentSourceVersion, source.Bytes(), source.ResourceVersion(), e.baselinePlan().Digest(), inputs.bootstrap, inputs.caSHA256, rows}
	body, document, err := e.baselineEnrollmentSourceBody(receipt)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	name, err := baselineEnrollmentSourceName(document.InstallationID, document.Revision)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	if _, err := e.files.CreateEvidenceExclusive(name, body); err != nil && !errors.Is(err, privatefs.ErrExists) {
		return nil, ErrOutcomeUnknown
	}
	got, identity, pin, err := e.files.PinEvidence(name, privatefs.MaxEvidenceFileBytes)
	if err != nil {
		return nil, ErrOutcomeUnknown
	}
	// An unchanged source journal may have a new Namespace RV after a benign
	// metadata update between invocations. Preserve the FIRST envelope's audit
	// RV, while requiring every journal/world/input/baseline byte to match.
	// The enclosing same-invocation original Snapshot fences stay strict.
	stored, _, decodeErr := e.decodeBaselineEnrollmentSource(got)
	if decodeErr == nil {
		receipt.JournalResourceVersion = stored.JournalResourceVersion
		body, document, decodeErr = e.baselineEnrollmentSourceBody(receipt)
	}
	w := &baselineEnrollmentSourceWitness{engine: e, name: name, body: got, identity: identity, source: document, receipt: receipt, inputs: inputs, pin: pin,
		provenance: installstate.BaselineEnrollmentProvenance{SourceRevision: document.Revision, SourceJournalSHA256: fixtureWorldDigest(source.Bytes()), SourceEvidenceSHA256: fixtureWorldDigest(body)}}
	w.self = w
	if decodeErr != nil || !bytes.Equal(got, body) || e.confirmBaselineEnrollmentSource(ctx, w, source) != nil {
		w.release()
		return nil, ErrOutcomeUnknown
	}
	return w, nil
}

// Resume reads only the envelope already sealed by public provenance. Source
// equality applies to this distinct enrollment epoch, not to later legitimate
// upgrades, server creation or retaining uninstall after enrollment completes.
func (e *Engine) openBaselineEnrollmentSource(ctx context.Context, current *installstate.Snapshot, original *installrender.Plan, receiptName, caFile string) (*baselineEnrollmentSourceWitness, error) {
	if e == nil || e.files == nil || current == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	d := current.Document()
	if d.SecurityBaseline == nil || d.SecurityBaseline.Enrollment == nil {
		return nil, ErrSecurityBaseline
	}
	provenance := *d.SecurityBaseline.Enrollment
	name, err := baselineEnrollmentSourceName(d.InstallationID, provenance.SourceRevision)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	body, identity, pin, err := e.files.PinEvidence(name, privatefs.MaxEvidenceFileBytes)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	w := &baselineEnrollmentSourceWitness{engine: e, name: name, body: body, identity: identity, provenance: provenance, pin: pin}
	w.self = w
	transferred := false
	defer func() {
		if !transferred {
			w.release()
		}
	}()
	if fixtureWorldDigest(body) != provenance.SourceEvidenceSHA256 {
		return nil, ErrSecurityBaseline
	}
	w.receipt, w.source, err = e.decodeBaselineEnrollmentSource(body)
	if err != nil || w.receipt.Bootstrap.ReceiptName != receiptName || w.receipt.Bootstrap.PackageSHA256 != original.Digest() {
		return nil, ErrSecurityBaseline
	}
	w.inputs, err = e.openBaselineEnrollmentInputs(ctx, current, original, receiptName, caFile)
	if err != nil || w.inputs.bootstrap != w.receipt.Bootstrap || w.inputs.caSHA256 != w.receipt.CASHA256 || e.confirmBaselineEnrollmentSource(ctx, w, current) != nil {
		return nil, ErrSecurityBaseline
	}
	transferred = true
	return w, nil
}

// Pure local close belongs AFTER the last remote original/safety read. The
// three original descriptors survive all those reads and are never recaptured.
func (e *Engine) confirmBaselineEnrollmentSource(ctx context.Context, w *baselineEnrollmentSourceWitness, current *installstate.Snapshot) error {
	if e == nil || w == nil || w.self != w || w.engine != e || current == nil || w.pin == nil || w.inputs.confirm(ctx, e, current.Anchor()) != nil ||
		w.confirmEnvelope() != nil {
		return ErrSecurityBaseline
	}
	d := current.Document()
	if d.SecurityBaseline == nil {
		if !bytes.Equal(current.Bytes(), w.receipt.Journal) {
			return ErrSecurityBaseline
		}
	} else {
		if d.SecurityBaseline.ArtifactDigest != w.receipt.BaselineSHA256 || d.SecurityBaseline.Enrollment == nil || *d.SecurityBaseline.Enrollment != w.provenance || d.Revision <= w.source.Revision {
			return ErrSecurityBaseline
		}
		d.SecurityBaseline, d.Revision = nil, w.source.Revision
	}
	if !reflect.DeepEqual(d, w.source) || ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

// The parsed fields are conveniences, not an independent floor. Bind them
// back to the exact canonical bytes and public seal at each local close so an
// in-memory mutation cannot recapture a different world tuple or source.
func (w *baselineEnrollmentSourceWitness) confirmEnvelope() error {
	if w == nil || w.self != w || w.engine == nil || w.pin == nil || w.pin.Confirm() != nil || fixtureWorldDigest(w.body) != w.provenance.SourceEvidenceSHA256 ||
		fixtureWorldDigest(w.receipt.Journal) != w.provenance.SourceJournalSHA256 || w.source.Revision != w.provenance.SourceRevision {
		return ErrSecurityBaseline
	}
	body, source, err := w.engine.baselineEnrollmentSourceBody(w.receipt)
	if err != nil || !bytes.Equal(body, w.body) || !reflect.DeepEqual(source, w.source) {
		return ErrSecurityBaseline
	}
	name, err := baselineEnrollmentSourceName(source.InstallationID, source.Revision)
	if err != nil || name != w.name {
		return ErrSecurityBaseline
	}
	stored, identity, err := w.engine.files.ReadEvidence(w.name, privatefs.MaxEvidenceFileBytes)
	if err != nil || identity != w.identity || !bytes.Equal(stored, w.body) || w.pin.Confirm() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

func (w *baselineEnrollmentSourceWitness) matchesWorlds(tuple *coldWorldTuple) error {
	if w.confirmEnvelope() != nil {
		return ErrSecurityBaseline
	}
	rows, err := tuple.fixtureWorldRows()
	if err != nil || !reflect.DeepEqual(rows, w.receipt.Worlds) {
		return ErrSecurityBaseline
	}
	return nil
}
