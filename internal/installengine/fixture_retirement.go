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
	"time"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/types"
)

type fixtureRetirementState string

const (
	fixtureRetiring fixtureRetirementState = "intent"
	fixtureRetired  fixtureRetirementState = "retired"
)

// This fixed sentinel survives WAL unlink. It proves disposition of ONE run,
// not current coldness, behavior, permissions or installation readiness.
type fixtureRetirementRecord struct {
	Version                string                 `json:"version"`
	State                  fixtureRetirementState `json:"state"`
	Namespace              string                 `json:"namespace"`
	NamespaceUID           types.UID              `json:"namespaceUid"`
	InstallationID         string                 `json:"installationId"`
	RunID                  string                 `json:"runId"`
	LedgerSHA256           string                 `json:"ledgerSha256"`
	OriginalWorldsSHA256   string                 `json:"originalWorldsSha256"`
	JournalSHA256          string                 `json:"journalSha256"`
	JournalResourceVersion string                 `json:"journalResourceVersion"`
}

type fixtureRetirementEvidence struct {
	record          fixtureRetirementRecord
	identity        privatefs.FileIdentity
	archiveIdentity privatefs.FileIdentity
	worldIdentity   privatefs.FileIdentity
	archive         []byte
}

func fixtureRetirementName(anchor installstate.Anchor) string {
	return "admission-retirement-" + anchor.InstallationID + ".json"
}

func fixtureArchiveName(anchor installstate.Anchor, run string) string {
	return "admission-archive-" + anchor.InstallationID + "-" + run + ".json"
}

func fixtureRetirementBody(r fixtureRetirementRecord, anchor installstate.Anchor) ([]byte, error) {
	if !installrender.ValidNamespace(anchor.Namespace) || !receiptUID.MatchString(string(anchor.UID)) || !nonceID.MatchString(anchor.InstallationID) || r.Version != "fixture-retirement-v1" || r.State != fixtureRetiring && r.State != fixtureRetired || r.Namespace != anchor.Namespace || r.NamespaceUID != anchor.UID || r.InstallationID != anchor.InstallationID || !nonceID.MatchString(r.RunID) || !fixtureWorldsDigest.MatchString(r.LedgerSHA256) || !fixtureWorldsDigest.MatchString(r.OriginalWorldsSHA256) || !fixtureWorldsDigest.MatchString(r.JournalSHA256) || !fixtureRV(r.JournalResourceVersion) {
		return nil, ErrFixtures
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, ErrFixtures
	}
	return canonicaljson.CanonicalJSON(body)
}

func decodeFixtureRetirement(body []byte, anchor installstate.Anchor) (fixtureRetirementRecord, error) {
	var r fixtureRetirementRecord
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&r) != nil || !errors.Is(decoder.Decode(&extra), io.EOF) {
		return r, ErrFixtures
	}
	want, err := fixtureRetirementBody(r, anchor)
	if err != nil || !bytes.Equal(body, want) {
		return r, ErrFixtures
	}
	return r, nil
}

// Historical validation deliberately does not ask the CURRENT package to
// decode an old journal. Hashes bind immutable original canonical evidence;
// strict schemas, original anchor and terminal fixed addresses still apply.
// Resume separately requires the complete current trusted-plan WAL decoder.
func (e *Engine) readFixtureRetirement(anchor installstate.Anchor) (*fixtureRetirementEvidence, error) {
	if e == nil || e.files == nil {
		return nil, ErrFixtures
	}
	name := fixtureRetirementName(anchor)
	body, identity, err := e.files.Read(name, fixtureLedgerMaxBytes)
	if errors.Is(err, privatefs.ErrNotFound) {
		return nil, err
	}
	if err != nil || e.files.ConfirmDurable(name, identity) != nil {
		return nil, ErrFixtures
	}
	r, err := decodeFixtureRetirement(body, anchor)
	if err != nil {
		return nil, ErrFixtures
	}
	archiveName := fixtureArchiveName(anchor, r.RunID)
	archive, archiveID, err := e.files.Read(archiveName, fixtureLedgerMaxBytes)
	if err != nil || fixtureWorldDigest(archive) != r.LedgerSHA256 || e.files.ConfirmDurable(archiveName, archiveID) != nil {
		return nil, ErrFixtures
	}
	var d fixtureLedgerDocument
	decoder := json.NewDecoder(bytes.NewReader(archive))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || d.Version != "v1" || !validFixtureRecipe(d) || d.Revision == 0 || d.Revision > 9007199254740991 || d.RunID != r.RunID || d.JournalResourceVersion != r.JournalResourceVersion || d.OriginalWorldsSHA256 != r.OriginalWorldsSHA256 || fixtureWorldDigest(d.Journal) != r.JournalSHA256 {
		return nil, ErrFixtures
	}
	canonical, err := canonicaljson.CanonicalJSON(archive)
	if err != nil || !bytes.Equal(canonical, archive) {
		return nil, ErrFixtures
	}
	// Canonical JSON alone still permits explicit null optional receipts. The
	// intrinsic document round trip must retain exactly the historical bytes,
	// without invoking the current package's journal decoder.
	roundTrip, err := json.Marshal(d)
	if err != nil {
		return nil, ErrFixtures
	}
	roundTrip, err = canonicaljson.CanonicalJSON(roundTrip)
	if err != nil || !bytes.Equal(roundTrip, archive) {
		return nil, ErrFixtures
	}
	var journal installstate.Document
	decoder = json.NewDecoder(bytes.NewReader(d.Journal))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&journal) != nil || journal.Namespace != anchor.Namespace || journal.NamespaceUID != anchor.UID || journal.InstallationID != anchor.InstallationID || journal.Pending != nil || journal.AdmissionRetirementRevision != 0 || journal.Stage == installstate.Complete || !validFixtureDestroySeedDocument(d) || !validFixtureRetainedMarkerDocument(d) || !validFixtureWorldsSeal(d) || !validFixtureBehaviorDocument(d) {
		return nil, ErrFixtures
	}
	seen := map[types.UID]bool{}
	neverCreated := false
	for slot, entry := range d.Entries {
		catalog := fixtureCatalogFor(d)[slot]
		key := installstate.Key{APIVersion: catalog.version, Kind: catalog.kind, Namespace: anchor.Namespace, Name: "arcadectl-probe-" + r.RunID + "-" + catalog.suffix}
		if entry.State != fixtureAbsent || entry.Key != key || entry.OriginalUID == "" && entry.DeleteResourceVersion != "" || entry.OriginalUID != "" && (neverCreated || !receiptUID.MatchString(string(entry.OriginalUID)) || !fixtureRV(entry.DeleteResourceVersion) || seen[entry.OriginalUID]) {
			return nil, ErrFixtures
		}
		if entry.OriginalUID == "" {
			neverCreated = true
		}
		seen[entry.OriginalUID] = true
	}
	worldName := "admission-worlds-" + anchor.InstallationID + "-" + r.RunID + ".json"
	world, worldID, err := e.files.ReadEvidence(worldName, privatefs.MaxEvidenceFileBytes)
	if err != nil || fixtureWorldDigest(world) != r.OriginalWorldsSHA256 || e.files.ConfirmEvidenceDurable(worldName, worldID) != nil {
		return nil, ErrFixtures
	}
	var companion fixtureWorldsDocument
	decoder = json.NewDecoder(bytes.NewReader(world))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&companion) != nil || companion.Version != "original-worlds-v1" || companion.RunID != r.RunID || companion.JournalResourceVersion != r.JournalResourceVersion || !bytes.Equal(companion.Journal, d.Journal) || companion.Rows == nil || companion.Phase == nil || companion.Phase.Public == nil || companion.Phase.validate(anchor.Namespace) != nil {
		return nil, ErrFixtures
	}
	canonical, err = fixtureWorldsShapeBody(companion, anchor.Namespace)
	if err != nil || !bytes.Equal(canonical, world) {
		return nil, ErrFixtures
	}
	return &fixtureRetirementEvidence{r, identity, archiveID, worldID, archive}, nil
}

func sameFixtureRetirement(a, b *fixtureRetirementEvidence) bool {
	return a != nil && b != nil && a.record == b.record && a.identity == b.identity && a.archiveIdentity == b.archiveIdentity && a.worldIdentity == b.worldIdentity && bytes.Equal(a.archive, b.archive)
}

// Resume acquires the SAME active-WAL lock. An absent WAL never becomes a new
// intent: only exact immutable terminal archive bytes are reloaded read-only.
func (e *Engine) loadFixtureRetirement(ctx context.Context, s *installstate.Snapshot) (*fixtureLedger, error) {
	if e == nil || e.files == nil || ctx == nil || s == nil {
		return nil, ErrInvalid
	}
	lock, err := e.files.Lock(ctx, fixtureLedgerName(s))
	if err != nil {
		return nil, ErrFixtures
	}
	success := false
	defer func() {
		if !success {
			_ = lock.Close()
		}
	}()
	evidence, err := e.readFixtureRetirement(s.Anchor())
	if err != nil || evidence.record.State != fixtureRetiring {
		return nil, ErrFixtures
	}
	d, err := e.decodeFixtureLedger(evidence.archive)
	if err != nil || !bytes.Equal(d.Journal, s.Bytes()) || d.JournalResourceVersion != s.ResourceVersion() {
		return nil, ErrFixtures
	}
	fresh, err := e.journal.Load(ctx, s.Anchor())
	if err != nil || !bytes.Equal(fresh.Bytes(), s.Bytes()) || fresh.ResourceVersion() != s.ResourceVersion() {
		return nil, ErrFixtures
	}
	name := fixtureLedgerName(s)
	body, identity, err := e.files.Read(name, fixtureLedgerMaxBytes)
	archived := errors.Is(err, privatefs.ErrNotFound)
	if archived {
		name, body, identity = fixtureArchiveName(s.Anchor(), d.RunID), evidence.archive, evidence.archiveIdentity
	} else if err != nil || !bytes.Equal(body, evidence.archive) || e.files.ConfirmDurable(name, identity) != nil {
		return nil, ErrFixtures
	}
	f := &fixtureLedger{engine: e, name: name, lock: lock, identity: identity, body: body, document: d, ackSlot: -1, effectSlot: -1, retirementArchive: archived}
	f.retirementEvidence = evidence
	f.retirementArchiveIdentity = &evidence.archiveIdentity
	f.retirementSentinelIdentity = &evidence.identity
	if _, err := f.loadOriginalWorlds(); err != nil {
		return nil, ErrFixtures
	}
	after, err := e.readFixtureRetirement(s.Anchor())
	if err != nil || !sameFixtureRetirement(evidence, after) {
		return nil, ErrFixtures
	}
	success = true
	return f, nil
}

// Integrated cleanup disposition only. A missing behavioral milestone still
// requires a NEW complete admission run; this cannot certify AdmissionEffective.
func (w *fixtureWire) retireDrained(ctx context.Context) error {
	if w == nil || w.ledger == nil || w.actors == nil || ctx == nil {
		return ErrFixtures
	}
	f := w.ledger
	f.wireMu.Lock()
	defer f.wireMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if f.retirementPublicationUnknown || !w.phaseReadable() || w.current(ctx) != nil {
		return ErrFixtures
	}
	for _, entry := range f.document.Entries {
		if entry.State != fixtureAbsent {
			return ErrFixtures
		}
	}
	s := w.actors.request.Snapshot
	anchor := s.Anchor()
	previous, err := f.engine.readFixtureRetirement(anchor)
	if f.retirementSentinelIdentity != nil && (err != nil || previous.identity != *f.retirementSentinelIdentity) {
		return ErrFixtures
	}
	if f.retirementEvidence != nil && (err != nil || !sameFixtureRetirement(f.retirementEvidence, previous)) {
		return ErrFixtures
	}
	if err != nil && !errors.Is(err, privatefs.ErrNotFound) || err == nil && (previous.record.State == fixtureRetired && previous.record.RunID == f.document.RunID || previous.record.State == fixtureRetiring && previous.record.RunID != f.document.RunID) || f.retirementArchive && (err != nil || previous.record.State != fixtureRetiring) {
		return ErrFixtures
	}
	if previous != nil {
		f.retirementEvidence = previous // preserve acquired pins on late refusal
	}
	if _, err := w.observePhaseLocked(ctx); err != nil {
		return ErrFixtures
	}
	cold, err := NewClusterCold(w.actors.admission.prerequisites)
	request := w.actors.request
	request.Checkpoint = ColdSafety
	if err != nil {
		return ErrFixtures
	}
	tuple, err := cold.captureOriginalWorlds(ctx, request)
	if err != nil {
		return ErrFixtures
	}
	rows, err := tuple.fixtureWorldRows()
	if err != nil || f.matchesOriginalWorlds(rows) != nil {
		return ErrFixtures
	}
	if _, err := w.observePhaseLocked(ctx); err != nil || w.current(ctx) != nil {
		return ErrFixtures
	}
	after, err := f.engine.readFixtureRetirement(anchor)
	if previous == nil && !errors.Is(err, privatefs.ErrNotFound) || previous != nil && (err != nil || !sameFixtureRetirement(previous, after)) {
		return ErrFixtures
	}
	r := fixtureRetirementRecord{"fixture-retirement-v1", fixtureRetiring, anchor.Namespace, anchor.UID, anchor.InstallationID, f.document.RunID, fixtureWorldDigest(f.body), f.document.OriginalWorldsSHA256, fixtureWorldDigest(f.document.Journal), f.document.JournalResourceVersion}
	if previous != nil && previous.record.State == fixtureRetiring && previous.record != r {
		return ErrFixtures
	}
	archiveName := fixtureArchiveName(anchor, r.RunID)
	archive, archiveID, archiveErr := f.engine.files.Read(archiveName, fixtureLedgerMaxBytes)
	if errors.Is(archiveErr, privatefs.ErrNotFound) {
		if f.retirementArchiveIdentity != nil {
			return ErrFixtures // never reconstruct missing pinned immutable evidence
		}
		archiveID, archiveErr = f.engine.files.CreateExclusive(archiveName, f.body)
		if archiveErr != nil {
			f.retirementPublicationUnknown = true
			return ErrFixtures
		}
		archive = bytes.Clone(f.body)
	}
	if archiveErr != nil || !bytes.Equal(archive, f.body) {
		return ErrFixtures
	}
	if f.retirementArchiveIdentity != nil && archiveID != *f.retirementArchiveIdentity || previous != nil && previous.record.RunID == r.RunID && archiveID != previous.archiveIdentity {
		return ErrFixtures
	}
	f.retirementArchiveIdentity = &archiveID
	if f.engine.files.ConfirmDurable(archiveName, archiveID) != nil || w.current(ctx) != nil {
		return ErrFixtures
	}
	name := fixtureRetirementName(anchor)
	intent, err := fixtureRetirementBody(r, anchor)
	if err != nil {
		return ErrFixtures
	}
	var sentinelID privatefs.FileIdentity
	if previous == nil {
		sentinelID, err = f.engine.files.CreateExclusive(name, intent)
	} else if previous.record.State == fixtureRetired {
		sentinelID, err = f.engine.files.AtomicWrite(name, intent, &previous.identity)
	} else {
		sentinelID = previous.identity
	}
	if err != nil {
		f.retirementPublicationUnknown = true
		return ErrFixtures
	}
	f.retirementSentinelIdentity = &sentinelID // save BEFORE any late refusal
	if previous == nil || previous.record.State == fixtureRetired {
		f.retirementEvidence = nil // successful known transition, new pin above
	}
	if f.engine.files.ConfirmDurable(name, sentinelID) != nil {
		return ErrFixtures
	}
	intentEvidence, err := f.engine.readFixtureRetirement(anchor)
	if err != nil || intentEvidence.record != r || intentEvidence.identity != sentinelID || intentEvidence.archiveIdentity != archiveID || f.worldIdentity == nil || intentEvidence.worldIdentity != *f.worldIdentity {
		return ErrFixtures
	}
	f.retirementEvidence = intentEvidence
	if !f.retirementArchive {
		if f.name != fixtureLedgerName(s) || w.current(ctx) != nil {
			return ErrFixtures
		}
		pinned, err := f.engine.readFixtureRetirement(anchor)
		if err != nil || !sameFixtureRetirement(f.retirementEvidence, pinned) || f.engine.files.Remove(f.name, f.identity) != nil {
			return ErrFixtures // uncertain unlink remains fenced by Intent
		}
	}
	if _, _, err := f.engine.files.Read(fixtureLedgerName(s), fixtureLedgerMaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
		return ErrFixtures
	}
	pinned, err := f.engine.readFixtureRetirement(anchor)
	if err != nil || !sameFixtureRetirement(f.retirementEvidence, pinned) {
		return ErrFixtures
	}
	r.State = fixtureRetired
	body, err := fixtureRetirementBody(r, anchor)
	if err != nil {
		return ErrFixtures
	}
	// AtomicWrite fsyncs this SAME protected directory, making a prior unlink
	// durable even when recovery began with WAL already absent.
	id, err := f.engine.files.AtomicWrite(name, body, &sentinelID)
	if err != nil {
		f.retirementPublicationUnknown = true
		return ErrFixtures
	}
	f.retirementSentinelIdentity = &id
	if f.engine.files.ConfirmDurable(name, id) != nil {
		return ErrFixtures
	}
	final, err := f.engine.readFixtureRetirement(anchor)
	if err != nil || final.record != r || final.identity != id || final.archiveIdentity != archiveID || f.worldIdentity == nil || final.worldIdentity != *f.worldIdentity || !reflect.DeepEqual(final.archive, f.body) || f.engine.fixtureFence(s) != nil {
		return ErrFixtures
	}
	// Retire the in-memory effect path too. Future proof reads can only use the
	// archive; no ACK/CREATE/DELETE/status capability is restored.
	f.name, f.identity, f.retirementArchive = archiveName, archiveID, true
	f.retirementEvidence = final
	return nil
}
