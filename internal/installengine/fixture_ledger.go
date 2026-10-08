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
	"strconv"
	"sync"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/types"
)

var ErrFixtures = errors.New("installation admission fixtures remain unresolved; original ownership must be observed before resume")

const fixtureLedgerMaxBytes = installstate.MaxBytes + 16384

const (
	fixtureRecipeV1 = "inert-admission-v1"
	fixtureRecipeV2 = "inert-admission-v2"
	fixtureMaxSlots = 11
)

type fixtureRecipe struct {
	version, kind, suffix string
	owner                 int
}

// Closed recipe slots, never arbitrary Kubernetes addresses or objects. Jobs
// precede their worker Pods so a future constructor can use the acknowledged
// original owner UID, never a fabricated UID or a lookup by owner name.
var fixtureCatalog = [...]fixtureRecipe{
	{"batch/v1", "Job", "backup-job", -1},
	{"v1", "Pod", "backup-pod", 0},
	{"batch/v1", "Job", "restore-job", -1},
	{"v1", "Pod", "restore-pod", 2},
	{"batch/v1", "Job", "destroy-job", -1},
	{"v1", "Pod", "destroy-pod", 4},
	{"v1", "Pod", "plain-pod", -1},
	{"v1", "PersistentVolumeClaim", "retained-pvc", -1},
	{"v1", "PersistentVolumeClaim", "plain-pvc", -1},
	{"arcade.gobha.me/v1alpha1", "GameDestroy", "cancelled-destroy", -1},
}

// Recipe semantics are immutable within a run. v2 appends an independent
// born-cancelled VerifiedBackup original for the named UPDATE branch; it never
// changes, upgrades or adopts any v1 original. The default producer stays v1
// until construction, whole validators and both native profiles are proved.
var fixtureCatalogV2 = [...]fixtureRecipe{
	fixtureCatalog[0], fixtureCatalog[1], fixtureCatalog[2], fixtureCatalog[3],
	fixtureCatalog[4], fixtureCatalog[5], fixtureCatalog[6], fixtureCatalog[7],
	fixtureCatalog[8], fixtureCatalog[9],
	{"arcade.gobha.me/v1alpha1", "GameDestroy", "verified-cancelled-destroy", -1},
}

// Only the sealed recipe selects a catalog, never a caller-supplied object,
// count or cluster observation. Unknown and count-mismatched documents have
// no addressable slots. In particular, an empty document is not a recipe.
func fixtureCatalogFor(d fixtureLedgerDocument) []fixtureRecipe {
	var catalog []fixtureRecipe
	switch d.Recipe {
	case fixtureRecipeV1:
		catalog = fixtureCatalog[:]
	case fixtureRecipeV2:
		catalog = fixtureCatalogV2[:]
	default:
		return nil
	}
	if len(d.Entries) != len(catalog) {
		return nil
	}
	return catalog
}

func validFixtureRecipe(d fixtureLedgerDocument) bool {
	return len(fixtureCatalogFor(d)) != 0
}

type fixtureState string

const (
	fixturePlanned         fixtureState = "planned"
	fixtureCreateAttempted fixtureState = "create-attempted"
	fixtureOriginal        fixtureState = "original"
	fixtureDeleteAttempted fixtureState = "delete-attempted"
	fixtureAbsent          fixtureState = "absent"
)

type fixtureEntry struct {
	Key                   installstate.Key `json:"key"`
	State                 fixtureState     `json:"state"`
	OriginalUID           types.UID        `json:"originalUid"`
	DeleteResourceVersion string           `json:"deleteResourceVersion"`
}

// Public identities in protected/fsynced local storage. The original sealed
// journal binds namespace UID, installation ID, package, profile and revision;
// the namespace RV also detects change-and-restore. No raw objects, credentials,
// URLs, private paths or caller-selected recipes belong in this document.
// This WAL does NOT certify object shapes, authorize effects or implement the
// fixture provider. Its private transitions are consumed only by that future
// closed provider after independent original-identity/shape/absence proofs.
type fixtureLedgerDocument struct {
	Version                string                        `json:"version"`
	Recipe                 string                        `json:"recipe"`
	Revision               uint64                        `json:"revision"`
	RunID                  string                        `json:"runId"`
	Journal                json.RawMessage               `json:"journal"`
	JournalResourceVersion string                        `json:"journalResourceVersion"`
	Entries                []fixtureEntry                `json:"entries"`
	DestroySeed            *fixtureDestroySeedReceipt    `json:"destroySeed,omitempty"`
	RetainedMarker         *fixtureRetainedMarkerReceipt `json:"retainedMarker,omitempty"`
	OriginalWorldsSHA256   string                        `json:"originalWorldsSHA256,omitempty"`
	Behavior               *fixtureBehaviorReceipt       `json:"behavior,omitempty"`
}

func fixtureLedgerName(s *installstate.Snapshot) string {
	return "admission-fixtures-" + s.Anchor().InstallationID + ".json"
}

// Any active WAL, including malformed, terminal-but-not-retired or unreadable
// evidence, fences ordinary effects/transitions AND pending recovery. Do not
// exempt its objects from cold/runtime checks. The future closed provider must
// drain originals, prove absence, archive evidence and retire this exact file.
func (e *Engine) fixtureFence(s *installstate.Snapshot) error {
	if e == nil || e.files == nil || s == nil {
		return ErrInvalid
	}
	_, _, err := e.files.Read(fixtureLedgerName(s), fixtureLedgerMaxBytes)
	if errors.Is(err, privatefs.ErrNotFound) {
		evidence, err := e.readFixtureRetirement(s.Anchor())
		if errors.Is(err, privatefs.ErrNotFound) {
			return nil
		}
		if err == nil && evidence.record.State == fixtureRetired {
			return nil // historical cleanup only; never AdmissionEffective
		}
	}
	return ErrFixtures
}

func fixtureRV(rv string) bool {
	n, err := strconv.ParseUint(rv, 10, 64)
	return err == nil && n != 0 && strconv.FormatUint(n, 10) == rv
}

func (e *Engine) validateFixtureLedger(d fixtureLedgerDocument) error {
	if e == nil || d.Version != "v1" || !validFixtureRecipe(d) || d.Revision == 0 || d.Revision > 9007199254740991 || !nonceID.MatchString(d.RunID) || !fixtureRV(d.JournalResourceVersion) {
		return ErrFixtures
	}
	plans := make([]*installrender.Plan, 0, len(e.plans))
	for _, p := range e.plans {
		plans = append(plans, p)
	}
	journal, err := installstate.Decode(d.Journal, plans...)
	if err != nil || journal.Pending != nil || journal.AdmissionRetirementRevision != 0 || journal.Stage == installstate.Complete {
		return ErrFixtures
	}
	uids := map[types.UID]bool{}
	pending, deleting, createPending, neverCreated := 0, false, false, false
	for i, entry := range d.Entries {
		recipe := fixtureCatalogFor(d)[i]
		key := installstate.Key{APIVersion: recipe.version, Kind: recipe.kind, Namespace: journal.Namespace, Name: "arcadectl-probe-" + d.RunID + "-" + recipe.suffix}
		if entry.Key != key {
			return ErrFixtures
		}
		if entry.OriginalUID != "" {
			if neverCreated || !receiptUID.MatchString(string(entry.OriginalUID)) || uids[entry.OriginalUID] {
				return ErrFixtures
			}
			uids[entry.OriginalUID] = true
		} else {
			neverCreated = true // acknowledged creations form one ordered prefix
		}
		switch entry.State {
		case fixturePlanned:
			if entry.OriginalUID != "" || entry.DeleteResourceVersion != "" {
				return ErrFixtures
			}
		case fixtureCreateAttempted:
			pending++
			createPending = true
			if entry.OriginalUID != "" || entry.DeleteResourceVersion != "" {
				return ErrFixtures
			}
		case fixtureOriginal:
			if entry.OriginalUID == "" || entry.DeleteResourceVersion != "" {
				return ErrFixtures
			}
		case fixtureDeleteAttempted:
			pending++
			deleting = true
			if entry.OriginalUID == "" || !fixtureRV(entry.DeleteResourceVersion) {
				return ErrFixtures
			}
		case fixtureAbsent:
			deleting = true
			if entry.OriginalUID == "" && entry.DeleteResourceVersion != "" || entry.OriginalUID != "" && !fixtureRV(entry.DeleteResourceVersion) {
				return ErrFixtures
			}
		default:
			return ErrFixtures
		}
		if recipe.owner >= 0 && entry.State != fixturePlanned && (entry.State != fixtureAbsent || entry.OriginalUID != "") {
			owner := d.Entries[recipe.owner]
			if owner.OriginalUID == "" || entry.State != fixtureAbsent && owner.State != fixtureOriginal || entry.State == fixtureAbsent && owner.State != fixtureOriginal && owner.State != fixtureDeleteAttempted && owner.State != fixtureAbsent {
				return ErrFixtures
			}
		}
		if entry.State == fixtureDeleteAttempted || entry.State == fixtureAbsent {
			for child, childRecipe := range fixtureCatalogFor(d) {
				if childRecipe.owner == i && d.Entries[child].State != fixtureAbsent {
					return ErrFixtures // resumed evidence cannot invert GC ordering
				}
			}
		}
	}
	if pending > 1 || deleting && createPending {
		return ErrFixtures
	}
	if !validFixtureDestroySeedDocument(d) || !validFixtureRetainedMarkerDocument(d) || !validFixtureWorldsSeal(d) || !validFixtureBehaviorDocument(d) {
		return ErrFixtures
	}
	return nil
}

func (e *Engine) fixtureLedgerBody(d fixtureLedgerDocument) ([]byte, error) {
	if e.validateFixtureLedger(d) != nil {
		return nil, ErrFixtures
	}
	body, err := json.Marshal(d)
	if err != nil || len(body) > fixtureLedgerMaxBytes {
		return nil, ErrFixtures
	}
	body, err = canonicaljson.CanonicalJSON(body)
	if err != nil {
		return nil, ErrFixtures
	}
	return body, nil
}

func (e *Engine) decodeFixtureLedger(body []byte) (fixtureLedgerDocument, error) {
	var d fixtureLedgerDocument
	if len(body) == 0 || len(body) > fixtureLedgerMaxBytes {
		return d, ErrFixtures
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil {
		return fixtureLedgerDocument{}, ErrFixtures
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return fixtureLedgerDocument{}, ErrFixtures
	}
	want, err := e.fixtureLedgerBody(d)
	if err != nil || !bytes.Equal(body, want) {
		return fixtureLedgerDocument{}, ErrFixtures
	}
	return d, nil
}

func validFixtureTransition(before, after fixtureLedgerDocument) bool {
	if after.Revision != before.Revision+1 || after.Version != before.Version || after.Recipe != before.Recipe || after.RunID != before.RunID || after.JournalResourceVersion != before.JournalResourceVersion || !bytes.Equal(after.Journal, before.Journal) || !validFixtureRecipe(before) || !validFixtureRecipe(after) {
		return false
	}
	if !validFixtureDestroySeedDocument(before) || !validFixtureDestroySeedDocument(after) || !validFixtureRetainedMarkerDocument(before) || !validFixtureRetainedMarkerDocument(after) || !validFixtureWorldsSeal(before) || !validFixtureWorldsSeal(after) || !validFixtureBehaviorDocument(before) || !validFixtureBehaviorDocument(after) {
		return false
	}
	if !reflect.DeepEqual(before.Behavior, after.Behavior) {
		return validFixtureBehaviorTransition(before, after)
	}
	if before.OriginalWorldsSHA256 != after.OriginalWorldsSHA256 {
		return validFixtureWorldsSealTransition(before, after)
	}
	seedChanged := !reflect.DeepEqual(before.DestroySeed, after.DestroySeed)
	markerChanged := !reflect.DeepEqual(before.RetainedMarker, after.RetainedMarker)
	if seedChanged {
		return !markerChanged && (before.RetainedMarker == nil || before.RetainedMarker.State == fixtureRetainedMarkerAcknowledged) && reflect.DeepEqual(before.Entries, after.Entries) && validFixtureDestroySeedTransition(before, after)
	}
	if markerChanged {
		return (before.DestroySeed == nil || before.DestroySeed.State == fixtureDestroySeedAcknowledged) && reflect.DeepEqual(before.Entries, after.Entries) && validFixtureRetainedMarkerTransition(before, after)
	}
	if before.DestroySeed != nil && before.DestroySeed.State != fixtureDestroySeedAcknowledged || before.RetainedMarker != nil && before.RetainedMarker.State != fixtureRetainedMarkerAcknowledged {
		return false // unknown status effect blocks EVERY ordinary entry transition
	}
	changed := -1
	for i, old := range before.Entries {
		if old == after.Entries[i] {
			continue
		}
		if changed != -1 || old.Key != after.Entries[i].Key {
			return false
		}
		changed = i
	}
	if changed == -1 {
		return false
	}
	old, next := before.Entries[changed], after.Entries[changed]
	switch old.State {
	case fixturePlanned:
		if next.OriginalUID != "" || next.DeleteResourceVersion != "" {
			return false
		}
		if next.State == fixtureAbsent {
			return true // future provider must first prove exact-address absence
		}
		if next.State != fixtureCreateAttempted {
			return false
		}
		for i, entry := range before.Entries {
			if entry.State != fixturePlanned && entry.State != fixtureOriginal || i < changed && entry.State != fixtureOriginal {
				return false // no create during cleanup or after an unknown outcome
			}
		}
		return true
	case fixtureCreateAttempted:
		return next.State == fixtureOriginal && next.OriginalUID != "" && next.DeleteResourceVersion == ""
	case fixtureOriginal:
		if next.State != fixtureDeleteAttempted || next.OriginalUID != old.OriginalUID || !fixtureRV(next.DeleteResourceVersion) {
			return false
		}
		for i, recipe := range fixtureCatalogFor(before) {
			if recipe.owner == changed && before.Entries[i].State != fixtureAbsent {
				return false // actual Pod absence must precede its Job deletion
			}
		}
		return true
	case fixtureDeleteAttempted:
		return next.State == fixtureAbsent && next.OriginalUID == old.OriginalUID && next.DeleteResourceVersion == old.DeleteResourceVersion
	}
	return false
}

// A locked durable ledger is an internal state primitive, not fixture access.
// The future provider must perform original witness/permission/whole-shape
// checks around each effect. advance never issues any Kubernetes request.
type fixtureLedger struct {
	// Serializes wire clients sharing this ledger, not arbitrary provider WAL
	// transitions. The closed provider owns transitions/close serially and must
	// never alter a ledger concurrently with a wire operation.
	wireMu                       sync.Mutex
	decodeCache                  fixtureDecodeCache
	engine                       *Engine
	name                         string
	lock                         *privatefs.Lock
	identity                     privatefs.FileIdentity
	body                         []byte
	document                     fixtureLedgerDocument
	ackSlot                      int                        // instance-local attempt capability; NEVER restored by load
	effectSlot                   int                        // single-send capability shared by ALL clients of this ledger
	seedAck                      bool                       // separate SAME-attempt capability; NEVER restored by load
	seedEffect                   bool                       // consumed before status transport; never permission by itself
	markerAck                    bool                       // separate same-attempt capability; NEVER restored by load
	markerEffect                 bool                       // consumed before marker transport; never permission by itself
	worldPublication             bool                       // one same-instance file publication; NEVER restored by load
	behaviorCompletion           *fixtureBehaviorCompletion // finite driver only; NEVER restored by load/archive
	driverFresh                  bool                       // consumed once by the fresh closed v2 driver; NEVER restored
	worldIdentity                *privatefs.FileIdentity    // pinned within this loaded session only
	phaseFloor                   *fixturePhaseBaseline      // latest COMPLETE accepted read; shared by this ledger's wires
	retirementArchive            bool                       // terminal archive reload has NO mutation/ACK capabilities
	retirementEvidence           *fixtureRetirementEvidence // pinned for this loaded session, including retries
	retirementArchiveIdentity    *privatefs.FileIdentity    // pinned even before sentinel publication
	retirementSentinelIdentity   *privatefs.FileIdentity    // acquired publication pin, before further checks
	retirementPublicationUnknown bool                       // failed publication cannot repin in this session
}

func (e *Engine) prepareFixtureLedger(ctx context.Context, s *installstate.Snapshot) (*fixtureLedger, error) {
	return e.prepareFixtureLedgerRecipe(ctx, s, false)
}

// The complete closed driver creates a NEW v2 run. Loading an existing run
// never calls this path and never changes its recipe or appends an original.
func (e *Engine) prepareFixtureLedgerV2(ctx context.Context, s *installstate.Snapshot) (*fixtureLedger, error) {
	return e.prepareFixtureLedgerRecipe(ctx, s, true)
}

func (e *Engine) prepareFixtureLedgerRecipe(ctx context.Context, s *installstate.Snapshot, v2 bool) (*fixtureLedger, error) {
	if e == nil || ctx == nil || s == nil || s.Document().Pending != nil || s.Document().AdmissionRetirementRevision != 0 {
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
	if _, err := e.current(ctx, s); err != nil {
		return nil, err
	}
	runID, err := installstate.NewID()
	if err != nil {
		return nil, ErrFixtures
	}
	d := fixtureLedgerDocument{Version: "v1", Recipe: fixtureRecipeV1, Revision: 1, RunID: runID, Journal: s.Bytes(), JournalResourceVersion: s.ResourceVersion()}
	catalog := fixtureCatalog[:]
	if v2 {
		d.Recipe, catalog = fixtureRecipeV2, fixtureCatalogV2[:]
	}
	for _, recipe := range catalog {
		d.Entries = append(d.Entries, fixtureEntry{Key: installstate.Key{APIVersion: recipe.version, Kind: recipe.kind, Namespace: s.Anchor().Namespace, Name: "arcadectl-probe-" + runID + "-" + recipe.suffix}, State: fixturePlanned})
	}
	body, err := e.fixtureLedgerBody(d)
	if err != nil {
		return nil, ErrFixtures
	}
	identity, err := e.files.CreateExclusive(fixtureLedgerName(s), body)
	if err != nil {
		return nil, ErrFixtures // never treat uncertain durability as absent intent
	}
	success = true
	return &fixtureLedger{engine: e, name: fixtureLedgerName(s), lock: lock, identity: identity, body: body, document: d, ackSlot: -1, effectSlot: -1, driverFresh: v2}, nil
}

// Resume only this exact protected run and original journal. Reading a matching
// live name/nonce cannot populate a missing UID. The future transport may
// observe pinned originals or absence; it must not replay an attempted effect.
func (e *Engine) loadFixtureLedger(ctx context.Context, s *installstate.Snapshot) (*fixtureLedger, error) {
	if e == nil || e.files == nil || ctx == nil || s == nil {
		return nil, ErrInvalid
	}
	name := fixtureLedgerName(s)
	lock, err := e.files.Lock(ctx, name)
	if err != nil {
		return nil, ErrFixtures
	}
	success := false
	defer func() {
		if !success {
			_ = lock.Close()
		}
	}()
	body, identity, err := e.files.Read(name, fixtureLedgerMaxBytes)
	if err != nil || e.files.ConfirmDurable(name, identity) != nil {
		return nil, ErrFixtures
	}
	d, err := e.decodeFixtureLedger(body)
	if err != nil || !bytes.Equal(d.Journal, s.Bytes()) || d.JournalResourceVersion != s.ResourceVersion() {
		return nil, ErrFixtures
	}
	fresh, err := e.journal.Load(ctx, s.Anchor())
	if err != nil || !bytes.Equal(fresh.Bytes(), s.Bytes()) || fresh.ResourceVersion() != s.ResourceVersion() {
		return nil, ErrFixtures
	}
	success = true
	return &fixtureLedger{engine: e, name: name, lock: lock, identity: identity, body: body, document: d, ackSlot: -1, effectSlot: -1}, nil
}

func (f *fixtureLedger) nextDocument() (fixtureLedgerDocument, error) {
	if f == nil || f.engine == nil || f.lock == nil {
		return fixtureLedgerDocument{}, ErrFixtures
	}
	d, err := f.decodeCurrentWAL(f.body)
	if err == nil {
		d.Revision++
	}
	return d, err
}

func (f *fixtureLedger) advance(next fixtureLedgerDocument) error {
	if f != nil && f.retirementArchive {
		return ErrFixtures
	}
	if f == nil || f.engine == nil || f.lock == nil {
		return ErrFixtures
	}
	current, err := f.decodeCurrentWAL(f.body)
	if err != nil || !reflect.DeepEqual(current, f.document) || !validFixtureTransition(current, next) {
		return ErrFixtures
	}
	seedChanged := !reflect.DeepEqual(f.document.DestroySeed, next.DestroySeed)
	markerChanged := !reflect.DeepEqual(f.document.RetainedMarker, next.RetainedMarker)
	worldChanged := f.document.OriginalWorldsSHA256 != next.OriginalWorldsSHA256
	behaviorChanged := !reflect.DeepEqual(f.document.Behavior, next.Behavior)
	if behaviorChanged {
		if !f.behaviorCompletion.matches(f) || f.ackSlot != -1 || f.effectSlot != -1 || f.seedAck || f.seedEffect || f.markerAck || f.markerEffect || f.worldPublication || f.originalWorldsCurrent() != nil {
			return ErrFixtures
		}
	} else if f.behaviorCompletion != nil {
		return ErrFixtures // no unrelated transition may spend or carry completion
	}
	if f.worldPublication || worldChanged && (f.ackSlot != -1 || f.effectSlot != -1 || f.seedAck || f.seedEffect || f.markerAck || f.markerEffect) {
		return ErrFixtures
	}
	if seedChanged && (f.markerAck || f.markerEffect || f.document.DestroySeed == nil && (f.ackSlot != -1 || f.effectSlot != -1) || f.document.DestroySeed != nil && (!f.seedAck || f.seedEffect)) {
		return ErrFixtures // no ACK before send, after uncertainty or after restart
	}
	if markerChanged && (f.seedAck || f.seedEffect || f.document.RetainedMarker == nil && (f.ackSlot != -1 || f.effectSlot != -1) || f.document.RetainedMarker != nil && (!f.markerAck || f.markerEffect)) {
		return ErrFixtures
	}
	if !seedChanged && !markerChanged && (f.seedAck || f.seedEffect || f.markerAck || f.markerEffect) {
		return ErrFixtures // no entry transition can spend stale receipt capabilities
	}
	changed := -1
	for i, entry := range f.document.Entries {
		if entry != next.Entries[i] {
			changed = i
			if entry.State == fixtureCreateAttempted && next.Entries[i].State == fixtureOriginal && f.ackSlot != i {
				return ErrFixtures // a restart cannot adopt a live name/nonce UID
			}
			break
		}
	}
	preparingEffect := seedChanged && f.document.DestroySeed == nil || markerChanged && f.document.RetainedMarker == nil || changed >= 0 && (next.Entries[changed].State == fixtureCreateAttempted || next.Entries[changed].State == fixtureDeleteAttempted)
	if preparingEffect && current.OriginalWorldsSHA256 != "" && f.originalWorldsCurrent() != nil {
		return ErrFixtures
	}
	// Reliable same-attempt acknowledgements deliberately do not require the
	// companion: pin original UID/RV before reporting a late witness failure.
	body, err := f.engine.fixtureLedgerBody(next)
	if err != nil {
		return ErrFixtures
	}
	old, identity, err := f.engine.files.Read(f.name, fixtureLedgerMaxBytes)
	if err != nil || identity != f.identity || !bytes.Equal(old, f.body) || f.engine.files.ConfirmDurable(f.name, identity) != nil {
		return ErrFixtures
	}
	if behaviorChanged {
		f.behaviorCompletion = nil // consume BEFORE a possibly uncertain publication
	}
	identity, err = f.engine.files.AtomicWrite(f.name, body, &identity)
	if err != nil {
		return ErrFixtures
	}
	d, err := f.engine.decodeFixtureLedger(body)
	if err != nil || !reflect.DeepEqual(d, next) {
		return ErrFixtures
	}
	f.identity, f.body, f.document = identity, body, d
	f.decodeCache.clearWAL()
	if worldChanged {
		f.worldPublication = true // sealed intent is NOT a durable companion witness
	}
	if seedChanged {
		f.seedAck, f.seedEffect = false, false
		if next.DestroySeed.State == fixtureDestroySeedAttempted {
			f.seedAck, f.seedEffect = true, true
		}
	}
	if markerChanged {
		f.markerAck, f.markerEffect = false, false
		if next.RetainedMarker.State == fixtureRetainedMarkerAttempted {
			f.markerAck, f.markerEffect = true, true
		}
	}
	if changed >= 0 {
		f.ackSlot = -1
		f.effectSlot = -1
		if next.Entries[changed].State == fixtureCreateAttempted {
			f.ackSlot = changed
			f.effectSlot = changed
		} else if next.Entries[changed].State == fixtureDeleteAttempted {
			f.effectSlot = changed
		}
	}
	return nil
}

func (f *fixtureLedger) close() error {
	if f == nil || f.lock == nil {
		return ErrFixtures
	}
	err := f.lock.Close()
	f.lock = nil
	f.decodeCache.clear()
	f.seedAck, f.seedEffect = false, false
	f.markerAck, f.markerEffect = false, false
	f.worldPublication = false
	f.behaviorCompletion = nil
	f.worldIdentity = nil
	return err
}
