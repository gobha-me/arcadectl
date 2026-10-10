// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/types"
)

// Immutable original identities, not a fresh coldness proof or effect permit.
// Full object hashes retain the same world tuple as ordinary cold safety,
// without persisting raw settings, storage sources or credentials. Attachment-
// derived foreign PVs are fresh safety evidence, never original world members.
type fixtureWorldRow struct {
	Key             installstate.Key `json:"key"`
	UID             types.UID        `json:"uid"`
	ResourceVersion string           `json:"resourceVersion"`
	SHA256          string           `json:"sha256"`
}

type fixtureWorldsDocument struct {
	Version                string                `json:"version"`
	RunID                  string                `json:"runId"`
	Journal                json.RawMessage       `json:"journal"`
	JournalResourceVersion string                `json:"journalResourceVersion"`
	Rows                   []fixtureWorldRow     `json:"rows"`
	Phase                  *fixturePhaseBaseline `json:"phase,omitempty"`
}

func fixtureWorldOrder(key installstate.Key) string {
	return key.APIVersion + "\x00" + key.Kind + "\x00" + key.Namespace + "\x00" + key.Name
}

func fixtureWorldDigest(body []byte) string {
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

func (f *fixtureLedger) worldsJournal() (*installstate.Document, error) {
	if f == nil || f.engine == nil {
		return nil, ErrFixtures
	}
	wal, err := f.decodeCurrentWAL(f.body)
	if err != nil || !reflect.DeepEqual(wal, f.document) {
		return nil, ErrFixtures
	}
	d, err := f.decodeCurrentJournal(wal.Journal)
	if err != nil {
		return nil, ErrFixtures
	}
	return &d, nil
}

func (f *fixtureLedger) originalWorldsName() (string, error) {
	d, err := f.worldsJournal()
	if err != nil {
		return "", ErrFixtures
	}
	return "admission-worlds-" + d.InstallationID + "-" + f.document.RunID + ".json", nil
}

func (f *fixtureLedger) worldsBody(d fixtureWorldsDocument) ([]byte, error) {
	journal, err := f.worldsJournal()
	if err != nil || d.Version != "original-worlds-v1" || d.RunID != f.document.RunID || !bytes.Equal(d.Journal, f.document.Journal) || d.JournalResourceVersion != f.document.JournalResourceVersion || d.Rows == nil || len(d.Rows) > 3*installsafety.MaxObjectsPerList {
		return nil, ErrFixtures
	}
	if d.Phase != nil && !fixtureAccountsRecipeMatches(f.document, d.Phase) || d.Phase == nil && f.document.Recipe == fixtureRecipeV3 {
		return nil, ErrFixtures
	}
	return fixtureWorldsShapeBody(d, journal.Namespace)
}

// Package-independent immutable shape validation also applies to historical
// retirement evidence; trusted-plan/journal binding remains the caller's duty.
func fixtureWorldsShapeBody(d fixtureWorldsDocument, namespace string) ([]byte, error) {
	if d.Rows == nil || len(d.Rows) > 3*installsafety.MaxObjectsPerList || d.Phase != nil && d.Phase.validate(namespace) != nil {
		return nil, ErrFixtures
	}
	uids := map[types.UID]bool{}
	counts := map[string]int{}
	previous := ""
	for _, row := range d.Rows {
		key := row.Key
		order := fixtureWorldOrder(key)
		if !addressPart(key.Name) || !receiptUID.MatchString(string(row.UID)) || uids[row.UID] || !fixtureRV(row.ResourceVersion) || !fixtureWorldsDigest.MatchString(row.SHA256) || order <= previous {
			return nil, ErrFixtures
		}
		switch key.APIVersion + "/" + key.Kind {
		case "arcade.gobha.me/v1alpha1/GameServer", "v1/PersistentVolumeClaim":
			if key.Namespace != namespace {
				return nil, ErrFixtures
			}
		case "v1/PersistentVolume":
			if key.Namespace != "" {
				return nil, ErrFixtures
			}
		default:
			return nil, ErrFixtures
		}
		counts[key.Kind]++
		if counts[key.Kind] > installsafety.MaxObjectsPerList {
			return nil, ErrFixtures
		}
		uids[row.UID], previous = true, order
	}
	if d.Phase != nil {
		worlds := map[installstate.Key]fixtureWorldRow{}
		identities := map[types.UID]fixtureWorldRow{}
		for _, row := range d.Rows {
			worlds[row.Key], identities[row.UID] = row, row
		}
		phaseWorlds := map[installstate.Key]fixtureWorldRow{}
		for _, row := range d.Phase.Rows {
			if original, found := identities[row.UID]; found && original != row {
				return nil, ErrFixtures
			}
			if row.Key.Kind == "GameServer" || row.Key.Kind == "PersistentVolumeClaim" {
				if worlds[row.Key] != row {
					return nil, ErrFixtures
				}
				phaseWorlds[row.Key] = row
			}
		}
		for _, row := range d.Rows {
			if row.Key.Kind != "PersistentVolume" && phaseWorlds[row.Key] != row {
				return nil, ErrFixtures
			}
		}
		for _, leader := range d.Phase.Leaders {
			if _, found := identities[leader.Row.UID]; found {
				return nil, ErrFixtures
			}
		}
		for _, row := range d.Phase.Public {
			if _, found := identities[row.UID]; found {
				return nil, ErrFixtures
			}
		}
		if d.Phase.Accounts != nil {
			for _, row := range d.Phase.Accounts.Rows {
				if _, found := identities[row.UID]; found {
					return nil, ErrFixtures
				}
			}
		}
	}
	body, err := json.Marshal(d)
	if err != nil || int64(len(body)) > privatefs.MaxEvidenceFileBytes {
		return nil, ErrFixtures
	}
	body, err = canonicaljson.CanonicalEvidenceJSON(body)
	if err != nil {
		return nil, ErrFixtures
	}
	return body, nil
}

func (f *fixtureLedger) decodeWorlds(body []byte) (fixtureWorldsDocument, error) {
	var d fixtureWorldsDocument
	if len(body) == 0 || int64(len(body)) > privatefs.MaxEvidenceFileBytes {
		return d, ErrFixtures
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil {
		return fixtureWorldsDocument{}, ErrFixtures
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return fixtureWorldsDocument{}, ErrFixtures
	}
	want, err := f.worldsBody(d)
	if err != nil || !bytes.Equal(body, want) {
		return fixtureWorldsDocument{}, ErrFixtures
	}
	return d, nil
}

// The digest is fsynced in the WAL BEFORE the exclusive companion publication.
// Failure never falls through to fixture effects. Publication is a once-only
// same-instance capability; reload can confirm exact visible evidence but may
// never reconstruct a missing baseline from current survivors.
func (f *fixtureLedger) sealOriginalWorlds(rows []fixtureWorldRow) error {
	if f == nil || f.lock == nil || f.document.OriginalWorldsSHA256 != "" {
		return ErrFixtures
	}
	d := fixtureWorldsDocument{"original-worlds-v1", f.document.RunID, bytes.Clone(f.document.Journal), f.document.JournalResourceVersion, append([]fixtureWorldRow{}, rows...), nil}
	return f.sealWorldsDocument(d)
}

func (f *fixtureLedger) sealWorldsDocument(d fixtureWorldsDocument) error {
	if f == nil || f.lock == nil || f.document.OriginalWorldsSHA256 != "" {
		return ErrFixtures
	}
	body, err := f.worldsBody(d)
	if err != nil {
		return ErrFixtures
	}
	next, err := f.nextDocument()
	if err != nil {
		return ErrFixtures
	}
	next.OriginalWorldsSHA256 = fixtureWorldDigest(body)
	if f.advance(next) != nil {
		return ErrFixtures
	}
	return f.publishOriginalWorlds(body)
}

func (f *fixtureLedger) publishOriginalWorlds(body []byte) error {
	if f == nil || f.lock == nil || !f.worldPublication || f.worldIdentity != nil || fixtureWorldDigest(body) != f.document.OriginalWorldsSHA256 || f.originalWorldsWALCurrent() != nil {
		return ErrFixtures
	}
	if _, err := f.decodeWorlds(body); err != nil {
		return ErrFixtures
	}
	name, err := f.originalWorldsName()
	if err != nil {
		return ErrFixtures
	}
	f.worldPublication = false // consumed BEFORE filesystem effect, even if uncertain
	identity, err := f.engine.files.CreateEvidenceExclusive(name, body)
	if err != nil {
		return ErrFixtures
	}
	f.worldIdentity = &identity
	_, err = f.readOriginalWorlds(false)
	return err
}

// loadOriginalWorlds is persistence recovery, not adoption of a cluster object.
// The sealed canonical bytes and original journal/run must match before the
// session pins an inode. An already pinned session refuses same-byte replacement.
func (f *fixtureLedger) loadOriginalWorlds() (fixtureWorldsDocument, error) {
	return f.readOriginalWorlds(true)
}

func (f *fixtureLedger) readOriginalWorlds(pin bool) (fixtureWorldsDocument, error) {
	if f == nil || f.lock == nil || f.worldPublication || f.document.OriginalWorldsSHA256 == "" || !pin && f.worldIdentity == nil || f.originalWorldsWALCurrent() != nil {
		return fixtureWorldsDocument{}, ErrFixtures
	}
	name, err := f.originalWorldsName()
	if err != nil {
		return fixtureWorldsDocument{}, ErrFixtures
	}
	body, identity, err := f.engine.files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
	if err != nil || fixtureWorldDigest(body) != f.document.OriginalWorldsSHA256 || f.worldIdentity != nil && identity != *f.worldIdentity || f.engine.files.ConfirmEvidenceDurable(name, identity) != nil {
		return fixtureWorldsDocument{}, ErrFixtures
	}
	d, err := f.decodeWorlds(body)
	if err != nil || d.Phase != nil && !fixtureAccountsRecipeMatches(f.document, d.Phase) || d.Phase == nil && f.document.Recipe == fixtureRecipeV3 || f.originalWorldsWALCurrent() != nil {
		return fixtureWorldsDocument{}, ErrFixtures
	}
	if pin {
		f.worldIdentity = &identity
	}
	return d, nil
}

// Check only the original protected WAL, never world/actor HTTP. Standalone
// companion readers must not trust a substituted in-memory seal. This helper
// intentionally does not require the companion and is not used to gate ACKs.
func (f *fixtureLedger) originalWorldsWALCurrent() error {
	if f == nil || f.engine == nil || f.engine.files == nil || f.lock == nil {
		return ErrFixtures
	}
	d, err := f.decodeCurrentWAL(f.body)
	if err != nil || !reflect.DeepEqual(d, f.document) {
		return ErrFixtures
	}
	body, identity, err := f.engine.files.Read(f.name, fixtureLedgerMaxBytes)
	if err != nil || identity != f.identity || !bytes.Equal(body, f.body) || f.engine.files.ConfirmDurable(f.name, identity) != nil {
		return ErrFixtures
	}
	return nil
}

func (f *fixtureLedger) originalWorldsCurrent() error {
	_, err := f.readOriginalWorlds(false)
	return err
}

func (f *fixtureLedger) matchesOriginalWorlds(rows []fixtureWorldRow) error {
	d, err := f.readOriginalWorlds(false)
	if err != nil || !reflect.DeepEqual(d.Rows, rows) {
		return ErrFixtures
	}
	return nil
}

func sortFixtureWorlds(rows []fixtureWorldRow) {
	sort.Slice(rows, func(i, j int) bool { return fixtureWorldOrder(rows[i].Key) < fixtureWorldOrder(rows[j].Key) })
}

func (tuple *coldWorldTuple) fixtureWorldRows() ([]fixtureWorldRow, error) {
	if tuple == nil || len(tuple.Servers) > installsafety.MaxObjectsPerList || len(tuple.Claims) > installsafety.MaxObjectsPerList || len(tuple.Volumes) > installsafety.MaxObjectsPerList {
		return nil, ErrFixtures
	}
	rows := make([]fixtureWorldRow, 0, len(tuple.Servers)+len(tuple.Claims)+len(tuple.Volumes))
	add := func(key installstate.Key, uid types.UID, rv string, value any) error {
		body, err := json.Marshal(value)
		if err != nil || len(body) > 32*1024*1024 {
			return ErrFixtures
		}
		rows = append(rows, fixtureWorldRow{key, uid, rv, fixtureWorldDigest(body)})
		return nil
	}
	for _, server := range tuple.Servers {
		if add(installstate.Key{APIVersion: "arcade.gobha.me/v1alpha1", Kind: "GameServer", Namespace: server.Namespace, Name: server.Name}, server.UID, server.ResourceVersion, server) != nil {
			return nil, ErrFixtures
		}
	}
	for _, claim := range tuple.Claims {
		if add(installstate.Key{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: claim.Namespace, Name: claim.Name}, claim.UID, claim.ResourceVersion, claim) != nil {
			return nil, ErrFixtures
		}
	}
	for _, volume := range tuple.Volumes {
		if volume == nil || add(installstate.Key{APIVersion: "v1", Kind: "PersistentVolume", Namespace: volume.Namespace, Name: volume.Name}, volume.UID, volume.ResourceVersion, volume) != nil {
			return nil, ErrFixtures
		}
	}
	sortFixtureWorlds(rows)
	return rows, nil
}
