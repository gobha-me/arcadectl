// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// These exercise only protected WAL durability, strict transitions and the
// installer fence. No fixture effects, absence or full provider are fabricated.
func TestFixtureLedgerUnknownCreateCannotBeReplayedOrAdopted(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(context.Background(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if f.access.writes != 0 || f.nsUpdates != 0 || !bytes.Equal(ledger.document.Journal, f.snapshot.Bytes()) {
		t.Fatal("pre-effect ledger changed cluster state or lost original journal")
	}
	next, err := ledger.nextDocument()
	if err != nil {
		t.Fatal(err)
	}
	next.Entries[0].State = fixtureCreateAttempted
	if err := ledger.advance(next); err != nil {
		t.Fatal(err)
	}
	if err := ledger.close(); err != nil {
		t.Fatal(err)
	}
	resumed, err := f.engine.loadFixtureLedger(context.Background(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.close()
	if resumed.document.Entries[0].OriginalUID != "" || resumed.document.Entries[0].State != fixtureCreateAttempted || f.access.writes != 0 {
		t.Fatal("restart inferred an unacknowledged original UID or issued an effect")
	}
	for _, state := range []fixtureState{fixturePlanned, fixtureAbsent, fixtureDeleteAttempted, fixtureCreateAttempted} {
		next, err := resumed.nextDocument()
		if err != nil {
			t.Fatal(err)
		}
		next.Entries[0].State = state
		if resumed.advance(next) != ErrFixtures {
			t.Fatal("unknown CREATE allowed replay, speculative cleanup or fresh intent")
		}
	}
	next, _ = resumed.nextDocument()
	next.Entries[0].State, next.Entries[0].OriginalUID = fixtureOriginal, "adopted-by-name-after-restart"
	if resumed.advance(next) != ErrFixtures {
		t.Fatal("restarted instance populated an unacknowledged UID")
	}
	next, _ = resumed.nextDocument()
	next.Entries[1].State = fixtureCreateAttempted
	if resumed.advance(next) != ErrFixtures {
		t.Fatal("unknown CREATE allowed a later effect")
	}
	if f.engine.fixtureFence(f.snapshot) != ErrFixtures || f.access.writes != 0 {
		t.Fatal("unresolved ledger did not fence ordinary effects")
	}
}

func TestFixtureLedgerPinsAcknowledgedIdentityAndCleanupOrdering(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(context.Background(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	advance := func(slot int, state fixtureState, uid types.UID, rv string) {
		t.Helper()
		next, err := ledger.nextDocument()
		if err != nil {
			t.Fatal(err)
		}
		next.Entries[slot].State, next.Entries[slot].OriginalUID, next.Entries[slot].DeleteResourceVersion = state, uid, rv
		if err := ledger.advance(next); err != nil {
			t.Fatalf("slot %d %s: %v", slot, state, err)
		}
	}
	for i := range fixtureCatalog {
		advance(i, fixtureCreateAttempted, "", "")
		advance(i, fixtureOriginal, types.UID(fmt.Sprintf("ack-original-%d", i)), "")
	}
	// A defensive copy, not a mutable alias into the sealed current receipt.
	next, _ := ledger.nextDocument()
	next.Entries[0].OriginalUID = "replacement"
	if ledger.document.Entries[0].OriginalUID != "ack-original-0" || ledger.advance(next) != ErrFixtures {
		t.Fatal("original UID replacement or caller slice alias accepted")
	}
	next, _ = ledger.nextDocument()
	next.Entries[0].State, next.Entries[0].DeleteResourceVersion = fixtureDeleteAttempted, "123"
	if ledger.advance(next) != ErrFixtures {
		t.Fatal("Job cleanup preceded original worker Pod absence")
	}
	for _, rv := range []string{"", "0", "00", "0123", "-1", "foreign"} {
		next, _ = ledger.nextDocument()
		next.Entries[1].State, next.Entries[1].DeleteResourceVersion = fixtureDeleteAttempted, rv
		if ledger.advance(next) != ErrFixtures {
			t.Fatal("unconditional or malformed cleanup resource-version accepted")
		}
	}
	for _, slot := range []int{1, 0, 3, 2, 5, 4, 6, 7, 8, 9} {
		uid := ledger.document.Entries[slot].OriginalUID
		advance(slot, fixtureDeleteAttempted, uid, "123")
		next, _ = ledger.nextDocument()
		next.Entries[slot].State = fixtureOriginal
		next.Entries[slot].DeleteResourceVersion = ""
		if ledger.advance(next) != ErrFixtures {
			t.Fatal("cleanup intent reset for replay")
		}
		advance(slot, fixtureAbsent, uid, "123")
	}
	if f.engine.fixtureFence(f.snapshot) != ErrFixtures {
		t.Fatal("terminal but unretired ledger bypassed current absence proof")
	}
	for _, state := range []fixtureState{fixturePlanned, fixtureOriginal, fixtureCreateAttempted} {
		forged, _ := ledger.nextDocument()
		forged.Entries[1].State = state
		forged.Entries[1].DeleteResourceVersion = ""
		if state != fixtureOriginal {
			forged.Entries[1].OriginalUID = ""
		}
		body, _ := json.Marshal(forged)
		body, _ = canonicaljson.CanonicalJSON(body)
		if _, err := f.engine.decodeFixtureLedger(body); err != ErrFixtures {
			t.Fatal("resumed receipt deleted Job before its child Pod absence")
		}
	}
}

func TestFixtureLedgerDecodeAndResumeRefuseForeignEvidence(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(context.Background(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(ledger.body)
	if err := ledger.close(); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"version", "recipe", "run", "namespace", "address", "catalog", "state", "uid", "duplicate", "unknown", "trailing", "whitespace", "journal-rv", "journal-namespace-uid", "journal-revision", "journal-package"} {
		t.Run(scenario, func(t *testing.T) {
			d, err := f.engine.decodeFixtureLedger(original)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "version":
				d.Version = "v2"
			case "recipe":
				d.Recipe = "caller-script"
			case "run":
				d.RunID = "../../foreign"
			case "namespace":
				d.Entries[0].Key.Namespace = "foreign"
			case "address":
				d.Entries[0].Key.Kind = "Secret"
			case "catalog":
				d.Entries = d.Entries[:1]
			case "state":
				d.Entries[0].State = "complete"
			case "uid":
				d.Entries[0].OriginalUID = "adopted-from-name"
			case "journal-rv":
				d.JournalResourceVersion = "999"
			case "journal-namespace-uid", "journal-revision", "journal-package":
				journal := f.snapshot.Document()
				if scenario == "journal-namespace-uid" {
					journal.NamespaceUID = "foreign-original"
				} else if scenario == "journal-revision" {
					journal.Revision++
				} else {
					journal.TargetPackage = "foreign"
				}
				d.Journal, _ = json.Marshal(journal)
				d.Journal, _ = canonicaljson.CanonicalJSON(d.Journal)
			}
			body, _ := json.Marshal(d)
			body, _ = canonicaljson.CanonicalJSON(body)
			switch scenario {
			case "duplicate":
				body = append([]byte(`{"version":"v1",`), body[1:]...)
			case "unknown":
				body = append([]byte(`{"rawCredential":"PRIVATE-CANARY",`), body[1:]...)
			case "trailing":
				body = append(body, []byte(` {}`)...)
			case "whitespace":
				body = append(body, '\n')
			}
			_, identity, err := f.engine.files.Read(fixtureLedgerName(f.snapshot), fixtureLedgerMaxBytes)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.engine.files.AtomicWrite(fixtureLedgerName(f.snapshot), body, &identity); err != nil {
				t.Fatal(err)
			}
			loaded, err := f.engine.loadFixtureLedger(context.Background(), f.snapshot)
			if err == nil {
				_ = loaded.close()
				t.Fatal("foreign or malformed evidence resumed")
			}
			if f.engine.fixtureFence(f.snapshot) != ErrFixtures || f.access.writes != 0 || f.nsUpdates != 0 {
				t.Fatal("bad receipt weakened the fence or changed cluster state")
			}
		})
	}
}

func TestFixtureLedgerFencePrecedesLifecycleAndInstallerPendingRecovery(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint(pending), func(t *testing.T) {
			v := newLifecycleFixture(t)
			s := v.f.snapshot
			if pending {
				v.f.access.write = func(installstate.Action, installstate.Key, *unstructured.Unstructured) (*unstructured.Unstructured, error) {
					return nil, ErrRead
				}
				var err error
				s, err = v.f.engine.Apply(context.Background(), s, v.f.key, v.f.plan.Digest(), false)
				if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil {
					t.Fatal("fixture did not preserve an unknown ordinary CREATE")
				}
			}
			// Malformed active receipt still fences: do not run even an injected
			// permissive proof provider or ordinary pending recovery underneath.
			if _, err := v.f.engine.files.CreateExclusive(fixtureLedgerName(s), []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			writes, commits := v.f.access.writes, v.f.nsUpdates
			if _, err := v.l.Step(context.Background(), s, v.opts); err != ErrFixtures || len(v.checks) != 0 {
				t.Fatal("Step reached provider or pending recovery before the fixture fence")
			}
			if _, err := v.l.Begin(context.Background(), s, installstate.Uninstall, v.f.plan.Digest(), v.opts); err != ErrFixtures {
				t.Fatal("Begin bypassed unresolved fixtures")
			}
			if _, err := v.f.engine.Apply(context.Background(), s, v.f.key, v.f.plan.Digest(), false); err != ErrFixtures {
				t.Fatal("public effect bypassed unresolved fixtures")
			}
			if _, err := v.f.engine.PrepareCredentials(context.Background(), s, v.opts.Credentials); err != ErrFixtures {
				t.Fatal("private effect bypassed unresolved fixtures")
			}
			if _, err := v.f.engine.Recover(context.Background(), s); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("direct pending recovery failed to preserve unknown outcome")
			}
			if v.f.access.writes != writes || v.f.nsUpdates != commits {
				t.Fatal("fixture fence allowed a cluster effect or journal settlement")
			}
		})
	}
}

func TestFixtureLedgerLocksAndProtectedFileIdentity(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(context.Background(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := f.engine.loadFixtureLedger(ctx, f.snapshot); err != ErrFixtures {
		t.Fatal("concurrent fixture writer acquired the cooperative lock")
	}
	// Byte-identical file replacement is not the observed protected inode.
	if _, err := f.engine.files.AtomicWrite(ledger.name, bytes.Clone(ledger.body), &ledger.identity); err != nil {
		t.Fatal(err)
	}
	next, _ := ledger.nextDocument()
	next.Entries[0].State = fixtureCreateAttempted
	if ledger.advance(next) != ErrFixtures {
		t.Fatal("replaced protected file accepted as original observed receipt")
	}
	if f.access.writes != 0 || f.nsUpdates != 0 {
		t.Fatal("WAL state machinery performed a cluster effect")
	}
}

func TestFixtureLedgerResumeRefusesChangeAndRestoreOfOriginalNamespace(t *testing.T) {
	f := newFixture(t, false)
	ledger, err := f.engine.prepareFixtureLedger(context.Background(), f.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.close(); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []bool{true, false} {
		live, err := f.access.client.CoreV1().Namespaces().Get(context.Background(), f.snapshot.Anchor().Namespace, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			live.Annotations["example.com/public-concurrent-change"] = "changed"
		} else {
			delete(live.Annotations, "example.com/public-concurrent-change")
		}
		if _, err := f.access.client.CoreV1().Namespaces().Update(context.Background(), live, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		resumed, err := f.engine.loadFixtureLedger(context.Background(), f.snapshot)
		if err == nil {
			_ = resumed.close()
			t.Fatal("changed/restored namespace resumed the original sealed fixture run")
		}
	}
	if f.access.writes != 0 || f.engine.fixtureFence(f.snapshot) != ErrFixtures {
		t.Fatal("namespace drift granted a fixture effect or bypassed the fence")
	}
}
