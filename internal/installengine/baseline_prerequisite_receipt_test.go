// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

func TestBaselinePrerequisiteReceiptOwnedOriginalAndRefusalCleanup(t *testing.T) {
	for _, acknowledged := range []bool{false, true} {
		name := "prepared-empty"
		if acknowledged {
			name = "acknowledged"
		}
		t.Run(name, func(t *testing.T) {
			f := newBaselineFixture(t)
			completeBaselineFixture(t, f)
			d := f.snapshot.Document()
			key := f.key
			template, err := f.engine.contracts[d.TargetPackage].Template(key, false)
			if err != nil {
				t.Fatal("signed prerequisite template unavailable")
			}
			d.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("c", 32), AfterSHA256: template.Hash()}
			snapshot := prerequisiteSnapshotFixture(t, f, d)
			d = snapshot.Document()
			operation, err := f.engine.prerequisiteOperation(snapshot, key, d.TargetPackage)
			if err != nil || f.engine.prepareCreateReceipt(d) != nil {
				t.Fatal("original prerequisite intent/receipt unavailable")
			}
			if acknowledged && f.engine.saveCreateUID(d, "original-prerequisite") != nil {
				t.Fatal("original protected ACK unavailable")
			}
			name := "create-" + d.Pending.CreateNonce + ".json"
			for range 32 {
				witness, err := f.engine.openPrerequisiteReceipt(snapshot, operation)
				t.Cleanup(witness.release)
				if err != nil || witness == nil || (witness.uid != "") != acknowledged || testBaselineReceiptDescriptors(t, name) != 1 || f.engine.confirmPrerequisiteReceipt(snapshot, operation, witness) != nil {
					t.Fatal("prerequisite receipt did not retain exact prepared/acknowledged opening evidence")
				}
				witness.release()
				witness.release()
				if f.engine.confirmPrerequisiteReceipt(snapshot, operation, witness) != ErrSecurityBaseline || testBaselineReceiptDescriptors(t, name) != 0 {
					t.Fatal("released prerequisite receipt leaked or supplied authority")
				}
			}
			first, err := f.engine.openPrerequisiteReceipt(snapshot, operation)
			t.Cleanup(first.release)
			if err != nil || first == nil {
				t.Fatal("opening prerequisite owner unavailable")
			}
			second, err := f.engine.openPrerequisiteReceipt(snapshot, operation)
			t.Cleanup(second.release)
			if err != nil || second == nil || first.receipt.pin == second.receipt.pin || !sameBaselineOriginalReceipt(first.receipt, second.receipt) || testBaselineReceiptDescriptors(t, name) != 2 {
				t.Fatal("independent prerequisite owners confused evidence and handles")
			}
			first.release()
			if f.engine.confirmPrerequisiteReceipt(snapshot, operation, second) != nil || testBaselineReceiptDescriptors(t, name) != 1 {
				t.Fatal("releasing an independent owner closed another witness")
			}
			body, identity, err := f.engine.files.Read(name, 4096)
			if err != nil {
				t.Fatal("test-owned receipt unavailable")
			}
			for range 64 {
				identity, err = f.engine.files.AtomicWrite(name, body, &identity)
				if err != nil || f.engine.confirmPrerequisiteReceipt(snapshot, operation, second) != ErrSecurityBaseline || testBaselineReceiptDescriptors(t, name) != 1 {
					t.Fatal("repeated same-byte replacement revived opening prerequisite authority")
				}
			}
			second.release()
			if testBaselineReceiptDescriptors(t, name) != 0 {
				t.Fatal("unlinked original prerequisite owner leaked")
			}
			if _, err := f.engine.files.AtomicWrite(name, []byte("{}"), &identity); err != nil {
				t.Fatal("test-owned malformed receipt unavailable")
			}
			for range 32 {
				rejected, err := f.engine.openPrerequisiteReceipt(snapshot, operation)
				t.Cleanup(rejected.release)
				if err != ErrSecurityBaseline || rejected != nil || testBaselineReceiptDescriptors(t, name) != 0 {
					t.Fatal("malformed prerequisite receipt refusal leaked its acquired descriptor")
				}
			}
		})
	}
}
