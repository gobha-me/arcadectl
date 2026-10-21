// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Count only this receipt's descriptors, including unlinked original inodes.
// HTTP connection creation does not contaminate ownership accounting. Tests
// are serial and never depend on GC finalizers or Store.Close for release.
func testBaselineReceiptDescriptors(t *testing.T, name string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("receipt descriptor accounting unavailable")
	}
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && strings.HasSuffix(strings.TrimSuffix(target, " (deleted)"), "/"+name) {
			count++
		}
	}
	return count
}

func testBaselinePendingReceipt(t *testing.T, parent bool) (*fixture, installstate.Document, installstate.Key, *unstructured.Unstructured) {
	t.Helper()
	f := seedBaselineAccessWitness(t)
	d := f.snapshot.Document()
	key := installstate.Key{APIVersion: "v1", Kind: "Service", Namespace: d.Namespace, Name: "arcadectl-api"}
	if parent {
		key = deploymentKey(d.Namespace, "arcadectl-api")
	}
	template, err := f.engine.contracts[d.TargetPackage].Template(key, false)
	if err != nil {
		t.Fatal("signed pending receipt template unavailable")
	}
	d.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("c", 32), AfterSHA256: template.Hash()}
	var live *unstructured.Unstructured
	if parent {
		live = testBaselineParentLive(t, template, d.Pending.CreateNonce)
		live.SetGeneration(1)
	} else {
		live = testBaselineMetadataLive(t, template, d.Pending.CreateNonce)
	}
	live.SetUID("original-pending-receipt")
	live.SetResourceVersion("17")
	d.Revision++
	seedBaselineAccessUnitDocument(t, f, d)
	if f.engine.prepareCreateReceipt(d) != nil || f.engine.saveCreateUID(d, live.GetUID()) != nil {
		t.Fatal("original protected receipt unavailable")
	}
	return f, d, key, live
}

func TestBaselineOriginalReceiptIndependentOwnersAndReleasedRefusal(t *testing.T) {
	for _, parent := range []bool{false, true} {
		name := "metadata"
		if parent {
			name = "parent"
		}
		t.Run(name, func(t *testing.T) {
			f, d, key, live := testBaselinePendingReceipt(t, parent)
			first, err := f.engine.originalBaselineObject(d, key, live)
			t.Cleanup(first.release)
			if err != nil || first == nil || first.receipt == nil {
				t.Fatal("opening receipt witness unavailable")
			}
			second, err := f.engine.originalBaselineObject(d, key, live)
			t.Cleanup(second.release)
			if err != nil || second == nil || second.receipt == nil || first.receipt.pin == second.receipt.pin || !sameBaselineOriginalReceipt(first.receipt, second.receipt) || reflect.DeepEqual(first.receipt, second.receipt) {
				t.Fatal("independent owned handles changed semantic evidence equality")
			}
			if f.engine.confirmBaselineOriginalReceipt(d, key, first) != nil || f.engine.confirmBaselineOriginalReceipt(d, key, second) != nil {
				t.Fatal("healthy independent receipt confirmation refused")
			}
			// Semantic equality deliberately cannot certify handle liveness.
			first.release()
			first.release()
			if !sameBaselineOriginalReceipt(first.receipt, second.receipt) || f.engine.confirmBaselineOriginalReceipt(d, key, first) != ErrSecurityBaseline || f.engine.confirmBaselineOriginalReceipt(d, key, second) != nil {
				t.Fatal("closing one owner closed another or released proof retained authority")
			}
			borrowed := *second
			receipt := *second.receipt
			receipt.pin = nil
			borrowed.receipt = &receipt
			if !sameBaselineOriginalReceipt(borrowed.receipt, second.receipt) || f.engine.confirmBaselineOriginalReceipt(d, key, &borrowed) != ErrSecurityBaseline {
				t.Fatal("equal evidence without an original descriptor supplied authority")
			}
			for _, fault := range []string{"identity", "body", "nil-body", "missing"} {
				receipt := *second.receipt
				switch fault {
				case "identity":
					receipt.identity = first.receipt.identity
					// Obtain a genuinely different inode/content identity.
					other, err := f.engine.files.CreateExclusive("distinct-receipt.json", []byte("{}"))
					if err != nil {
						t.Fatal("distinct test identity unavailable")
					}
					receipt.identity = other
				case "body":
					receipt.body = append(bytes.Clone(receipt.body), '\n')
				case "nil-body":
					receipt.body = nil
				}
				candidate := &receipt
				if fault == "missing" {
					candidate = nil
				}
				if sameBaselineOriginalReceipt(second.receipt, candidate) {
					t.Fatal("receipt evidence comparison dropped an original field")
				}
			}
			if sameBaselineOriginalReceipt(&baselineOriginalReceipt{body: nil}, &baselineOriginalReceipt{body: []byte{}}) {
				t.Fatal("receipt equality erased nil versus empty body")
			}
		})
	}
}

func TestBaselineOriginalReceiptRepeatedReplacementAndFailureRelease(t *testing.T) {
	for _, parent := range []bool{false, true} {
		name := "metadata"
		if parent {
			name = "parent"
		}
		t.Run(name, func(t *testing.T) {
			f, d, key, live := testBaselinePendingReceipt(t, parent)
			name := "create-" + d.Pending.CreateNonce + ".json"
			before := testBaselineReceiptDescriptors(t, name)
			for range 32 {
				object, err := f.engine.originalBaselineObject(d, key, live)
				t.Cleanup(object.release)
				if err != nil || object == nil || testBaselineReceiptDescriptors(t, name) != before+1 || f.engine.confirmBaselineOriginalReceipt(d, key, object) != nil {
					t.Fatal("successful acquisition did not own exactly one original descriptor")
				}
				object.release()
				if testBaselineReceiptDescriptors(t, name) != before {
					t.Fatal("successful receipt ownership leaked a descriptor")
				}
				foreign := live.DeepCopy()
				foreign.SetUID("foreign-pending-receipt")
				rejected, err := f.engine.originalBaselineObject(d, key, foreign)
				if err != ErrSecurityBaseline || rejected != nil || testBaselineReceiptDescriptors(t, name) != before {
					t.Fatal("post-pin validation refusal leaked a descriptor")
				}
			}
			original, err := f.engine.originalBaselineObject(d, key, live)
			t.Cleanup(original.release)
			if err != nil || original == nil {
				t.Fatal("opening original descriptor unavailable")
			}
			body, identity, err := f.engine.files.Read(name, 4096)
			if err != nil {
				t.Fatal("test-owned receipt read unavailable")
			}
			for range 64 {
				identity, err = f.engine.files.AtomicWrite(name, body, &identity)
				if err != nil || f.engine.confirmBaselineOriginalReceipt(d, key, original) != ErrSecurityBaseline || testBaselineReceiptDescriptors(t, name) != before+1 {
					t.Fatal("repeated identical replacement revived original receipt authority")
				}
			}
			original.release()
			if testBaselineReceiptDescriptors(t, name) != before {
				t.Fatal("unlinked original descriptor was not released")
			}
		})
	}
}

func TestBaselineParentIndependentReceiptOwnersPreserveWholeEvidence(t *testing.T) {
	f, d, key, live := testBaselinePendingReceipt(t, true)
	first, err := f.engine.originalBaselineParent(d, key, live)
	t.Cleanup(first.release)
	if err != nil || first == nil {
		t.Fatal("original parent unavailable")
	}
	second, err := f.engine.originalBaselineParent(d, key, live)
	t.Cleanup(second.release)
	if err != nil || second == nil {
		t.Fatal("independent original parent unavailable")
	}
	a, b := map[string]*baselineParent{key.Name: first}, map[string]*baselineParent{key.Name: second}
	if !sameBaselineParents(a, b) || f.engine.confirmBaselineParentReceipts(d, a) != nil || f.engine.confirmBaselineParentReceipts(d, b) != nil {
		t.Fatal("independent parent handles could not compare and confirm")
	}
	first.release()
	if !sameBaselineParents(a, b) || f.engine.confirmBaselineParentReceipts(d, a) != ErrSecurityBaseline || f.engine.confirmBaselineParentReceipts(d, b) != nil {
		t.Fatal("released parent witness supplied authority or closed independent owner")
	}
	for _, fault := range []string{"whole", "typed", "missing", "nil-parent"} {
		copy := *second
		copy.whole = second.whole.DeepCopy()
		copy.parent = second.parent.DeepCopy()
		candidate := map[string]*baselineParent{key.Name: &copy}
		switch fault {
		case "whole":
			copy.whole.SetResourceVersion("18")
		case "typed":
			copy.parent.ResourceVersion = "18"
		case "missing":
			delete(candidate, key.Name)
		case "nil-parent":
			candidate[key.Name] = nil
		}
		if sameBaselineParents(b, candidate) {
			t.Fatal("parent semantic equality omitted original evidence")
		}
	}
}
