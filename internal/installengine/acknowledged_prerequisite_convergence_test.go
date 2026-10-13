// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Synthetic access and durable original journal/receipt fixtures exercise ONLY
// ACK preparation. The complete production proof and CAS are tested separately.
func TestAcknowledgedPrerequisiteQuietnessPreservesOriginalIntent(t *testing.T) {
	for _, scenario := range []string{"quiet", "status-rv-converges", "continuous-churn", "cancelled", "uid", "nonce", "spec", "generation", "receipt", "journal", "nil-ack", "foreign-ack", "unacknowledged-receipt", "wrong-kind"} {
		t.Run(scenario, func(t *testing.T) {
			f := newBaselineFixture(t)
			completeBaselineFixture(t, f)
			key := (&Lifecycle{engine: f.engine}).ordered(f.snapshot.Document())[0]
			if scenario == "wrong-kind" {
				for _, r := range f.plan.ResourceMetadata() {
					if r.Kind == "ServiceAccount" {
						key = installstate.Key{APIVersion: r.APIVersion, Kind: r.Kind, Namespace: r.Namespace, Name: r.Name}
						break
					}
				}
			}
			template, err := f.engine.contracts[f.plan.Digest()].Template(key, false)
			if err != nil {
				t.Fatal("original template unavailable")
			}
			d := f.snapshot.Document()
			d.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("c", 32), AfterSHA256: template.Hash()}
			f.snapshot = prerequisiteSnapshotFixture(t, f, d)
			ack, err := template.Candidate(d.Pending.CreateNonce)
			if err != nil {
				t.Fatal("original ACK fixture unavailable")
			}
			ack.SetUID("acknowledged-original")
			ack.SetResourceVersion("43")
			ack.SetGeneration(1)
			if key.Kind == "CustomResourceDefinition" {
				if unstructured.SetNestedMap(ack.Object, map[string]any{"strategy": "None"}, "spec", "conversion") != nil {
					t.Fatal("native CRD default unavailable")
				}
			}
			f.access.objects[key] = ack.DeepCopy()
			if f.engine.prepareCreateReceipt(f.snapshot.Document()) != nil || scenario != "unacknowledged-receipt" && f.engine.saveCreateUID(f.snapshot.Document(), ack.GetUID()) != nil {
				t.Fatal("original protected receipt unavailable")
			}
			operation, err := f.engine.prerequisiteOperation(f.snapshot, key, f.plan.Digest())
			if err != nil {
				t.Fatal("original operation unavailable")
			}
			receipt, err := f.engine.openPrerequisiteReceipt(f.snapshot, operation)
			if err != nil {
				t.Fatal("original receipt owner unavailable")
			}
			defer receipt.release()
			before := bytes.Clone(f.snapshot.Bytes())
			writes, previews, gets := f.access.writes, f.access.dryRuns, 0
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if scenario == "continuous-churn" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 650*time.Millisecond)
				defer cancel()
			}
			if scenario == "cancelled" {
				cancel()
			}
			f.access.get = func(k installstate.Key) error {
				if k != key {
					return nil
				}
				gets++
				o := f.access.objects[key]
				switch scenario {
				case "status-rv-converges", "continuous-churn":
					if gets <= 3 || scenario == "continuous-churn" {
						o.SetResourceVersion(strconv.Itoa(43 + gets))
						o.Object["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Established", "status": "True"}}}
					}
				case "uid":
					o.SetUID("replacement")
				case "nonce":
					o.SetAnnotations(map[string]string{installstate.MutationAnnotation: strings.Repeat("d", 32)})
				case "spec":
					_ = unstructured.SetNestedField(o.Object, "foreign.example", "spec", "group")
				case "generation":
					o.SetGeneration(2)
				case "receipt":
					name := "create-" + f.snapshot.Document().Pending.CreateNonce + ".json"
					body, identity, err := f.engine.files.Read(name, 4096)
					if err != nil {
						t.Fatal("test-owned original receipt unavailable")
					}
					if _, err := f.engine.files.AtomicWrite(name, body, &identity); err != nil {
						t.Fatal("test-owned identical receipt replacement failed")
					}
				case "journal":
					changed := f.snapshot.Document()
					changed.Revision++
					prerequisiteSnapshotFixture(t, f, changed)
				}
				return nil
			}
			if scenario == "nil-ack" {
				ack = nil
			}
			if scenario == "foreign-ack" {
				ack.SetUID("foreign")
			}
			err = f.engine.prepareAcknowledgedPrerequisite(ctx, f.snapshot, ack, operation, receipt)
			if scenario == "quiet" || scenario == "status-rv-converges" {
				if err != nil || gets < 6 || f.engine.confirmPrerequisiteReceipt(f.snapshot, operation, receipt) != nil {
					t.Fatal("original CRD did not become quietly observed", err, gets)
				}
			} else if !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("unsafe or unquiet original acquired preparation", err)
			}
			if !bytes.Equal(before, f.snapshot.Bytes()) || f.access.writes != writes || f.access.dryRuns != previews {
				t.Fatal("read-only preparation changed intent or replayed an effect")
			}
			receipt.release()
			if testBaselineReceiptDescriptors(t, "create-"+d.Pending.CreateNonce+".json") != 0 {
				t.Fatal("preparation owner leaked its original receipt")
			}
		})
	}
}
