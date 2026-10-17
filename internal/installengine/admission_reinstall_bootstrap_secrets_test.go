// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/runtime"
	clienttest "k8s.io/client-go/testing"
)

// Real protected source/Begin/stage CAS and original Secret format validation;
// enrollment, policy health and lifecycle proof provider are synthetic. These
// tests do not certify admission, cold worlds, effects or native reinstall.
func retainedBootstrapSecretFixture(t *testing.T) (*lifecycleFixture, *installstate.Snapshot, string, string) {
	t.Helper()
	v, source := reinstallReceiptLifecycleFixture(t)
	f := v.f
	published, err := f.engine.saveReinstallSource(source)
	if err != nil {
		t.Fatal("original bootstrap source unavailable")
	}
	provenance, sourceName, retirementName := published.provenance, published.name, published.retirement.name
	published.release()
	d := source.Document()
	d.Revision++
	d.Mode, d.Stage, d.AdmissionRetirementRevision = installstate.Install, installstate.Preparing, 0
	d.AdmissionReinstall = &provenance
	current, err := f.store.Commit(t.Context(), source, d)
	if err != nil {
		t.Fatal("genuine retained Preparing journal CAS unavailable")
	}
	workflow, err := NewSecretWorkflow(f.engine, v.private)
	if err != nil {
		t.Fatal("retained private workflow unavailable")
	}
	v.l, err = NewLifecycleWithChecks(f.engine, workflow, v)
	if err != nil {
		t.Fatal("retained lifecycle fixture unavailable")
	}
	f.snapshot = current
	return v, current, sourceName, retirementName
}

func TestAdmissionReinstallBootstrapSecretsOwnOriginalsThroughStageCAS(t *testing.T) {
	for _, scenario := range []string{"healthy", "actual-step", "late-secret-uid", "late-secret-rv", "late-secret-data", "closing-ca", "closing-source", "closing-retirement", "released-owner", "nil-context", "missing-pin"} {
		t.Run(scenario, func(t *testing.T) {
			v, current, sourceName, retirementName := retainedBootstrapSecretFixture(t)
			f, caFile := v.f, v.opts.Activation.CAFile
			writes, nsWrites, secretWrites := f.access.writes, f.nsUpdates, v.private.writes
			before := bytes.Clone(current.Bytes())
			if scenario == "actual-step" {
				returned, err := v.l.Step(t.Context(), current, v.opts)
				if err != nil || returned == nil || returned.Document().Stage != installstate.Applying || returned.Document().Revision != current.Document().Revision+1 || !reflect.DeepEqual(returned.Document().Resources, current.Document().Resources) || f.nsUpdates != nsWrites+1 {
					t.Fatal("actual Preparing Step could not verify retained Secrets without installed access")
				}
				if f.access.writes != writes || v.private.writes != secretWrites || f.engine.baseline.runtimeGuard != nil || testBaselineReceiptDescriptors(t, sourceName) != 0 || testBaselineReceiptDescriptors(t, retirementName) != 0 || testBaselineReceiptDescriptors(t, filepath.Base(caFile)) != 0 {
					t.Fatal("Preparing Step issued an effect, supplied runtime authority or leaked original evidence")
				}
				return
			}
			owned, err := v.l.secrets.openRetainedBootstrapSecrets(t.Context(), current, caFile, v.opts.Now)
			if err != nil {
				t.Fatal("healthy original retained Secret owner refused")
			}
			defer owned.release()
			if testBaselineReceiptDescriptors(t, sourceName) != 1 || testBaselineReceiptDescriptors(t, retirementName) != 1 || testBaselineReceiptDescriptors(t, filepath.Base(caFile)) != 1 {
				t.Fatal("bootstrap owner did not hold source, retirement and original CA")
			}
			faultHit := false
			switch scenario {
			case "late-secret-uid":
				v.private.objects["arcadectl-api-tls"].UID = "foreign-secret"
				faultHit = true
			case "late-secret-rv":
				v.private.objects["arcadectl-api-tls"].ResourceVersion += "1"
				faultHit = true
			case "late-secret-data":
				v.private.objects["arcadectl-api-tls"].Data["tls.crt"] = []byte("invalid-certificate")
				faultHit = true
			case "released-owner":
				owned.release()
				faultHit = true
			case "missing-pin":
				d := current.Document()
				d.AdmissionReinstall = nil
				current = prerequisiteSnapshotFixture(t, f, d)
				faultHit = true
			}
			if scenario == "closing-ca" || scenario == "closing-source" || scenario == "closing-retirement" {
				secretReads, closingReads := 0, 0
				v.private.get = func(string) error { secretReads++; return nil }
				f.access.client.PrependReactor("get", "namespaces", func(clienttest.Action) (bool, runtime.Object, error) {
					if secretReads == 2 {
						closingReads++
						// verify's closing original uses reads1–2; stage's final
						// original starts at read3, AFTER the helper returned.
						if closingReads == 3 {
							if testBaselineReceiptDescriptors(t, sourceName) != 1 || testBaselineReceiptDescriptors(t, retirementName) != 1 || testBaselineReceiptDescriptors(t, filepath.Base(caFile)) != 1 {
								t.Error("stage final fence lost its outer original evidence owner")
							}
							files, name := f.engine.files, sourceName
							if scenario == "closing-retirement" {
								name = retirementName
							} else if scenario == "closing-ca" {
								var err error
								files, err = privatefs.Open(filepath.Dir(caFile), false)
								if err != nil {
									t.Error("test-owned CA directory unavailable")
									return false, nil, nil
								}
								defer files.Close()
								name = filepath.Base(caFile)
							}
							body, identity, err := files.Read(name, retirementMaxBytes)
							if err != nil {
								t.Error("test-owned original evidence unreadable")
								return false, nil, nil
							}
							for range 2 {
								identity, err = files.AtomicWrite(name, body, &identity)
								if err != nil {
									t.Error("test-owned evidence replacement failed")
									return false, nil, nil
								}
							}
							faultHit = true
						}
					}
					return false, nil, nil
				})
			}
			ctx := t.Context()
			if scenario == "nil-context" {
				ctx = nil
				faultHit = true
			}
			returned, err := v.l.stageOwned(ctx, current, installstate.Applying, owned)
			if scenario == "healthy" {
				if err != nil || returned.Document().Stage != installstate.Applying || f.nsUpdates != nsWrites+1 || !reflect.DeepEqual(returned.Document().Resources, current.Document().Resources) {
					t.Fatal("owned retained Preparing stage refused or altered original inventory")
				}
			} else if err == nil || !faultHit || f.nsUpdates != nsWrites || !bytes.Equal(returned.Bytes(), current.Bytes()) {
				t.Fatal("stage accepted invalid original evidence, mutated state, or missed its final-window fault")
			}
			owned.release()
			if f.access.writes != writes || v.private.writes != secretWrites || !bytes.Equal(before, f.snapshot.Bytes()) || testBaselineReceiptDescriptors(t, sourceName) != 0 || testBaselineReceiptDescriptors(t, retirementName) != 0 || testBaselineReceiptDescriptors(t, filepath.Base(caFile)) != 0 {
				t.Fatal("owned Secret proof generated credentials, changed source or leaked descriptors")
			}
		})
	}
}
