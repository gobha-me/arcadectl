// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Verification-only original-Secret/canonical journal tests over explicitly
// synthetic baseline health, not native admission or full reinstall proof.
func TestAdmissionReinstallCompletedRetirementSecretsKeepOriginalScope(t *testing.T) {
	for _, scenario := range []string{"healthy", "replaced-secret", "expired", "wrong-ca", "closing-ca-replacement", "receipt-replacement", "nil-context", "cancelled", "zero-time", "stale-journal"} {
		t.Run(scenario, func(t *testing.T) {
			v, snapshot := reinstallReceiptLifecycleFixture(t)
			f := v.f
			workflow, err := NewSecretWorkflow(f.engine, v.private)
			if err != nil {
				t.Fatal("verification-only retained Secret reader unavailable")
			}
			before, rv := snapshot.Bytes(), snapshot.ResourceVersion()
			writes, namespaceWrites, secretWrites := f.access.writes, f.nsUpdates, v.private.writes
			ctx, now, ca := t.Context(), v.opts.Now, v.opts.Activation.CAFile
			caReplaced := false
			switch scenario {
			case "replaced-secret":
				v.private.objects["arcadectl-api-tls"].UID = "same-name-new-secret"
			case "expired":
				now = now.Add(2 * time.Hour)
			case "wrong-ca":
				ca = fixtureTLS(t, snapshot.Document().Namespace, now).CAFile
			case "closing-ca-replacement":
				files, err := privatefs.Open(filepath.Dir(ca), false)
				if err != nil {
					t.Fatal("test-owned CA directory unavailable")
				}
				t.Cleanup(func() { _ = files.Close() })
				v.private.get = func(string) error {
					name := filepath.Base(ca)
					body, identity, err := files.Read(name, 65536)
					if err != nil {
						return ErrCredentials
					}
					if _, err := files.AtomicWrite(name, body, &identity); err != nil {
						return ErrCredentials
					}
					caReplaced = true // Valid CA bytes, changed original inode.
					return nil
				}
			case "receipt-replacement":
				v.private.get = func(string) error {
					name := retirementName(snapshot.Document(), snapshot.Document().AdmissionRetirementRevision)
					body, identity, err := f.engine.files.Read(name, retirementMaxBytes)
					if err != nil {
						return ErrRead
					}
					_, err = f.engine.files.AtomicWrite(name, body, &identity)
					return err
				}
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(t.Context())
				cancel()
			case "zero-time":
				now = time.Time{}
			case "stale-journal":
				d := snapshot.Document()
				d.Revision++
				body := mustReinstallJournal(t, f.engine, d)
				if bytes.Equal(body, before) {
					t.Fatal("stale source test did not alter journal bytes")
				}
				namespace, err := f.access.client.CoreV1().Namespaces().Get(t.Context(), d.Namespace, metav1.GetOptions{})
				if err != nil {
					t.Fatal("original namespace test opening unavailable")
				}
				namespace.Annotations[installstate.Annotation] = string(body)
				namespace.ResourceVersion = "999"
				if f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), namespace, "") != nil {
					t.Fatal("test-only concurrent journal drift seed failed")
				}
				before, rv = body, "999" // Deliberate external fixture drift, not a workflow write.
			}
			err = workflow.verifyCompletedRetirementSecrets(ctx, snapshot, ca, now)
			if scenario == "healthy" {
				if err != nil {
					t.Fatal("genuine completed retirement could not verify original Secrets")
				}
			} else if err == nil {
				t.Fatal("invalid completed-retirement Secret evidence passed")
			}
			if scenario == "closing-ca-replacement" && !caReplaced {
				t.Fatal("closing CA identity regression never reached the replacement")
			}
			if workflow.VerifyRetained(t.Context(), snapshot, ca, now) == nil {
				t.Fatal("read-only retired Secret route broadened ordinary current eligibility")
			}
			if f.engine.compatible(snapshot.Document()) {
				t.Fatal("genuine completed-Uninstall mutation compatibility was broadened")
			}
			fresh, err := f.store.Load(t.Context(), snapshot.Anchor())
			if err != nil || !bytes.Equal(fresh.Bytes(), before) || fresh.ResourceVersion() != rv || f.access.writes != writes || f.nsUpdates != namespaceWrites || v.private.writes != secretWrites || f.engine.baseline.runtimeGuard != nil {
				t.Fatal("verification-only Secret route mutated journal/resources/credentials or wired authority")
			}
			if snapshot.Document().Mode != installstate.Uninstall || snapshot.Document().Installed {
				t.Fatal("completed retirement state was relabelled for Secret observation")
			}
		})
	}
}
