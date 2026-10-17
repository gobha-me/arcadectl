// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

// Genuine completed legacy uninstall with explicit synthetic baseline
// enrollment tests refusals before the new actual Begin CAS. This is not a
// successful native Begin, access recreation or full reinstall lifecycle.
func TestAdmissionReinstallBeginRequiresClosedProviderBeforeCAS(t *testing.T) {
	v, snapshot := reinstallReceiptLifecycleFixture(t)
	f := v.f
	secrets, err := NewSecretWorkflow(f.engine, v.private)
	if err != nil {
		t.Fatal("retained Secret verification setup failed")
	}
	lifecycle, err := NewLifecycleWithChecks(f.engine, secrets, v)
	if err != nil {
		t.Fatal("Begin refusal lifecycle setup failed")
	}
	body, rv := snapshot.Bytes(), snapshot.ResourceVersion()
	writes, namespaceWrites, secretWrites, checks := f.access.writes, f.nsUpdates, v.private.writes, len(v.checks)
	for _, provider := range []*ClusterSecurityBaseline{nil, {engine: &Engine{}}, {engine: f.engine}} {
		f.engine.baseline.prerequisites = provider
		returned, err := lifecycle.Begin(t.Context(), snapshot, installstate.Install, f.plan.Digest(), v.opts)
		if err != ErrSecurityBaseline || returned == nil || !bytes.Equal(returned.Bytes(), body) || returned.ResourceVersion() != rv {
			t.Fatal("incomplete provider permitted retained reinstall Begin")
		}
	}
	fresh, err := f.store.Load(t.Context(), snapshot.Anchor())
	if err != nil || !bytes.Equal(fresh.Bytes(), body) || fresh.ResourceVersion() != rv || f.access.writes != writes || f.nsUpdates != namespaceWrites || v.private.writes != secretWrites || len(v.checks) != checks || fresh.Document().AdmissionReinstall != nil || f.engine.baseline.runtimeGuard != nil {
		t.Fatal("refused Begin created authority, mutated journal/Secrets or entered caller proof callbacks")
	}
	name, err := reinstallSourceName(snapshot.Anchor().InstallationID, snapshot.Document().Revision)
	if err != nil {
		t.Fatal("fixed original source path unavailable")
	}
	if _, _, err := f.engine.files.Read(name, reinstallReceiptMaxBytes); err != privatefs.ErrNotFound {
		t.Fatal("incomplete provider published source evidence before whole retired proof")
	}
}
