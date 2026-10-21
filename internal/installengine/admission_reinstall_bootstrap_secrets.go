// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"slices"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
)

// Verification-only ownership at the lifecycle boundary. No credential objects
// escape this private witness; it does not authorize a workload, Secret effect,
// Service, UPDATE, DELETE or world mutation. The complete current cold/GC proof
// remains mandatory for each original signed access CREATE and its recovery.
type retainedBootstrapSecrets struct {
	workflow *SecretWorkflow
	source   *reinstallSourceWitness
	caPin    *privatefs.FilePin
	caID     privatefs.FileIdentity
	caFile   string
	now      time.Time
	objects  map[string]*corev1.Secret
}

func (w *retainedBootstrapSecrets) release() {
	if w != nil {
		_ = w.caPin.Close()
		w.source.release()
		w.objects = nil
	}
}

// Selection only, never authority: the owned source and closed signed union
// are authenticated separately. Once a Service/executor exists, use ordinary
// full installed-state verification, not this bootstrap reader.
func retainedBootstrapPhase(d installstate.Document) bool {
	if d.Mode != installstate.Install || d.ActivePackage == "" || d.Installed || d.AdmissionRetirementRevision != 0 ||
		(d.Stage != installstate.Preparing && d.Stage != installstate.RecoveryRequired && d.Stage != installstate.Applying) {
		return false
	}
	for _, entry := range d.Resources {
		if entry.Key.Kind == "Service" || entry.Key.Kind == "Deployment" {
			return false
		}
	}
	return d.Pending == nil || d.Pending.Action == installstate.Create && accessRetirementKey(d.Pending.Key)
}

func (e *Engine) retainedBootstrapContext(s *installstate.Snapshot, source *reinstallSourceWitness) error {
	if e == nil || e.baseline == nil || s == nil || source == nil {
		return ErrSecurityBaseline
	}
	d := s.Document()
	if !retainedBootstrapPhase(d) || d.AdmissionReinstall == nil || *d.AdmissionReinstall != source.provenance || len(source.source.Resources) != 20 ||
		d.SecurityBaseline == nil || d.SecurityBaseline.Stage != installstate.BaselineVerified || d.SecurityBaseline.Pending != nil ||
		d.SecurityBaseline.ArtifactDigest != e.baselinePlan().Digest() || !reflect.DeepEqual(d.SecurityBaseline, source.source.SecurityBaseline) {
		return ErrSecurityBaseline
	}
	contract := e.contracts[d.TargetPackage]
	if contract == nil || d.ActivePackage != source.source.ActivePackage || d.TargetPackage != source.source.TargetPackage || d.Namespace != source.source.Namespace ||
		d.NamespaceUID != source.source.NamespaceUID || d.InstallationID != source.source.InstallationID || d.ProfileID != source.source.ProfileID || d.PreviousPackage != source.source.PreviousPackage {
		return ErrSecurityBaseline
	}
	for _, original := range source.source.Resources {
		entry, _ := e.inventory(d, original.Key)
		if entry == nil || *entry != original {
			return ErrSecurityBaseline
		}
	}
	for _, entry := range d.Resources {
		if original, _ := e.inventory(source.source, entry.Key); original != nil {
			continue
		}
		template, err := contract.Template(entry.Key, false)
		if err != nil || entry.Retained || !accessRetirementKey(entry.Key) || !baselinePrerequisiteKey(entry.Key, d.Namespace) ||
			entry.TemplateSHA256 != template.Hash() || entry.Phase != template.Phase() || template.Retained() {
			return ErrSecurityBaseline
		}
	}
	if d.Pending != nil {
		if _, err := e.prerequisiteOperation(s, d.Pending.Key, d.TargetPackage); err != nil {
			return ErrSecurityBaseline
		}
	}
	return e.closeReinstallSource(source)
}

func (w *SecretWorkflow) openRetainedBootstrapSecrets(ctx context.Context, s *installstate.Snapshot, caFile string, now time.Time) (*retainedBootstrapSecrets, error) {
	if w == nil || w.engine == nil || ctx == nil || ctx.Err() != nil || s == nil || now.IsZero() {
		return nil, ErrSecurityBaseline
	}
	owned := &retainedBootstrapSecrets{workflow: w, caFile: caFile, now: now}
	transferred := false
	defer func() {
		if !transferred {
			owned.release()
		}
	}()
	var err error
	owned.source, err = w.engine.openReinstallSource(s)
	if err != nil || w.engine.retainedBootstrapContext(s, owned.source) != nil {
		return nil, ErrSecurityBaseline
	}
	_, owned.caID, owned.caPin, err = privatefs.PinAbsolute(caFile, 65536, privatefs.TrustedPublic)
	if err != nil {
		return nil, ErrCredentials
	}
	if _, err := (&Lifecycle{engine: w.engine}).original(ctx, s); err != nil {
		return nil, ErrSecurityBaseline
	}
	var observedCA privatefs.FileIdentity
	owned.objects, observedCA, err = w.readRetainedObjects(ctx, s, caFile, now)
	if err != nil || observedCA != owned.caID {
		return nil, ErrCredentials
	}
	if owned.verify(ctx, s) != nil {
		return nil, ErrSecurityBaseline
	}
	transferred = true
	return owned, nil
}

// Only local confirmation here: called after each final original Namespace
// observation and immediately before intent/effect/settlement/stage edges.
func (w *retainedBootstrapSecrets) confirm(s *installstate.Snapshot) error {
	if w == nil || w.workflow == nil || w.workflow.engine == nil || w.caPin == nil || w.objects == nil ||
		w.workflow.engine.retainedBootstrapContext(s, w.source) != nil || w.caPin.Confirm() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

func (w *retainedBootstrapSecrets) verify(ctx context.Context, s *installstate.Snapshot) error {
	if ctx == nil || ctx.Err() != nil || w.confirm(s) != nil {
		return ErrSecurityBaseline
	}
	e := w.workflow.engine
	if _, err := (&Lifecycle{engine: e}).original(ctx, s); err != nil {
		return ErrSecurityBaseline
	}
	policies, err := e.retirementPolicies(ctx, s)
	if err != nil || !slices.Equal(policies, w.source.retirement.receipt.Policies) {
		return ErrSecurityBaseline
	}
	baseline, err := e.retirementBaselinePolicies(ctx, s)
	if err != nil || !slices.Equal(baseline, w.source.retirement.receipt.Baseline) {
		return ErrSecurityBaseline
	}
	for _, entry := range s.Document().Resources {
		if entry.Key.Kind == "Secret" || entry.Key.Kind == "Namespace" {
			continue
		}
		template, err := e.contracts[s.Document().TargetPackage].Template(entry.Key, false)
		live, readErr := e.access.Get(ctx, entry.Key)
		if err != nil || readErr != nil || template.MatchLive(live, entry.UID) != nil {
			return ErrSecurityBaseline
		}
	}
	objects, caID, err := w.workflow.readRetainedObjects(ctx, s, w.caFile, w.now)
	if err != nil || caID != w.caID || !reflect.DeepEqual(objects, w.objects) {
		return ErrCredentials
	}
	if _, err := (&Lifecycle{engine: e}).original(ctx, s); err != nil || ctx.Err() != nil || w.confirm(s) != nil {
		return ErrSecurityBaseline
	}
	return nil
}
