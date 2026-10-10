// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

// This purpose only strengthens pre-proof observation for the ordinary
// controller started by the closed lifecycle. It grants no mutation authority,
// skips no baseline proof, and cannot be reconstructed by public recovery.
type lifecycleControllerPreparation struct {
	lifecycle *Lifecycle
	checks    *clusterLifecycleChecks
	original  *installstate.Snapshot
	intent    *installstate.Snapshot
	pending   installstate.Pending
	key       installstate.Key
	digest    string
	hash      string
}

func (l *Lifecycle) applyTarget(ctx context.Context, s *installstate.Snapshot, key installstate.Key, digest string) (*installstate.Snapshot, error) {
	if l == nil || l.engine == nil || s == nil {
		return s, ErrInvalid
	}
	checks, closed := l.checks.(*clusterLifecycleChecks)
	d := s.Document()
	if !closed || l.engine.baseline == nil || d.Stage != installstate.Applying || key != deploymentKey(d.Namespace, "arcadectl-controller") {
		return l.engine.Apply(ctx, s, key, digest, false)
	}
	t, err := l.engine.desired(d, key, digest, false)
	if err != nil {
		return s, err
	}
	purpose := &lifecycleControllerPreparation{lifecycle: l, checks: checks, original: s, key: key, digest: digest, hash: t.Hash()}
	return l.engine.applyPrepared(ctx, s, key, digest, false, nil, purpose)
}

func (p *lifecycleControllerPreparation) validOriginal(e *Engine, s *installstate.Snapshot, key installstate.Key, digest string, paused bool) bool {
	if p == nil || e == nil || e.baseline == nil || p.lifecycle == nil || p.lifecycle.engine != e || p.checks == nil || p.lifecycle.checks != p.checks || p.checks.prerequisites == nil || p.checks.prerequisites.engine != e || p.checks.prerequisites.access != e.access || p.original == nil || p.original != s || p.intent != nil || paused || key != p.key || digest != p.digest {
		return false
	}
	d := s.Document()
	if d.Stage != installstate.Applying || d.Pending != nil || key != deploymentKey(d.Namespace, "arcadectl-controller") || digest != d.TargetPackage {
		return false
	}
	t, err := e.desired(d, key, digest, false)
	return err == nil && t.Hash() == p.hash
}

// Bind the purpose to the actual single intent CAS, not an equivalent replayed
// snapshot, another revision, another template, or a restarted invocation.
func (p *lifecycleControllerPreparation) bindIntent(e *Engine, s *installstate.Snapshot, pending *installstate.Pending) (*lifecycleControllerPreparation, error) {
	if p == nil || s == nil || !p.validOriginal(e, p.original, p.key, p.digest, false) {
		return nil, ErrOutcomeUnknown
	}
	d := s.Document()
	if pending == nil || !reflect.DeepEqual(d.Pending, pending) || d.Pending.Key != p.key || d.Pending.AfterSHA256 != p.hash || d.Pending.Action != installstate.Create && d.Pending.Action != installstate.Update || s.Anchor() != p.original.Anchor() {
		return nil, ErrOutcomeUnknown
	}
	want := p.original.Document()
	want.Revision++
	want.Pending = d.Pending
	if !reflect.DeepEqual(want, d) {
		return nil, ErrOutcomeUnknown
	}
	bound := *p
	bound.intent = s
	bound.pending = *pending
	return &bound, nil
}

func (p *lifecycleControllerPreparation) validIntent(e *Engine, s *installstate.Snapshot) bool {
	if p == nil || p.intent == nil || p.intent != s {
		return false
	}
	original := *p
	original.intent = nil
	bound, err := original.bindIntent(e, s, &p.pending)
	return err == nil && bound.intent == p.intent
}
