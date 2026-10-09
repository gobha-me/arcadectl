// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
)

const baselineRuntimeTimeout = 15 * time.Minute

// Verify dispatches only between the complete live behavioral proof and the
// distinct original-retirement proof. It never enters current(), effective
// admission, persistent fixture generation or effect/recovery authorization. Fresh and
// retained-reinstall nonexecuting bootstrap are separate protocols, not an
// exception selected by stage or a missing actor. Closed production composition
// installs this full provider; incomplete access never becomes runtime authority.
func (c *ClusterSecurityBaseline) Verify(ctx context.Context, snapshot *installstate.Snapshot) error {
	if c == nil || c.engine == nil || c.engine.baseline == nil || !c.engine.baselinePlan().IsTrusted() || c.engine.journal == nil || c.engine.journal.BaselineDigest() != c.engine.baselinePlan().Digest() ||
		c.access == nil || c.access.native == nil || c.engine.access != c.access || !c.access.actorCompatible() ||
		ctx == nil || ctx.Err() != nil || snapshot == nil {
		return ErrSecurityBaseline
	}
	// One finite deadline covers construction AND the full proof. Shorter
	// component deadlines remain in force; an earlier caller deadline wins.
	ctx, cancel := context.WithTimeout(ctx, baselineRuntimeTimeout)
	defer cancel()
	d := snapshot.Document()
	if d.SecurityBaseline == nil || d.SecurityBaseline.Version != installbaseline.Version || d.SecurityBaseline.ArtifactDigest != c.engine.baselinePlan().Digest() ||
		d.SecurityBaseline.Stage != installstate.BaselineVerified || d.SecurityBaseline.Pending != nil {
		return ErrSecurityBaseline
	}
	var source *reinstallSourceWitness
	if d.AdmissionReinstall != nil {
		var err error
		source, err = c.engine.openReinstallSource(snapshot)
		if err != nil {
			return ErrSecurityBaseline
		}
		defer source.release()
	}
	if d.AdmissionRetirementRevision != 0 {
		if d.Mode != installstate.Uninstall {
			return ErrSecurityBaseline
		}
		return c.verifyRetiredRuntime(ctx, snapshot)
	}
	if !c.engine.baselineObservable(d) {
		return ErrSecurityBaseline
	}
	behavior, err := c.newBaselineBehavior(ctx, snapshot)
	if err != nil {
		return ErrSecurityBaseline
	}
	defer behavior.release()
	if behavior.prove(ctx) != nil || ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	if source != nil && c.engine.closeReinstallSource(source) != nil {
		return ErrSecurityBaseline
	}
	if ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

var _ baselineRuntimeGuard = (*ClusterSecurityBaseline)(nil)
