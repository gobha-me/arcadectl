// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import "github.com/gobha-me/arcadectl/internal/installstate"

// baselineObservable is eligibility for READ-only baseline evidence, not
// mutation authority or a security proof. Complete snapshots keep their real
// Mode, Installed flag and package history. Effect eligibility, desired-action
// derivation and journal transition validation deliberately keep compatible.
// Completed retirement has its own provenance-bound proof and is not admitted
// by this active-runtime predicate.
func (e *Engine) baselineObservable(d installstate.Document) bool {
	if e == nil {
		return false
	}
	if d.Stage != installstate.Complete {
		return e.compatible(d)
	}
	target, previous := e.plans[d.TargetPackage], e.plans[d.PreviousPackage]
	if !d.Installed || d.Pending != nil || d.AdmissionRetirementRevision != 0 || d.ActivePackage != d.TargetPackage ||
		!target.IsTrusted() || target.Digest() != d.TargetPackage || target.Namespace() != d.Namespace || target.Profile().ID != d.ProfileID {
		return false
	}
	if d.PreviousPackage != "" && (!previous.IsTrusted() || previous.Digest() != d.PreviousPackage || previous.Namespace() != d.Namespace || previous.Profile().ID != d.ProfileID || d.PreviousPackage == d.TargetPackage) {
		return false
	}
	switch d.Mode {
	case installstate.Install:
		return true // Retained reinstall may legitimately preserve older history.
	case installstate.Upgrade:
		return previous != nil && predecessor(target, previous)
	case installstate.Rollback:
		return previous != nil && predecessor(previous, target)
	}
	return false
}
