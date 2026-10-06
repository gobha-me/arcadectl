// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import "context"

// PinnedAnchor returns only the original identity from an unchanged, durable
// private bootstrap receipt. It neither contacts Kubernetes nor creates a
// local lock file, repairs a receipt, binds a journal or regenerates a candidate.
// The receiver retains its ORIGINAL trusted bootstrap plan after upgrades;
// callers must independently validate the current Namespace and live journal.
// A pinned ACK UID alone is not proof that its Namespace shape was accepted.
// As with EnsureNamespace, each receipt instance has a single workflow owner.
func (r *BootstrapReceipt) PinnedAnchor(ctx context.Context) (Anchor, error) {
	if r == nil || r.store == nil || ctx == nil || !r.plan.IsTrusted() || !receiptName.MatchString(r.name) {
		return Anchor{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return Anchor{}, ErrOwnership
	}
	body, identity, err := r.store.Read(r.name, MaxBytes)
	if err != nil {
		return Anchor{}, privateError(err)
	}
	if identity != r.identity {
		return Anchor{}, ErrConflict
	}
	d, err := decodeBootstrap(body, r.plan)
	if err != nil {
		return Anchor{}, err
	}
	if d != r.document {
		return Anchor{}, ErrConflict
	}
	if err := r.store.ConfirmDurable(r.name, identity); err != nil {
		return Anchor{}, privateError(err)
	}
	if ctx.Err() != nil {
		return Anchor{}, ErrOwnership
	}
	if d.NamespaceUID == "" || !d.CreateAttempted {
		return Anchor{}, ErrOutcomeUnknown
	}
	return Anchor{Namespace: d.Namespace, UID: d.NamespaceUID, InstallationID: d.InstallationID}, nil
}
