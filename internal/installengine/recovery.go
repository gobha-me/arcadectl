// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

var ErrRecovery = errors.New("original installation recovery observation is unproved; preserve receipts and retained worlds")

// RecoveryReporter reads only the original Namespace/journal and every current
// PVC. It needs no surviving controller, ServiceAccount, admission fixture,
// domain CRD or Secret. It is not a LifecycleChecks provider or mutation grant.
type RecoveryReporter struct {
	engine *Engine
	access *HTTPAccess
}

func NewRecoveryReporter(engine *Engine, access *HTTPAccess) (*RecoveryReporter, error) {
	if engine == nil || access == nil || engine.access != access || engine.journal == nil || access.frozen == nil || len(engine.plans) == 0 {
		return nil, ErrInvalid
	}
	return &RecoveryReporter{engine, access}, nil
}

// RecoveryReport exposes only an allowlisted, bounded JSON document. Raw PVC
// objects, annotations, labels, owner references, specs, Secret values, private
// paths and transport diagnostics are never returned by this public formatter.
type RecoveryReport struct{ body []byte }

func (r *RecoveryReport) Bytes() []byte {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.body)
}

type recoveryClaim struct {
	Name            string    `json:"name"`
	UID             types.UID `json:"uid"`
	ResourceVersion string    `json:"resourceVersion"`
	VolumeName      string    `json:"volumeName"`
	Phase           string    `json:"phase"`
	Deleting        bool      `json:"deleting"`
}

type recoveryPending struct {
	Action    installstate.Action `json:"action"`
	Key       installstate.Key    `json:"key"`
	BeforeUID types.UID           `json:"beforeUid"`
}

type recoveryDocument struct {
	Version               string             `json:"version"`
	Namespace             string             `json:"namespace"`
	NamespaceUID          types.UID          `json:"namespaceUid"`
	InstallationID        string             `json:"installationId"`
	ProfileID             string             `json:"profileId"`
	Revision              uint64             `json:"revision"`
	Mode                  installstate.Mode  `json:"mode"`
	Stage                 installstate.Stage `json:"stage"`
	Installed             bool               `json:"installed"`
	ActivePackage         string             `json:"activePackage"`
	TargetPackage         string             `json:"targetPackage"`
	PreviousPackage       string             `json:"previousPackage"`
	Pending               *recoveryPending   `json:"pending,omitempty"`
	ClaimsResourceVersion string             `json:"claimsResourceVersion"`
	Claims                []recoveryClaim    `json:"claims"`
	Guidance              []string           `json:"guidance"`
}

// Collect uses a durable ORIGINAL bootstrap receipt (which may predate all
// currently registered packages) without calling EnsureNamespace or repairing
// private state. Each receipt has one workflow owner. Repeated observations
// detect drift but are not an atomic storage snapshot or a deletion permission.
func (r *RecoveryReporter) Collect(ctx context.Context, receipt *installstate.BootstrapReceipt) (*RecoveryReport, error) {
	if r == nil || r.engine == nil || r.access == nil || r.engine.access != r.access || r.access.frozen == nil || ctx == nil || receipt == nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	anchor, err := receipt.PinnedAnchor(ctx)
	if err != nil {
		return nil, ErrRecovery
	}
	s, err := r.engine.journal.Load(ctx, anchor)
	if err != nil {
		return nil, ErrRecovery
	}
	lifecycle := &Lifecycle{engine: r.engine}
	if _, err := lifecycle.original(ctx, s); err != nil {
		return nil, ErrRecovery
	}
	plan := r.engine.plans[s.Document().TargetPackage]
	observer, err := installobserve.New(r.access.frozen, r.engine.journal, plan)
	if err != nil {
		return nil, ErrRecovery
	}
	first, err := observer.CollectClaims(ctx, anchor)
	if err != nil || first == nil || !sameRecoveryJournal(s, first.Journal()) {
		return nil, ErrRecovery
	}
	if _, err := lifecycle.original(ctx, s); err != nil {
		return nil, ErrRecovery
	}
	second, err := observer.CollectClaims(ctx, anchor)
	if err != nil || second == nil || !sameRecoveryJournal(s, second.Journal()) {
		return nil, ErrRecovery
	}
	a, b := first.Claims(), second.Claims()
	if a == nil || b == nil {
		return nil, ErrRecovery
	}
	slices.SortFunc(a.Items, func(x, y corev1.PersistentVolumeClaim) int { return strings.Compare(x.Name, y.Name) })
	slices.SortFunc(b.Items, func(x, y corev1.PersistentVolumeClaim) int { return strings.Compare(x.Name, y.Name) })
	// Each enumeration has its own coherent list revision. Background storage
	// churn may advance that collection revision without changing any claim;
	// compare complete item witnesses, not unrelated collection revisions.
	if !reflect.DeepEqual(a.Items, b.Items) {
		return nil, ErrRecovery
	}
	if _, err := lifecycle.original(ctx, s); err != nil {
		return nil, ErrRecovery
	}
	finalAnchor, err := receipt.PinnedAnchor(ctx)
	if err != nil || finalAnchor != anchor || ctx.Err() != nil {
		return nil, ErrRecovery
	}
	d := s.Document()
	public := recoveryDocument{Version: "arcadectl.install-recovery/v1", Namespace: anchor.Namespace, NamespaceUID: anchor.UID,
		InstallationID: anchor.InstallationID, ProfileID: d.ProfileID, Revision: d.Revision, Mode: d.Mode, Stage: d.Stage,
		Installed: d.Installed, ActivePackage: d.ActivePackage, TargetPackage: d.TargetPackage, PreviousPackage: d.PreviousPackage,
		ClaimsResourceVersion: b.ResourceVersion, Claims: []recoveryClaim{}, Guidance: []string{
			"Preserve the original signed bootstrap package, current signed packages, protected bootstrap/create receipts, and protected client/CA files; do not regenerate them to recover an uncertain operation.",
			"Do not delete the Namespace or any listed PVC. Listing includes unrelated and unlabeled claims; it is not ownership, coldness, backup, detach or deletion authorization.",
			"An interrupted operation must recover its original journal intent; do not replay it with a fresh candidate or switch its target.",
		}}
	if d.Pending != nil {
		public.Pending = &recoveryPending{Action: d.Pending.Action, Key: d.Pending.Key, BeforeUID: d.Pending.BeforeUID}
	}
	for _, claim := range b.Items {
		switch claim.Status.Phase {
		case "", corev1.ClaimPending, corev1.ClaimBound, corev1.ClaimLost:
		default:
			return nil, ErrRecovery // never print an arbitrary status diagnostic
		}
		public.Claims = append(public.Claims, recoveryClaim{Name: claim.Name, UID: claim.UID, ResourceVersion: claim.ResourceVersion,
			VolumeName: claim.Spec.VolumeName, Phase: string(claim.Status.Phase), Deleting: claim.DeletionTimestamp != nil})
	}
	body, err := json.Marshal(public)
	if err != nil || len(body) > 2*1024*1024 || ctx.Err() != nil {
		return nil, ErrRecovery
	}
	return &RecoveryReport{body: append(body, '\n')}, nil
}

func sameRecoveryJournal(a, b *installstate.Snapshot) bool {
	return a != nil && b != nil && a.Anchor() == b.Anchor() && a.ResourceVersion() == b.ResourceVersion() && bytes.Equal(a.Bytes(), b.Bytes())
}
