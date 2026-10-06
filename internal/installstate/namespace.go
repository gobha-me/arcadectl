// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"context"
	"reflect"
	"slices"

	"github.com/gobha-me/arcadectl/internal/installrender"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Anchor must come from durable original-identity evidence, not a fresh lookup
// by namespace name. The bootstrap workflow pins it before ordinary operation.
type Anchor struct {
	Namespace      string
	UID            types.UID
	InstallationID string
}

type Store struct {
	namespaces NamespaceAccess
	plans      []*installrender.Plan
}

// NamespaceAccess is deliberately narrow. Production installers must supply a
// single-attempt writer, including for journal CAS and bootstrap creation: the
// ordinary typed client may retry requests internally on Retry-After.
type NamespaceAccess interface {
	Get(context.Context, string, metav1.GetOptions) (*corev1.Namespace, error)
	Create(context.Context, *corev1.Namespace, metav1.CreateOptions) (*corev1.Namespace, error)
	Update(context.Context, *corev1.Namespace, metav1.UpdateOptions) (*corev1.Namespace, error)
}

// Snapshot is a sealed uncached observation. Accessors copy all mutable data.
// A read is not a lock; the exact Namespace UID/resourceVersion guard Commit.
type Snapshot struct {
	store     *Store
	namespace *corev1.Namespace
	document  Document
	body      []byte
}

func (s *Snapshot) Document() Document {
	if s == nil {
		return Document{}
	}
	var d Document
	_ = jsonCopy(s.document, &d)
	return d
}
func (s *Snapshot) Anchor() Anchor {
	if s == nil {
		return Anchor{}
	}
	return Anchor{s.document.Namespace, s.document.NamespaceUID, s.document.InstallationID}
}
func (s *Snapshot) ResourceVersion() string {
	if s == nil || s.namespace == nil {
		return ""
	}
	return s.namespace.ResourceVersion
}

// Bytes returns a defensive copy of the validated public journal encoding.
// It lets the mutation engine bind a full Namespace GET to this exact sealed
// observation instead of exempting arbitrary live annotation values.
func (s *Snapshot) Bytes() []byte {
	if s == nil {
		return nil
	}
	return bytes.Clone(s.body)
}

func New(namespaces NamespaceAccess, plans ...*installrender.Plan) (*Store, error) {
	if namespaces == nil || reflect.ValueOf(namespaces).Kind() == reflect.Pointer && reflect.ValueOf(namespaces).IsNil() || len(plans) < 1 || !plans[0].IsTrusted() {
		return nil, ErrInvalid
	}
	if _, _, err := contracts(plans, plans[0].Namespace(), plans[0].Profile().ID); err != nil {
		return nil, err
	}
	return &Store{namespaces: namespaces, plans: slices.Clone(plans)}, nil
}

func (s *Store) validAnchor(anchor Anchor) bool {
	return s != nil && s.namespaces != nil && len(s.plans) > 0 && anchor.Namespace == s.plans[0].Namespace() && validIdentity(string(anchor.UID)) && hexID.MatchString(anchor.InstallationID)
}
func (s *Store) Load(ctx context.Context, anchor Anchor) (*Snapshot, error) {
	if !s.validAnchor(anchor) {
		return nil, ErrInvalid
	}
	namespace, err := s.namespaces.Get(ctx, anchor.Namespace, metav1.GetOptions{})
	if err != nil {
		return nil, ErrOwnership
	}
	return s.observe(namespace, anchor)
}

func (s *Store) observe(namespace *corev1.Namespace, anchor Anchor) (*Snapshot, error) {
	if !safeNamespace(namespace, anchor, s.plans[0]) {
		return nil, ErrOwnership
	}
	body := []byte(namespace.Annotations[Annotation])
	d, err := Decode(body, s.plans...)
	if err != nil || d.NamespaceUID != anchor.UID || d.Namespace != anchor.Namespace || d.InstallationID != anchor.InstallationID {
		return nil, ErrOwnership
	}
	return &Snapshot{store: s, namespace: namespace.DeepCopy(), document: d, body: bytes.Clone(body)}, nil
}

// Bind initializes a journal only for a newly-created, locally journaled
// bootstrap candidate. Passing a name or matching labels is insufficient. The
// caller must retain its private bootstrap evidence until this CAS is confirmed.
// No pre-existing installation is adopted or overwritten here.
func (s *Store) Bind(ctx context.Context, anchor Anchor, initial Document) (*Snapshot, error) {
	if !s.validAnchor(anchor) || initial.Namespace != anchor.Namespace || initial.NamespaceUID != anchor.UID || initial.InstallationID != anchor.InstallationID || initial.Revision != 1 || initial.Mode != Install || initial.Stage != Preparing || initial.ActivePackage != "" || initial.Pending != nil || len(initial.Resources) != 1 || initial.Resources[0].Key.Kind != "Namespace" {
		return nil, ErrInvalid
	}
	body, err := Encode(initial, s.plans...)
	if err != nil {
		return nil, err
	}
	namespace, err := s.namespaces.Get(ctx, anchor.Namespace, metav1.GetOptions{})
	if err != nil || !safeNamespace(namespace, anchor, s.plans[0]) || namespace.Annotations[BootstrapAnnotation] != anchor.InstallationID || namespace.Annotations[Annotation] != "" {
		return nil, ErrOwnership
	}
	next := namespace.DeepCopy()
	next.Annotations[Annotation] = string(body)
	return s.update(ctx, namespace, next, anchor, body)
}

// Commit is one UID/RV-preconditioned Update, never a patch or retry. A lost
// response is confirmed only by exact candidate bytes on the same Namespace UID.
// A conflict, unreadable readback or superseded candidate cannot mean success.
func (s *Store) Commit(ctx context.Context, snapshot *Snapshot, next Document) (*Snapshot, error) {
	if snapshot == nil || snapshot.store != s || !s.validAnchor(snapshot.Anchor()) || !validTransition(snapshot.document, next) {
		return nil, ErrInvalid
	}
	body, err := Encode(next, s.plans...)
	if err != nil {
		return nil, err
	}
	namespace := snapshot.namespace.DeepCopy()
	namespace.Annotations[Annotation] = string(body)
	return s.update(ctx, snapshot.namespace, namespace, snapshot.Anchor(), body)
}

func (s *Store) update(ctx context.Context, before, next *corev1.Namespace, anchor Anchor, body []byte) (*Snapshot, error) {
	result, err := s.namespaces.Update(ctx, next, metav1.UpdateOptions{})
	if err == nil {
		observed, observationErr := s.observe(result, anchor)
		if observationErr != nil || !bytes.Equal(observed.body, body) || observed.ResourceVersion() == before.ResourceVersion {
			return nil, ErrOutcomeUnknown
		}
		return observed, nil
	}
	if apierrors.IsConflict(err) {
		return nil, ErrConflict
	}
	// Definite rejection is not success, but no arbitrary API error is reflected
	// into diagnostics. Transport/server failures always require correlation.
	if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) || apierrors.IsInvalid(err) {
		return nil, ErrOwnership
	}
	observed, readErr := s.Load(ctx, anchor)
	if readErr == nil && bytes.Equal(observed.body, body) && observed.ResourceVersion() != before.ResourceVersion {
		return observed, nil
	}
	return nil, ErrOutcomeUnknown
}

func safeNamespace(namespace *corev1.Namespace, anchor Anchor, plan *installrender.Plan) bool {
	if namespace == nil || namespace.Name != anchor.Namespace || namespace.UID != anchor.UID || !validIdentity(namespace.ResourceVersion) || namespace.DeletionTimestamp != nil || len(namespace.OwnerReferences) != 0 {
		return false
	}
	for _, finalizer := range namespace.Spec.Finalizers {
		if finalizer != corev1.FinalizerKubernetes {
			return false
		}
	}
	if len(namespace.Finalizers) != 0 {
		return false
	}
	for _, mode := range []string{"enforce", "audit", "warn"} {
		if namespace.Labels["pod-security.kubernetes.io/"+mode] != "restricted" || namespace.Labels["pod-security.kubernetes.io/"+mode+"-version"] != plan.Profile().PodSecurityVersion {
			return false
		}
	}
	return true
}

func validTransition(before, next Document) bool {
	if next.Version != before.Version || next.InstallationID != before.InstallationID || next.Namespace != before.Namespace || next.NamespaceUID != before.NamespaceUID || next.ProfileID != before.ProfileID || next.Revision != before.Revision+1 {
		return false
	}
	if before.Stage == Complete {
		// A new operation cannot silently switch packages or mode mid-journal.
		if next.Stage != Preparing || next.Pending != nil || next.AdmissionRetirementRevision != 0 || next.ActivePackage != before.ActivePackage || next.PreviousPackage != before.PreviousPackage || next.Installed != before.Installed || !reflect.DeepEqual(next.Resources, before.Resources) {
			return false
		}
		if next.Mode == Install {
			return !before.Installed && next.TargetPackage == before.ActivePackage
		}
		if !before.Installed {
			return false
		}
		return next.Mode == Uninstall && next.TargetPackage == before.ActivePackage || (next.Mode == Upgrade || next.Mode == Rollback) && next.TargetPackage != before.ActivePackage
	}
	if next.Mode != before.Mode || next.TargetPackage != before.TargetPackage {
		return false
	}
	if next.AdmissionRetirementRevision != before.AdmissionRetirementRevision {
		// One observation-only latch, before any access is withdrawn. Subsequent
		// effects, recovery and completion cannot replace or erase its evidence.
		return before.Mode == Uninstall && before.Stage == Applying && next.Stage == Applying &&
			before.AdmissionRetirementRevision == 0 && next.AdmissionRetirementRevision == before.Revision &&
			before.Pending == nil && next.Pending == nil && next.ActivePackage == before.ActivePackage &&
			next.PreviousPackage == before.PreviousPackage && next.Installed == before.Installed &&
			reflect.DeepEqual(next.Resources, before.Resources)
	}
	if next.Stage == Complete {
		if before.Stage != Verifying || before.Pending != nil || next.Pending != nil {
			return false
		}
		if next.Installed != (next.Mode != Uninstall) || next.ActivePackage != before.TargetPackage {
			return false
		}
		previous := before.PreviousPackage
		if before.ActivePackage != "" && before.ActivePackage != before.TargetPackage {
			previous = before.ActivePackage
		}
		return next.PreviousPackage == previous && reflect.DeepEqual(before.Resources, next.Resources)
	}
	if next.ActivePackage != before.ActivePackage || next.PreviousPackage != before.PreviousPackage || next.Installed != before.Installed {
		return false
	}
	if next.Stage != before.Stage {
		if before.Pending != nil || next.Pending != nil || !reflect.DeepEqual(before.Resources, next.Resources) {
			return false
		}
		switch before.Stage {
		case Preparing:
			return next.Stage == Applying && before.Mode == Install || next.Stage == Quiescing && before.Mode != Install || next.Stage == RecoveryRequired
		case Quiescing:
			return next.Stage == Applying || next.Stage == RecoveryRequired
		case Applying:
			return next.Stage == Verifying || next.Stage == RecoveryRequired
		case Verifying:
			return next.Stage == RecoveryRequired
		case RecoveryRequired:
			return next.Stage == Quiescing && before.Mode != Install || next.Stage == Applying && before.Mode == Install
		}
		return false
	}
	if before.Pending == nil {
		return next.Pending != nil && reflect.DeepEqual(before.Resources, next.Resources)
	}
	if next.Pending != nil {
		return false
	} // no overwrite or takeover of intent
	return settlesResources(before.Resources, next.Resources, *before.Pending)
}

func settlesResources(before, after []Resource, pending Pending) bool {
	beforeIndex := slices.IndexFunc(before, func(r Resource) bool { return r.Key == pending.Key })
	afterIndex := slices.IndexFunc(after, func(r Resource) bool { return r.Key == pending.Key })
	copyBefore := slices.Clone(before)
	copyAfter := slices.Clone(after)
	if beforeIndex >= 0 {
		copyBefore = slices.Delete(copyBefore, beforeIndex, beforeIndex+1)
	}
	if afterIndex >= 0 {
		copyAfter = slices.Delete(copyAfter, afterIndex, afterIndex+1)
	}
	if !reflect.DeepEqual(copyBefore, copyAfter) {
		return false
	}
	switch pending.Action {
	case Create:
		return beforeIndex < 0 && afterIndex >= 0 && after[afterIndex].TemplateSHA256 == pending.AfterSHA256
	case Update:
		return beforeIndex >= 0 && afterIndex >= 0 && after[afterIndex].UID == pending.BeforeUID && after[afterIndex].TemplateSHA256 == pending.AfterSHA256
	case Delete:
		return beforeIndex >= 0 && afterIndex < 0
	}
	return false
}
