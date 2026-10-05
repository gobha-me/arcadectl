// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// BootstrapReceipt is public identity evidence kept in private, durable local
// storage. It is created BEFORE the first namespace mutation. An interrupted
// invocation must explicitly load this receipt; it must not create a new nonce
// or adopt a same-named Namespace. No credentials or private paths are recorded.
type BootstrapReceipt struct {
	store    *privatefs.Store
	name     string
	identity privatefs.FileIdentity
	plan     *installrender.Plan
	document bootstrapDocument
}
type bootstrapDocument struct {
	Version         string    `json:"version"`
	InstallationID  string    `json:"installationId"`
	Namespace       string    `json:"namespace"`
	NamespaceUID    types.UID `json:"namespaceUid"`
	CreateAttempted bool      `json:"createAttempted"`
	PackageSHA256   string    `json:"packageSha256"`
	ProfileID       string    `json:"profileId"`
}

var receiptName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,111}$`)

func PrepareBootstrap(store *privatefs.Store, name string, plan *installrender.Plan) (*BootstrapReceipt, error) {
	if store == nil || !receiptName.MatchString(name) || !plan.IsTrusted() {
		return nil, ErrInvalid
	}
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	d := bootstrapDocument{Version: Version, InstallationID: id, Namespace: plan.Namespace(), PackageSHA256: plan.Digest(), ProfileID: plan.Profile().ID}
	body, err := encodeBootstrap(d, plan)
	if err != nil {
		return nil, err
	}
	identity, err := store.CreateExclusive(name, body)
	if err != nil {
		return nil, privateError(err)
	}
	return &BootstrapReceipt{store: store, name: name, identity: identity, plan: plan, document: d}, nil
}

func LoadBootstrap(store *privatefs.Store, name string, plan *installrender.Plan) (*BootstrapReceipt, error) {
	if store == nil || !receiptName.MatchString(name) || !plan.IsTrusted() {
		return nil, ErrInvalid
	}
	body, identity, err := store.Read(name, MaxBytes)
	if err != nil {
		return nil, privateError(err)
	}
	d, err := decodeBootstrap(body, plan)
	if err != nil {
		return nil, err
	}
	if err := store.ConfirmDurable(name, identity); err != nil {
		return nil, privateError(err)
	}
	return &BootstrapReceipt{store: store, name: name, identity: identity, plan: plan, document: d}, nil
}

func encodeBootstrap(d bootstrapDocument, plan *installrender.Plan) ([]byte, error) {
	if !plan.IsTrusted() || d.Version != Version || !hexID.MatchString(d.InstallationID) || d.Namespace != plan.Namespace() || d.PackageSHA256 != plan.Digest() || d.ProfileID != plan.Profile().ID || d.NamespaceUID != "" && (!validIdentity(string(d.NamespaceUID)) || !d.CreateAttempted) {
		return nil, ErrInvalid
	}
	body, err := json.Marshal(d)
	if err != nil {
		return nil, ErrInvalid
	}
	body, err = canonicaljson.CanonicalJSON(body)
	if err != nil {
		return nil, ErrInvalid
	}
	return body, nil
}
func decodeBootstrap(body []byte, plan *installrender.Plan) (bootstrapDocument, error) {
	var d bootstrapDocument
	if len(body) == 0 || len(body) > MaxBytes {
		return d, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil {
		return bootstrapDocument{}, ErrInvalid
	}
	canonical, err := encodeBootstrap(d, plan)
	if err != nil || !bytes.Equal(body, canonical) {
		return bootstrapDocument{}, ErrInvalid
	}
	return d, nil
}
func privateError(err error) error {
	if errors.Is(err, privatefs.ErrChanged) || errors.Is(err, privatefs.ErrExists) {
		return ErrConflict
	}
	if errors.Is(err, privatefs.ErrDurability) {
		return ErrOutcomeUnknown
	}
	return ErrOwnership
}

// CreateResponseRejected recognizes fixed API responses that prove this Create
// was rejected. A matching object discovered afterward is not its effect.
// Transport errors and unreadable success responses remain ambiguous.
func CreateResponseRejected(err error) bool {
	return apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) || apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) || apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) || apierrors.IsNotFound(err) || apierrors.IsTooManyRequests(err) || apierrors.IsMethodNotSupported(err) || apierrors.IsRequestEntityTooLargeError(err) || apierrors.IsUnsupportedMediaType(err)
}

// EnsureNamespace sends at most one Create, pins its exact UID durably, then
// binds the namespace CAS journal. Only the original invocation may correlate
// a genuinely lost response using immediate reviewed nonce-bound readback.
// Restart requires a durably pinned UID; an empty attempted receipt remains
// unresolved even when a same-named object looks correct. It never removes a
// namespace, retries a create, or authorizes runtime resources. A caller must
// complete cluster/prerequisite/foreign-resource preflight BEFORE calling it.
func (r *BootstrapReceipt) EnsureNamespace(ctx context.Context, namespaces NamespaceAccess) (*Snapshot, error) {
	if r == nil || r.store == nil || !r.plan.IsTrusted() || namespaces == nil || reflect.ValueOf(namespaces).Kind() == reflect.Pointer && reflect.ValueOf(namespaces).IsNil() {
		return nil, ErrInvalid
	}
	lock, err := r.store.Lock(ctx, r.name+".lock")
	if err != nil {
		return nil, privateError(err)
	}
	defer lock.Close()
	// Reload under the local lock; stale in-memory evidence is not authority.
	body, identity, err := r.store.Read(r.name, MaxBytes)
	if err != nil {
		return nil, privateError(err)
	}
	if identity != r.identity {
		return nil, ErrConflict
	}
	d, err := decodeBootstrap(body, r.plan)
	if err != nil {
		return nil, err
	}
	if d != r.document {
		return nil, ErrConflict
	}
	if err := r.store.ConfirmDurable(r.name, identity); err != nil {
		return nil, privateError(err)
	}
	if d.CreateAttempted && d.NamespaceUID == "" {
		return nil, ErrOutcomeUnknown
	}
	want, templateDigest, err := bootstrapNamespace(r.plan, d.InstallationID)
	if err != nil {
		return nil, err
	}
	live, err := namespaces.Get(ctx, d.Namespace, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if d.NamespaceUID != "" {
			return nil, ErrOwnership
		}
		if d.CreateAttempted {
			return nil, ErrOutcomeUnknown
		}
		// Persist the attempt before the call. A process interruption after this
		// point cannot distinguish an unsent request from a delayed server write,
		// so explicit resume without a pinned UID must neither replay Create
		// nor establish ownership from a copied public nonce.
		d.CreateAttempted = true
		candidate, encodeErr := encodeBootstrap(d, r.plan)
		if encodeErr != nil {
			return nil, encodeErr
		}
		identity, err = r.store.AtomicWrite(r.name, candidate, &r.identity)
		if err != nil {
			return nil, privateError(err)
		}
		r.document, r.identity = d, identity
		live, err = namespaces.Create(ctx, want, metav1.CreateOptions{})
		if err != nil {
			if CreateResponseRejected(err) {
				return nil, ErrOwnership
			}
			live, err = namespaces.Get(ctx, d.Namespace, metav1.GetOptions{})
			if err != nil {
				return nil, ErrOutcomeUnknown
			}
			if !matchesBootstrapNamespace(live, want, r.plan, d) {
				return nil, ErrOwnership
			}
			if r.pinUID(&d, live.UID) != nil {
				return nil, ErrOutcomeUnknown
			}
		} else {
			// Pin any known ACK identity before accepting shape. A rejected
			// ACK cannot leave an empty receipt that adopts a replacement later.
			if live == nil || live.UID == "" {
				return nil, ErrOutcomeUnknown
			}
			unbound := d
			if r.pinUID(&d, live.UID) != nil {
				return nil, ErrOutcomeUnknown
			}
			if !matchesBootstrapNamespace(live, want, r.plan, unbound) {
				return nil, ErrOwnership
			}
		}
	} else if err != nil {
		return nil, ErrOwnership
	}
	if !matchesBootstrapNamespace(live, want, r.plan, d) {
		return nil, ErrOwnership
	}
	if err := r.store.ConfirmDurable(r.name, r.identity); err != nil {
		return nil, privateError(err)
	}
	anchor := Anchor{d.Namespace, d.NamespaceUID, d.InstallationID}
	store, err := New(namespaces, r.plan)
	if err != nil {
		return nil, err
	}
	if live.Annotations[Annotation] != "" {
		return store.Load(ctx, anchor)
	}
	initial := Document{Version: Version, InstallationID: d.InstallationID, Namespace: d.Namespace, NamespaceUID: d.NamespaceUID, ProfileID: d.ProfileID, Revision: 1, Mode: Install, Stage: Preparing, TargetPackage: d.PackageSHA256, Resources: []Resource{{Key: Key{"v1", "Namespace", "", d.Namespace}, UID: d.NamespaceUID, TemplateSHA256: templateDigest, Retained: true, Phase: installrender.Anchors}}}
	return store.Bind(ctx, anchor, initial)
}

func (r *BootstrapReceipt) pinUID(d *bootstrapDocument, uid types.UID) error {
	if d == nil || uid == "" || d.NamespaceUID != "" {
		return ErrInvalid
	}
	next := *d
	next.NamespaceUID = uid
	body, err := encodeBootstrap(next, r.plan)
	if err != nil {
		return err
	}
	identity, err := r.store.AtomicWrite(r.name, body, &r.identity)
	if err != nil {
		return err
	}
	*d, r.document, r.identity = next, next, identity
	return nil
}

func bootstrapNamespace(plan *installrender.Plan, id string) (*corev1.Namespace, string, error) {
	for _, r := range plan.Resources() {
		if r.Object.GetKind() == "Namespace" {
			var namespace corev1.Namespace
			if runtime.DefaultUnstructuredConverter.FromUnstructured(r.Object.Object, &namespace) != nil {
				return nil, "", ErrInvalid
			}
			body, err := json.Marshal(r.Object.Object)
			if err != nil {
				return nil, "", ErrInvalid
			}
			sum := sha256.Sum256(body)
			if namespace.Annotations == nil {
				namespace.Annotations = map[string]string{}
			}
			namespace.Annotations[BootstrapAnnotation] = id
			return &namespace, hex.EncodeToString(sum[:]), nil
		}
	}
	return nil, "", ErrInvalid
}
func matchesBootstrapNamespace(live, want *corev1.Namespace, plan *installrender.Plan, d bootstrapDocument) bool {
	if !d.CreateAttempted || live == nil || live.UID == "" || d.NamespaceUID != "" && live.UID != d.NamespaceUID {
		return false
	}
	anchor := Anchor{d.Namespace, live.UID, d.InstallationID}
	if !safeNamespace(live, anchor, plan) || live.Annotations[BootstrapAnnotation] != d.InstallationID {
		return false
	}
	if d.NamespaceUID == "" && live.Annotations[Annotation] != "" {
		return false
	}
	for key, value := range want.Labels {
		if live.Labels[key] != value {
			return false
		}
	}
	for key, value := range live.Labels {
		if want.Labels[key] != value && (key != "kubernetes.io/metadata.name" || value != d.Namespace) {
			return false
		}
	}
	for key, value := range want.Annotations {
		if live.Annotations[key] != value {
			return false
		}
	}
	for key, value := range live.Annotations {
		if key != Annotation && want.Annotations[key] != value {
			return false
		}
	}
	return true
}
