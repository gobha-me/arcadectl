// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// SecretWorkflow performs only the two reviewed private Creates. It is not
// rotation, TLS activation, prerequisite validation or a lifecycle safety proof.
// Namespace bootstrap and public resources remain managed by Engine.
type SecretWorkflow struct {
	engine *Engine
	access PrivateSecretAccess
}

func NewSecretWorkflow(engine *Engine, access PrivateSecretAccess) (*SecretWorkflow, error) {
	if engine == nil || access == nil || reflect.ValueOf(access).Kind() == reflect.Pointer && reflect.ValueOf(access).IsNil() {
		return nil, ErrInvalid
	}
	return &SecretWorkflow{engine: engine, access: access}, nil
}

func (w *SecretWorkflow) candidate(s *installstate.Snapshot, c *Credentials, now time.Time) (*Credentials, error) {
	if w == nil || w.engine == nil || c == nil || c.engine != w.engine {
		return nil, ErrCredentials
	}
	d := s.Document()
	if d.Mode != installstate.Install || d.Stage != installstate.Applying {
		return nil, ErrInvalid
	}
	loaded, err := w.engine.loadCredentials(s, now)
	if err != nil || loaded.fileIdentity != c.fileIdentity || !bytes.Equal(loaded.body, c.body) {
		return nil, ErrCredentials
	}
	return loaded, nil
}

// Create writes candidate/client/CA output privately BEFORE the real Secret
// effect. Public pending/inventory hashes stay empty: no Secret content/hash is
// written to Namespace annotations. There is one real Create and no replay.
func (w *SecretWorkflow) Create(ctx context.Context, s *installstate.Snapshot, c *Credentials, name string, now time.Time) (*installstate.Snapshot, error) {
	if w == nil || w.engine == nil {
		return nil, ErrInvalid
	}
	fresh, err := w.engine.current(ctx, s)
	if err != nil {
		return nil, err
	}
	c, err = w.candidate(fresh, c, now)
	if err != nil {
		return nil, err
	}
	d := fresh.Document()
	if d.Pending != nil {
		return nil, ErrInvalid
	}
	key := secretKey(d.Namespace, name)
	for _, r := range d.Resources {
		if r.Key == key {
			return nil, ErrInvalid
		}
	}
	secret, nonce, err := c.secret(name)
	if err != nil {
		return nil, err
	}
	if _, err := w.access.Get(ctx, key.Namespace, key.Name); !apierrors.IsNotFound(err) {
		return nil, ErrOwnership
	}
	if c.ExportClient("admin-client-"+d.InstallationID+".json") != nil || c.ExportCA("api-ca-"+d.InstallationID+".pem") != nil {
		return nil, ErrCredentials
	}
	admitted, err := w.access.Create(ctx, secret.DeepCopy(), true)
	if err != nil || !matchesPrivateSecret(admitted, secret, "", false) {
		return nil, ErrRead
	}
	fresh, err = w.engine.current(ctx, fresh)
	if err != nil {
		return nil, err
	}
	// Recheck protected original candidate after external admission activity.
	if _, err = w.candidate(fresh, c, now); err != nil {
		return nil, err
	}
	d.Revision++
	d.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: nonce}
	intent, err := w.engine.journal.Commit(ctx, fresh, d)
	if err != nil {
		return nil, err
	}
	if w.engine.prepareCreateReceipt(intent.Document()) != nil {
		return intent, ErrOutcomeUnknown
	}
	if _, err = w.engine.current(ctx, intent); err != nil {
		return intent, ErrOutcomeUnknown
	}
	if _, err = w.candidate(intent, c, now); err != nil {
		return intent, ErrOutcomeUnknown
	}
	ack, writeErr := w.access.Create(ctx, secret.DeepCopy(), false)
	if writeErr == nil {
		if ack == nil || w.engine.saveCreateUID(intent.Document(), ack.UID) != nil {
			return intent, ErrOutcomeUnknown
		}
		if !matchesPrivateSecret(ack, secret, ack.UID, true) {
			return intent, ErrOutcomeUnknown
		}
	}
	return w.recover(ctx, intent, c, now, ambiguousCreateResponse(writeErr))
}

// Recover never reissues Create or regenerates private candidates. Missing
// original UID evidence requires manual investigation, not nonce-only adoption.
func (w *SecretWorkflow) Recover(ctx context.Context, s *installstate.Snapshot, c *Credentials, now time.Time) (*installstate.Snapshot, error) {
	return w.recover(ctx, s, c, now, false)
}
func (w *SecretWorkflow) recover(ctx context.Context, s *installstate.Snapshot, c *Credentials, now time.Time, allowInitialObservation bool) (*installstate.Snapshot, error) {
	if w == nil || w.engine == nil {
		return s, ErrInvalid
	}
	fresh, err := w.engine.current(ctx, s)
	if err != nil {
		return s, ErrOutcomeUnknown
	}
	c, err = w.candidate(fresh, c, now)
	if err != nil {
		return fresh, ErrOutcomeUnknown
	}
	d := fresh.Document()
	p := d.Pending
	if p == nil || p.Action != installstate.Create || p.Key.Kind != "Secret" || p.Key.Namespace != d.Namespace || p.AfterSHA256 != "" {
		return fresh, ErrInvalid
	}
	secret, nonce, err := c.secret(p.Key.Name)
	if err != nil || nonce != p.CreateNonce {
		return fresh, ErrInvalid
	}
	for _, r := range d.Resources {
		if r.Key == p.Key {
			return fresh, ErrInvalid
		}
	}
	live, err := w.access.Get(ctx, p.Key.Namespace, p.Key.Name)
	if err != nil || live == nil || !matchesPrivateSecret(live, secret, live.UID, true) {
		return fresh, ErrOutcomeUnknown
	}
	if allowInitialObservation && w.engine.saveCreateUID(d, live.UID) != nil {
		return fresh, ErrOutcomeUnknown
	}
	original, err := w.engine.loadCreateUID(d)
	if err != nil || original != live.UID {
		return fresh, ErrOutcomeUnknown
	}
	d.Resources = append(d.Resources, installstate.Resource{Key: p.Key, UID: original, Retained: true, Phase: installrender.API})
	installstate.SortResources(d.Resources)
	d.Revision++
	d.Pending = nil
	settled, err := w.engine.journal.Commit(ctx, fresh, d)
	if err != nil {
		return fresh, ErrOutcomeUnknown
	}
	return settled, nil
}

func safePrivateMetadata(s *corev1.Secret, uid types.UID, requireUID bool) bool {
	if s == nil || requireUID && (uid == "" || s.UID != uid || s.ResourceVersion == "") || s.DeletionTimestamp != nil || s.DeletionGracePeriodSeconds != nil || len(s.OwnerReferences) != 0 || len(s.Finalizers) != 0 || s.GenerateName != "" || s.SelfLink != "" || len(s.StringData) != 0 || s.Immutable != nil && *s.Immutable {
		return false
	}
	if s.Generation < 0 || s.UID != "" && !receiptUID.MatchString(string(s.UID)) || s.ResourceVersion != "" && !receiptUID.MatchString(s.ResourceVersion) {
		return false
	}
	return true
}
func matchesPrivateSecret(live, want *corev1.Secret, uid types.UID, requireUID bool) bool {
	if !safePrivateMetadata(live, uid, requireUID) || want == nil {
		return false
	}
	a, b := live.DeepCopy(), want.DeepCopy()
	a.TypeMeta, b.TypeMeta = metav1.TypeMeta{}, metav1.TypeMeta{}
	a.UID, a.ResourceVersion, a.Generation = "", "", 0
	a.CreationTimestamp = metav1.Time{}
	a.ManagedFields = nil
	a.Immutable = nil
	a.OwnerReferences = nil
	a.Finalizers = nil
	a.StringData = nil
	return apiequality.Semantic.DeepEqual(a, b)
}

// VerifyRetained proves original Secret UIDs and current accepted formats,
// allowing legitimate administrator token rotation without adopting a new UID.
// It never loads original candidate token bytes, writes or rotates a Secret.
func (w *SecretWorkflow) VerifyRetained(ctx context.Context, s *installstate.Snapshot, caFile string, now time.Time) error {
	_, _, err := w.retained(ctx, s, caFile, now)
	return err
}

// retained binds returned private bytes and CA identity to the very reads
// checked against the original inventory. Do not validate then independently
// reopen a Secret to obtain authentication material.
func (w *SecretWorkflow) retained(ctx context.Context, s *installstate.Snapshot, caFile string, now time.Time) (objects map[string]*corev1.Secret, caID privatefs.FileIdentity, err error) {
	defer func() {
		if err != nil {
			objects = nil
			caID = privatefs.FileIdentity{}
		}
	}()
	if w == nil || w.engine == nil {
		return nil, caID, ErrInvalid
	}
	fresh, err := w.engine.current(ctx, s)
	if err != nil {
		return nil, caID, err
	}
	d := fresh.Document()
	if d.Pending != nil && (!retiringAccessDelete(d) || w.engine.verifyRetiredAdmission(ctx, fresh) != nil) {
		return nil, caID, ErrInvalid
	}
	ca, caID, err := privatefs.ReadAbsolute(caFile, 65536, privatefs.TrustedPublic)
	if err != nil {
		return nil, caID, ErrCredentials
	}
	objects = make(map[string]*corev1.Secret, 2)
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		key := secretKey(d.Namespace, name)
		index := slices.IndexFunc(d.Resources, func(r installstate.Resource) bool { return r.Key == key })
		if index < 0 || !d.Resources[index].Retained || d.Resources[index].TemplateSHA256 != "" {
			return nil, caID, ErrOwnership
		}
		live, err := w.access.Get(ctx, d.Namespace, name)
		if err != nil || !safePrivateMetadata(live, d.Resources[index].UID, true) || len(live.Annotations) != 1 || !nonceID.MatchString(live.Annotations[installstate.MutationAnnotation]) {
			return nil, caID, ErrOwnership
		}
		if name == adminauth.CredentialSecretName {
			if string(live.Type) != adminauth.CredentialSecretType || !reflect.DeepEqual(live.Labels, adminauth.ManagedSecretLabels()) || len(live.Data) != 2 {
				return nil, caID, ErrCredentials
			}
			bundle, err := adminauth.ParseVerifierBundle(live.Data[adminauth.VerifierSecretKey])
			if err != nil || !bundle.ExpiresAt.After(now) || !adminauth.TokenMatchesBundle(string(live.Data[adminauth.TokenSecretKey]), bundle) {
				return nil, caID, ErrCredentials
			}
		} else if live.Type != corev1.SecretTypeTLS || len(live.Labels) != 0 || len(live.Data) != 2 || validateTLS(live.Data[corev1.TLSCertKey], live.Data[corev1.TLSPrivateKeyKey], ca, d.Namespace, now) != nil {
			return nil, caID, ErrCredentials
		}
		objects[name] = live.DeepCopy()
	}
	if _, err := w.engine.current(ctx, fresh); err != nil {
		return nil, caID, ErrConcurrent
	}
	return objects, caID, nil
}
