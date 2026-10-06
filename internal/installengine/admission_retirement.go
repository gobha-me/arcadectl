// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const retirementMaxBytes = installstate.MaxBytes + 32768

type retirementPolicy struct {
	Key      installstate.Key  `json:"key"`
	Identity admissionIdentity `json:"identity"`
}

// This is public identity evidence in protected administrator storage, not
// credentials, executable fixtures, current behavior or an authorization grant.
type retirementReceipt struct {
	Version  string             `json:"version"`
	Journal  json.RawMessage    `json:"journal"`
	Policies []retirementPolicy `json:"policies"`
}

func accessRetirementKey(key installstate.Key) bool {
	switch key.Kind {
	case "RoleBinding", "ClusterRoleBinding", "Role", "ClusterRole", "ServiceAccount":
		return true
	}
	return false
}

func retiringAccessDelete(d installstate.Document) bool {
	return d.Mode == installstate.Uninstall && d.Stage == installstate.Applying && d.AdmissionRetirementRevision != 0 &&
		d.Pending != nil && d.Pending.Action == installstate.Delete && accessRetirementKey(d.Pending.Key)
}

func retirementName(d installstate.Document, revision uint64) string {
	return "uninstall-admission-" + d.InstallationID + "-" + strconv.FormatUint(revision, 10) + ".json"
}

// Read exactly the original twelve protections; never create a probe or depend
// on a surviving runtime account. Resource-version pinning rejects even a
// change-and-restore of a policy with the same desired hash.
func (e *Engine) retirementPolicies(ctx context.Context, s *installstate.Snapshot) ([]retirementPolicy, error) {
	d := s.Document()
	var result []retirementPolicy
	for _, resource := range d.Resources {
		key := resource.Key
		if key.Kind != "ValidatingAdmissionPolicy" && key.Kind != "ValidatingAdmissionPolicyBinding" {
			continue
		}
		_, template := e.inventory(d, key)
		live, err := e.access.Get(ctx, key)
		if template == nil || err != nil || !resource.Retained || template.MatchLive(live, resource.UID) != nil || !receiptUID.MatchString(live.GetResourceVersion()) {
			return nil, ErrAdmission
		}
		if key.Kind == "ValidatingAdmissionPolicy" {
			var policy admissionv1.ValidatingAdmissionPolicy
			if decodeServing(live, &policy) != nil || !healthyAdmissionPolicy(&policy) {
				return nil, ErrAdmission
			}
		}
		result = append(result, retirementPolicy{key, admissionIdentity{resource.UID, live.GetResourceVersion(), resource.TemplateSHA256}})
	}
	if len(result) != 12 {
		return nil, ErrAdmission
	}
	return result, nil
}

func (l *Lifecycle) retireAdmission(ctx context.Context, s *installstate.Snapshot, opts LifecycleOptions) (*installstate.Snapshot, error) {
	d := s.Document()
	if d.Mode != installstate.Uninstall || d.Stage != installstate.Applying || d.Pending != nil || d.AdmissionRetirementRevision != 0 {
		return s, ErrInvalid
	}
	// All software accounts and their original authorization must still exist.
	// An interrupted older uninstall cannot retrospectively invent this proof.
	for _, resource := range l.engine.plans[d.TargetPackage].Resources() {
		key := resourceKey(resource)
		if resource.Retained {
			continue
		}
		entry, template := l.engine.inventory(d, key)
		live, err := l.engine.access.Get(ctx, key)
		if accessRetirementKey(key) {
			if entry == nil || template == nil || err != nil || template.MatchLive(live, entry.UID) != nil {
				return s, ErrAdmission
			}
		} else if entry != nil || !apierrors.IsNotFound(err) {
			return s, ErrAdmission // executable/service removal must already be settled
		}
	}
	before, err := l.engine.retirementPolicies(ctx, s)
	if err != nil {
		return s, err
	}
	for _, kind := range []Checkpoint{AdmissionEffective, ColdSafety, RuntimeStopped} {
		if err := l.check(ctx, kind, s, opts); err != nil {
			return s, err
		}
	}
	after, err := l.engine.retirementPolicies(ctx, s)
	if err != nil || !slices.Equal(before, after) {
		return s, ErrAdmission
	}
	receipt := retirementReceipt{"v1", s.Bytes(), before}
	body, err := json.Marshal(receipt)
	if err != nil {
		return s, ErrAdmission
	}
	body, err = canonicaljson.CanonicalJSON(body)
	if err != nil || len(body) > retirementMaxBytes {
		return s, ErrAdmission
	}
	name := retirementName(d, d.Revision)
	if _, err := l.engine.files.CreateExclusive(name, body); err != nil && !errors.Is(err, privatefs.ErrExists) {
		return s, ErrOutcomeUnknown
	}
	// A lost fsync/CAS acknowledgement never allows overwrite or fresh proof
	// adoption: the exact original receipt must be readable and durable.
	saved, identity, err := l.engine.files.Read(name, retirementMaxBytes)
	if err != nil || !bytes.Equal(saved, body) || l.engine.files.ConfirmDurable(name, identity) != nil {
		return s, ErrOutcomeUnknown
	}
	if _, err := l.original(ctx, s); err != nil {
		return s, err
	}
	after, err = l.engine.retirementPolicies(ctx, s)
	if err != nil || !slices.Equal(before, after) {
		return s, ErrAdmission
	}
	d.AdmissionRetirementRevision = d.Revision
	d.Revision++
	return l.engine.journal.Commit(ctx, s, d)
}

// verifyRetiredAdmission proves current unchanged protection and an exact
// original inventory subset. It does not claim live actor behavior or global
// revocation of permissions granted independently by other administrators.
func (e *Engine) verifyRetiredAdmission(ctx context.Context, s *installstate.Snapshot) error {
	d := s.Document()
	if d.Mode != installstate.Uninstall || d.AdmissionRetirementRevision == 0 || d.AdmissionRetirementRevision >= d.Revision {
		return ErrAdmission
	}
	body, identity, err := e.files.Read(retirementName(d, d.AdmissionRetirementRevision), retirementMaxBytes)
	if err != nil || e.files.ConfirmDurable(retirementName(d, d.AdmissionRetirementRevision), identity) != nil {
		return ErrAdmission
	}
	canonical, err := canonicaljson.CanonicalJSON(body)
	var receipt retirementReceipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err != nil || !bytes.Equal(canonical, body) || decoder.Decode(&receipt) != nil || receipt.Version != "v1" {
		return ErrAdmission
	}
	plans := []*installrender.Plan{}
	for _, plan := range e.plans {
		plans = append(plans, plan)
	}
	original, err := installstate.Decode(receipt.Journal, plans...)
	if err != nil || original.Mode != installstate.Uninstall || original.Stage != installstate.Applying || original.Pending != nil || original.AdmissionRetirementRevision != 0 ||
		original.Revision != d.AdmissionRetirementRevision || original.Namespace != d.Namespace || original.NamespaceUID != d.NamespaceUID || original.InstallationID != d.InstallationID ||
		original.ProfileID != d.ProfileID || original.TargetPackage != d.TargetPackage || original.ActivePackage != d.ActivePackage || original.PreviousPackage != d.PreviousPackage || !original.Installed {
		return ErrAdmission
	}
	for _, resource := range e.plans[d.TargetPackage].Resources() {
		key := resourceKey(resource)
		entry, _ := e.inventory(original, key)
		if !resource.Retained && (accessRetirementKey(key) != (entry != nil)) {
			return ErrAdmission
		}
	}
	for _, resource := range d.Resources {
		entry, _ := e.inventory(original, resource.Key)
		if entry == nil || *entry != resource {
			return ErrAdmission
		}
		if accessRetirementKey(resource.Key) {
			_, template := e.inventory(d, resource.Key)
			live, err := e.access.Get(ctx, resource.Key)
			pending := d.Pending
			if pending != nil && pending.Action == installstate.Delete && pending.Key == resource.Key && apierrors.IsNotFound(err) {
				continue // observe the original in-flight deletion; never replay it
			}
			if err != nil || template == nil || template.MatchLive(live, resource.UID) != nil {
				return ErrAdmission
			}
		}
	}
	for _, resource := range original.Resources {
		if entry, _ := e.inventory(d, resource.Key); entry == nil {
			if resource.Retained || !accessRetirementKey(resource.Key) {
				return ErrAdmission
			}
			if _, err := e.access.Get(ctx, resource.Key); !apierrors.IsNotFound(err) {
				return ErrAdmission // same-name access recreation is not retirement
			}
		}
	}
	policies, err := e.retirementPolicies(ctx, s)
	if err != nil || !slices.Equal(policies, receipt.Policies) {
		return ErrAdmission
	}
	_, err = e.current(ctx, s)
	return err
}
