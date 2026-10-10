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
	"github.com/gobha-me/arcadectl/internal/installbaseline"
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
	Baseline []retirementPolicy `json:"baseline,omitempty"`
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

// Separate original non-rollback baseline evidence. This reader alone does
// not prove behavior; capture requires the full runtime guard while all
// original actors still exist. Verification remains read-only after retirement.
func (e *Engine) retirementBaselinePolicies(ctx context.Context, s *installstate.Snapshot) ([]retirementPolicy, error) {
	security := s.Document().SecurityBaseline
	if security == nil {
		if e.baseline != nil {
			return nil, ErrAdmission
		}
		return nil, nil
	}
	if e.baseline == nil || security.Version != installbaseline.Version || security.Stage != installstate.BaselineVerified || security.Pending != nil || security.ArtifactDigest != e.baselinePlan().Digest() || len(security.Resources) != installbaseline.ResourceCount {
		return nil, ErrAdmission
	}
	result := make([]retirementPolicy, 0, installbaseline.ResourceCount)
	seen := map[installstate.Key]bool{}
	for _, resource := range security.Resources {
		template, err := e.baseline.contract.Template(resource.Key, false)
		if err != nil || template.Hash() != resource.TemplateSHA256 || seen[resource.Key] {
			return nil, ErrAdmission
		}
		live, err := e.access.Get(ctx, resource.Key)
		if err != nil || template.MatchLive(live, resource.UID) != nil || !receiptUID.MatchString(live.GetResourceVersion()) {
			return nil, ErrAdmission
		}
		if resource.Key.Kind == "ValidatingAdmissionPolicy" {
			var policy admissionv1.ValidatingAdmissionPolicy
			if decodeServing(live, &policy) != nil || !healthyAdmissionPolicy(&policy) {
				return nil, ErrAdmission
			}
		}
		seen[resource.Key] = true
		result = append(result, retirementPolicy{resource.Key, admissionIdentity{resource.UID, live.GetResourceVersion(), resource.TemplateSHA256}})
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
	if d.SecurityBaseline != nil && l.engine.baseline.verifyRuntime(ctx, s) != nil {
		return s, ErrSecurityBaseline
	}
	baselineBefore, err := l.engine.retirementBaselinePolicies(ctx, s)
	if err != nil {
		return s, err
	}
	for _, kind := range []Checkpoint{AdmissionEffective, ColdSafety, RuntimeStopped} {
		if err := l.check(ctx, kind, s, opts); err != nil {
			return s, err
		}
	}
	if d.SecurityBaseline != nil && l.engine.baseline.verifyRuntime(ctx, s) != nil {
		return s, ErrSecurityBaseline
	}
	after, err := l.engine.retirementPolicies(ctx, s)
	if err != nil || !slices.Equal(before, after) {
		return s, ErrAdmission
	}
	baselineAfter, err := l.engine.retirementBaselinePolicies(ctx, s)
	if err != nil || !slices.Equal(baselineBefore, baselineAfter) {
		return s, ErrAdmission
	}
	version := "v1"
	if d.SecurityBaseline != nil {
		version = "v2"
	}
	receipt := retirementReceipt{Version: version, Journal: s.Bytes(), Policies: before, Baseline: baselineBefore}
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
	saved, identity, pin, err := l.engine.files.Pin(name, retirementMaxBytes)
	if err != nil {
		return s, ErrOutcomeUnknown
	}
	defer pin.Close()
	if !bytes.Equal(saved, body) || pin.Confirm() != nil {
		return s, ErrOutcomeUnknown
	}
	if _, err := l.original(ctx, s); err != nil {
		return s, err
	}
	if d.SecurityBaseline != nil && l.engine.baseline.verifyRuntime(ctx, s) != nil {
		return s, ErrSecurityBaseline
	}
	after, err = l.engine.retirementPolicies(ctx, s)
	if err != nil || !slices.Equal(before, after) {
		return s, ErrAdmission
	}
	baselineAfter, err = l.engine.retirementBaselinePolicies(ctx, s)
	if err != nil || !slices.Equal(baselineBefore, baselineAfter) {
		return s, ErrAdmission
	}
	if _, err := l.original(ctx, s); err != nil {
		return s, err
	}
	closedBody, closedIdentity, err := l.engine.files.Read(name, retirementMaxBytes)
	if err != nil || closedIdentity != identity || !bytes.Equal(closedBody, body) || pin.Confirm() != nil {
		return s, ErrOutcomeUnknown
	}
	d.AdmissionRetirementRevision = d.Revision
	d.Revision++
	return l.engine.journal.Commit(ctx, s, d)
}

// verifyRetiredAdmission proves current unchanged protection and an exact
// original inventory subset. It does not claim live actor behavior or global
// revocation of permissions granted independently by other administrators.
func (e *Engine) verifyRetiredAdmission(ctx context.Context, s *installstate.Snapshot) error {
	if err := e.verifyRetiredAdmissionCore(ctx, s); err != nil {
		return err
	}
	_, err := e.current(ctx, s)
	return err
}

// The runtime baseline guard must use this nonrecursive read-only core, not
// the historical wrapper above: current itself invokes that guard. The core
// still closes the exact original namespace/journal fence, but grants neither
// runtime effect authority nor current actor-behavior evidence.
func (e *Engine) verifyRetiredAdmissionCore(ctx context.Context, s *installstate.Snapshot) error {
	if e == nil || e.journal == nil || e.access == nil || e.files == nil || ctx == nil || s == nil {
		return ErrAdmission
	}
	d := s.Document()
	if d.Mode != installstate.Uninstall || d.AdmissionRetirementRevision == 0 || d.AdmissionRetirementRevision >= d.Revision {
		return ErrAdmission
	}
	witness, err := e.openRetirementEvidence(d)
	if err != nil {
		return ErrAdmission
	}
	defer witness.release()
	original, receipt := witness.original, witness.receipt
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
	baseline, err := e.retirementBaselinePolicies(ctx, s)
	if err != nil || !slices.Equal(baseline, receipt.Baseline) {
		return ErrAdmission
	}
	_, err = (&Lifecycle{engine: e}).original(ctx, s)
	if err != nil {
		return err
	}
	// Remote GETs must not leave a replaced local receipt accepted from an
	// earlier copy, even when an atomic replacement writes identical bytes.
	return e.closeRetirementEvidence(witness)
}
