// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var ErrAdmission = errors.New("installation admission evidence is unproved")

// ClusterAdmission establishes original configuration and closed native probe
// evidence, not the complete LifecycleChecks provider. Configuration alone is
// never behavioral authorization for RBAC, Secrets or executable workloads.
type ClusterAdmission struct {
	prerequisites *ClusterPrerequisites
}

func NewClusterAdmission(engine *Engine, access *HTTPAccess) (*ClusterAdmission, error) {
	p, err := NewClusterPrerequisites(engine, access)
	if err != nil {
		return nil, err
	}
	return &ClusterAdmission{prerequisites: p}, nil
}

type admissionIdentity struct {
	UID             types.UID
	ResourceVersion string
	TemplateSHA256  string
}

// Kept private: this is original-identity observation, not caller-supplied
// configuration, a durable behavioral receipt or a distributed lock.
type admissionConfiguration struct {
	anchor   installstate.Anchor
	objects  map[installstate.Key]admissionIdentity
	policies map[string]*admissionv1.ValidatingAdmissionPolicy
	bindings map[string]*admissionv1.ValidatingAdmissionPolicyBinding
}

func (a *ClusterAdmission) VerifyConfigured(ctx context.Context, request LifecycleCheck) error {
	if request.Checkpoint != AdmissionConfigured {
		return ErrInvalid
	}
	_, err := a.configured(ctx, request)
	return err
}

// VerifyRetained is the uninstall-only administrator observation after runtime
// access retirement. It needs durable original behavior evidence and unchanged
// healthy protections, but performs no probes or account/permission recreation.
func (a *ClusterAdmission) VerifyRetained(ctx context.Context, request LifecycleCheck) error {
	if a == nil || a.prerequisites == nil || ctx == nil || request.Checkpoint != RetainedAdmission || request.Mode != installstate.Uninstall || request.Snapshot == nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if a.prerequisites.engine.verifyRetiredAdmission(ctx, request.Snapshot) != nil {
		return ErrAdmission
	}
	before, err := a.configured(ctx, request)
	if err != nil {
		return ErrAdmission
	}
	after, err := a.configured(ctx, request)
	if err != nil || !sameAdmissionConfiguration(before, after) || a.prerequisites.engine.verifyRetiredAdmission(ctx, request.Snapshot) != nil {
		return ErrAdmission
	}
	return nil
}

// VerifyCreateProbes establishes only the six paired CREATE behaviors. This
// must not stand alone as LifecycleChecks.AdmissionEffective: cold/retention,
// UPDATE/subresource and applicable live-claim evidence remain separate proof
// obligations. No default/foreign ServiceAccount is adopted or recreated when
// the original signed dependency is missing, including uninstall's tail.
func (a *ClusterAdmission) VerifyCreateProbes(ctx context.Context, request LifecycleCheck) error {
	if request.Checkpoint != AdmissionEffective || ctx == nil {
		return ErrInvalid
	}
	return a.verifyCreateProbes(ctx, request)
}

// Called only by the two closed public entrypoints; bootstrap adds independent
// cold/runtime/account prerequisites, never aliases full AdmissionEffective.
func (a *ClusterAdmission) verifyCreateProbes(ctx context.Context, request LifecycleCheck) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	before, err := a.configured(ctx, request)
	if err != nil {
		return err
	}
	p := a.prerequisites
	key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: request.Target.Namespace(), Name: "arcadectl-controller"}
	entry, template := p.engine.inventory(request.Snapshot.Document(), key)
	if entry == nil || template == nil {
		return ErrAdmission
	}
	account, err := p.access.Get(ctx, key)
	if err != nil || template.MatchLive(account, entry.UID) != nil {
		return ErrAdmission
	}
	identity := admissionIdentity{UID: entry.UID, ResourceVersion: account.GetResourceVersion(), TemplateSHA256: template.Hash()}
	names := make([]string, 0, len(before.policies))
	for name := range before.policies {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return ErrAdmission
		}
		positive, negative, index, err := admissionCreateProbe(request.Target, name, account.GetName(), "arcadectl-probe-"+hex.EncodeToString(nonce[:]))
		if err != nil || index >= len(before.policies[name].Spec.Validations) {
			return ErrAdmission
		}
		binding := ""
		for _, candidate := range before.bindings {
			if candidate.Spec.PolicyName == name {
				if binding != "" {
					return ErrAdmission
				}
				binding = candidate.Name
			}
		}
		if binding == "" {
			return ErrAdmission
		}
		start := time.Now().UTC()
		result, err := p.access.probeCreate(ctx, positive, "", "", "")
		if err != nil || !validAdmissionProbeResult(positive, result, start, time.Now().UTC()) {
			return ErrAdmission
		}
		if _, err := p.access.probeCreate(ctx, negative, name, binding, before.policies[name].Spec.Validations[index].Message); err != nil {
			return ErrAdmission
		}
	}
	after, err := a.configured(ctx, request)
	if err != nil || !sameAdmissionConfiguration(before, after) {
		return ErrAdmission
	}
	account, err = p.access.Get(ctx, key)
	if err != nil || template.MatchLive(account, identity.UID) != nil || account.GetResourceVersion() != identity.ResourceVersion || template.Hash() != identity.TemplateSHA256 || p.original(ctx, request.Snapshot) != nil {
		return ErrAdmission
	}
	return nil
}

func (a *ClusterAdmission) configured(ctx context.Context, request LifecycleCheck) (*admissionConfiguration, error) {
	if a == nil || a.prerequisites == nil || ctx == nil || request.Snapshot == nil || !request.Target.IsTrusted() || request.Options.Now.IsZero() {
		return nil, ErrInvalid
	}
	p := a.prerequisites
	if _, err := p.permissions(request); err != nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if p.original(ctx, request.Snapshot) != nil {
		return nil, ErrAdmission
	}
	d := request.Snapshot.Document()
	witness := &admissionConfiguration{anchor: request.Snapshot.Anchor(), objects: map[installstate.Key]admissionIdentity{}, policies: map[string]*admissionv1.ValidatingAdmissionPolicy{}, bindings: map[string]*admissionv1.ValidatingAdmissionPolicyBinding{}}
	var frozen []admissionOriginalRead
	seen := map[installstate.Key]bool{}
	var policyCount, bindingCount int
	for _, resource := range request.Target.ResourceMetadata() {
		key := installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
		if key.Kind != "ValidatingAdmissionPolicy" && key.Kind != "ValidatingAdmissionPolicyBinding" {
			continue
		}
		entry, template := p.engine.inventory(d, key)
		if entry == nil || template == nil || !entry.Retained || key.Namespace != "" || seen[key] {
			return nil, ErrAdmission
		}
		seen[key] = true
		if key.Kind == "ValidatingAdmissionPolicy" {
			policyCount++
		} else {
			bindingCount++
		}
		frozen = append(frozen, admissionOriginalRead{resource: *entry, template: template})
	}
	if policyCount != 6 || bindingCount != 6 {
		return nil, ErrAdmission
	}
	type configuredObservation struct {
		identity admissionIdentity
		policy   *admissionv1.ValidatingAdmissionPolicy
		binding  *admissionv1.ValidatingAdmissionPolicyBinding
	}
	observed := make([]configuredObservation, len(frozen))
	var failures [admissionReadLanes]error
	readCtx, cancelReads := context.WithCancel(ctx)
	defer cancelReads()
	var readers sync.WaitGroup
	for lane := range admissionReadLanes {
		readers.Go(func() {
			for index := lane; index < len(frozen); index += admissionReadLanes {
				if readCtx.Err() != nil {
					failures[lane] = ErrAdmission
					return
				}
				entry := frozen[index]
				live, err := p.access.Get(readCtx, entry.resource.Key)
				if err != nil || live == nil || readCtx.Err() != nil {
					failures[lane] = ErrAdmission
					cancelReads()
					return
				}
				matched, err := entry.template.MatchLiveAdmissionObject(live, entry.resource.UID)
				if err != nil {
					failures[lane] = ErrAdmission
					cancelReads()
					return
				}
				// Mixed upgrades match the recorded signed template, never only
				// the target shape. Each worker owns all of this result slot.
				result := configuredObservation{identity: admissionIdentity{UID: entry.resource.UID, ResourceVersion: live.GetResourceVersion(), TemplateSHA256: entry.template.Hash()}}
				if entry.resource.Key.Kind == "ValidatingAdmissionPolicy" {
					policy, ok := matched.(*admissionv1.ValidatingAdmissionPolicy)
					if !ok || !healthyAdmissionPolicy(policy) {
						failures[lane] = ErrAdmission
						cancelReads()
						return
					}
					result.policy = policy.DeepCopy()
				} else {
					binding, ok := matched.(*admissionv1.ValidatingAdmissionPolicyBinding)
					if !ok {
						failures[lane] = ErrAdmission
						cancelReads()
						return
					}
					result.binding = binding.DeepCopy()
				}
				observed[index] = result
			}
		})
	}
	readers.Wait()
	if ctx.Err() != nil {
		return nil, ErrAdmission
	}
	for _, err := range failures {
		if err != nil {
			return nil, ErrAdmission
		}
	}
	for index, entry := range frozen {
		key, result := entry.resource.Key, observed[index]
		if result.policy != nil {
			if witness.policies[key.Name] != nil {
				return nil, ErrAdmission
			}
			witness.policies[key.Name] = result.policy
		} else {
			if result.binding == nil || witness.bindings[key.Name] != nil {
				return nil, ErrAdmission
			}
			witness.bindings[key.Name] = result.binding
		}
		witness.objects[key] = result.identity
	}
	if len(witness.policies) != 6 || len(witness.bindings) != 6 || len(witness.objects) != 12 {
		return nil, ErrAdmission
	}
	for _, binding := range witness.bindings {
		if witness.policies[binding.Spec.PolicyName] == nil {
			return nil, ErrAdmission
		}
	}
	if p.original(ctx, request.Snapshot) != nil {
		return nil, ErrAdmission
	}
	return witness, nil
}

func healthyAdmissionPolicy(policy *admissionv1.ValidatingAdmissionPolicy) bool {
	if policy == nil || policy.Generation < 1 || policy.Status.ObservedGeneration != policy.Generation || policy.Status.TypeChecking == nil || len(policy.Status.TypeChecking.ExpressionWarnings) != 0 {
		return false
	}
	seen := map[string]bool{}
	for _, condition := range policy.Status.Conditions {
		if condition.Type == "" || seen[condition.Type] || condition.Status != metav1.ConditionTrue || condition.ObservedGeneration != policy.Generation || condition.LastTransitionTime.IsZero() {
			return false
		}
		seen[condition.Type] = true
	}
	return true
}

func sameAdmissionConfiguration(a, b *admissionConfiguration) bool {
	return a != nil && b != nil && a.anchor == b.anchor && reflect.DeepEqual(a.objects, b.objects)
}
