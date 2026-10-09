// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"reflect"
	"slices"
	"strings"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"k8s.io/apimachinery/pkg/types"
)

type BaselineStage string

const (
	BaselinePreparing BaselineStage = "preparing"
	BaselineApplying  BaselineStage = "applying"
	BaselineVerified  BaselineStage = "verified"
	BaselineRecovery  BaselineStage = "recovery-required"
)

type BaselineResource struct {
	Key            Key       `json:"key"`
	UID            types.UID `json:"uid"`
	TemplateSHA256 string    `json:"templateSha256"`
}

// SecurityBaseline records only public pinned identities. Its inventory is
// independent of runtime resources, never removed or rewritten by rollback or
// retaining uninstall. Verified records completed ownership establishment, not
// a promise about current live health; the engine must continuously reobserve.
type SecurityBaseline struct {
	Version        string             `json:"version"`
	ArtifactDigest string             `json:"artifactDigest"`
	Stage          BaselineStage      `json:"stage"`
	Resources      []BaselineResource `json:"resources"`
	Pending        *Pending           `json:"pending"`
}

func PinnedSecurityBaseline(plan *installbaseline.Plan) (*SecurityBaseline, error) {
	if !plan.IsTrusted() {
		return nil, ErrInvalid
	}
	return &SecurityBaseline{Version: installbaseline.Version, ArtifactDigest: plan.Digest(), Stage: BaselinePreparing, Resources: []BaselineResource{}}, nil
}

func validateSecurityBaseline(document Document, plan *installbaseline.Plan) error {
	if validateAdmissionReinstall(document) != nil {
		return ErrInvalid
	}
	if plan != nil && (!plan.IsTrusted() || plan.Namespace() != document.Namespace || plan.Profile() != document.ProfileID) {
		return ErrInvalid
	}
	baseline := document.SecurityBaseline
	if baseline == nil {
		return nil
	} // Historical absence, not verification.
	if !plan.IsTrusted() || baseline.Version != installbaseline.Version || baseline.ArtifactDigest != plan.Digest() || baseline.Resources == nil || len(baseline.Resources) > installbaseline.ResourceCount {
		return ErrInvalid
	}
	if baseline.Stage != BaselineVerified && document.Pending != nil {
		return ErrInvalid
	}
	keys := make(map[Key]string, installbaseline.ResourceCount)
	for _, resource := range plan.Resources() {
		object := resource.Object
		key := Key{object.GetAPIVersion(), object.GetKind(), object.GetNamespace(), object.GetName()}
		keys[key] = resource.TemplateSHA256
	}
	seenUIDs := make(map[types.UID]bool, MaxResources+installbaseline.ResourceCount)
	for _, resource := range document.Resources {
		seenUIDs[resource.UID] = true
	}
	previous := ""
	for _, resource := range baseline.Resources {
		if keys[resource.Key] == "" || keys[resource.Key] != resource.TemplateSHA256 || !validIdentity(string(resource.UID)) || seenUIDs[resource.UID] || resource.Key.String() <= previous {
			return ErrInvalid
		}
		seenUIDs[resource.UID], previous = true, resource.Key.String()
	}
	switch baseline.Stage {
	case BaselinePreparing:
		if len(baseline.Resources) != 0 || baseline.Pending != nil {
			return ErrInvalid
		}
	case BaselineApplying, BaselineRecovery:
	case BaselineVerified:
		if len(baseline.Resources) != installbaseline.ResourceCount || baseline.Pending != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if pending := baseline.Pending; pending != nil {
		if document.Pending != nil || pending.Action != Create || !hexID.MatchString(pending.CreateNonce) || pending.BeforeUID != "" || pending.BeforeResourceVersion != "" || pending.BeforeSHA256 != "" || keys[pending.Key] == "" || pending.AfterSHA256 != keys[pending.Key] || slices.ContainsFunc(baseline.Resources, func(resource BaselineResource) bool { return resource.Key == pending.Key }) {
			return ErrInvalid
		}
	}
	return nil
}

// Baseline evolution cannot piggyback a runtime effect, package transition,
// mode/stage change or retirement latch. It advances under the same revision
// and namespace CAS; each created identity must settle a prior exact intent.
func validSecurityTransition(before, next Document) bool {
	if before.Pending != nil || next.Pending != nil {
		return false
	}
	oldRuntime, newRuntime := before, next
	oldRuntime.SecurityBaseline, newRuntime.SecurityBaseline = nil, nil
	newRuntime.Revision = oldRuntime.Revision
	if !reflect.DeepEqual(oldRuntime, newRuntime) {
		return false
	}
	a, b := before.SecurityBaseline, next.SecurityBaseline
	if b == nil {
		return false
	}
	if a == nil {
		return b.Stage == BaselinePreparing && len(b.Resources) == 0 && b.Pending == nil
	}
	if a.Version != b.Version || a.ArtifactDigest != b.ArtifactDigest || a.Stage == BaselineVerified {
		return false
	}
	if a.Stage != b.Stage {
		if !reflect.DeepEqual(a.Resources, b.Resources) || !reflect.DeepEqual(a.Pending, b.Pending) {
			return false
		}
		switch a.Stage {
		case BaselinePreparing:
			return b.Stage == BaselineApplying
		case BaselineApplying:
			return b.Stage == BaselineRecovery || b.Stage == BaselineVerified && a.Pending == nil && len(a.Resources) == installbaseline.ResourceCount
		case BaselineRecovery:
			return b.Stage == BaselineApplying
		}
		return false
	}
	if a.Stage != BaselineApplying {
		return false
	}
	if a.Pending == nil {
		return b.Pending != nil && reflect.DeepEqual(a.Resources, b.Resources)
	}
	if b.Pending != nil || a.Pending.Action != Create {
		return false
	}
	index := slices.IndexFunc(b.Resources, func(resource BaselineResource) bool { return resource.Key == a.Pending.Key })
	if index < 0 || slices.ContainsFunc(a.Resources, func(resource BaselineResource) bool { return resource.Key == a.Pending.Key }) || b.Resources[index].TemplateSHA256 != a.Pending.AfterSHA256 {
		return false
	}
	remaining := slices.Clone(b.Resources)
	remaining = slices.Delete(remaining, index, index+1)
	return reflect.DeepEqual(a.Resources, remaining)
}

func SortBaselineResources(resources []BaselineResource) {
	slices.SortFunc(resources, func(a, b BaselineResource) int { return strings.Compare(a.Key.String(), b.Key.String()) })
}
