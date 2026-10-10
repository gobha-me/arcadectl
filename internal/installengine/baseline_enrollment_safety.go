// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
)

// A private historical READ owner, not an effect permit or evidence that the
// new baseline is configured/effective. Its actual Complete Install, Upgrade
// or Rollback snapshot remains unchanged. Opening inputs belong to the caller
// and must remain held through eventual source publication and introduction.
type baselineEnrollmentSafety struct {
	self      *baselineEnrollmentSafety
	lifecycle *Lifecycle
	baseline  *ClusterSecurityBaseline
	snapshot  *installstate.Snapshot
	inputs    *baselineEnrollmentInputs
	source    *baselineEnrollmentSourceWitness
	options   LifecycleOptions
	opening   *baselineEnrollmentSafetyEvidence
}

type baselineEnrollmentSafetyEvidence struct {
	worlds      *coldWorldTuple
	secrets     map[string]*corev1.Secret
	access      map[installstate.Key]admissionIdentity
	policies    []retirementPolicy
	executables *baselineExecutables
	metadata    *baselineMetadata
	parents     map[string]*baselineParent
	family      *baselineFamilyWitness
	coldFamily  *baselineFamilyWitness
}

func (w *baselineEnrollmentSafetyEvidence) release() {
	if w != nil {
		w.metadata.release()
		releaseBaselineParents(w.parents)
	}
}

func (w *baselineEnrollmentSafety) release() {
	if w != nil && w.self == w {
		w.opening.release()
		w.self = nil
	}
}

// No caller-selected checks, alternate cluster, snapshot normalization, fresh
// bootstrap exception, effect permission catalog or runtime guard fallback.
func (l *Lifecycle) openBaselineEnrollmentSafety(ctx context.Context, snapshot *installstate.Snapshot, inputs *baselineEnrollmentInputs, source *baselineEnrollmentSourceWitness, options LifecycleOptions) (*baselineEnrollmentSafety, error) {
	if l == nil || l.engine == nil || l.secrets == nil || l.secrets.engine != l.engine || ctx == nil || ctx.Err() != nil || snapshot == nil || inputs == nil || options.Now.IsZero() {
		return nil, ErrSecurityBaseline
	}
	e := l.engine
	checks, ok := l.checks.(*clusterLifecycleChecks)
	access, direct := e.access.(*HTTPAccess)
	if !ok || checks == nil || !direct || access == nil || access.native == nil || !access.actorCompatible() || e.baseline == nil || e.journal == nil || e.journal.BaselineDigest() != e.baselinePlan().Digest() ||
		checks.prerequisites == nil || checks.prerequisites.engine != e || checks.prerequisites.access != access || checks.cold == nil || checks.cold.prerequisites != checks.prerequisites || checks.cold.games == nil {
		return nil, ErrSecurityBaseline
	}
	private, privateOK := l.secrets.access.(privateSecrets)
	if !privateOK || private.access != access || checks.admission == nil || checks.admission.prerequisites == nil || checks.admission.prerequisites.engine != e || checks.admission.prerequisites.access != access ||
		checks.quiescence == nil || checks.quiescence.prerequisites != checks.prerequisites || checks.controllers == nil || checks.controllers.prerequisites != checks.prerequisites || checks.activation == nil || checks.activation.prerequisites != checks.prerequisites {
		return nil, ErrSecurityBaseline
	}
	baseline, ok := e.baseline.runtimeGuard.(*ClusterSecurityBaseline)
	if !ok || baseline == nil || baseline != e.baseline.prerequisites || baseline.engine != e || baseline.access != access {
		return nil, ErrSecurityBaseline
	}
	w := &baselineEnrollmentSafety{lifecycle: l, baseline: baseline, snapshot: snapshot, inputs: inputs, source: source, options: options}
	w.self = w
	if w.eligible(ctx) != nil {
		return nil, ErrSecurityBaseline
	}
	ctx, cancel := context.WithTimeout(ctx, baselineRuntimeTimeout)
	defer cancel()
	transferred := false
	defer func() {
		if !transferred {
			w.release()
		}
	}()
	var err error
	w.opening, err = w.collect(ctx)
	if err != nil || w.close(ctx) != nil || w.verifyActorContainment(ctx) != nil {
		return nil, ErrSecurityBaseline
	}
	transferred = true
	return w, nil
}

func (w *baselineEnrollmentSafety) eligible(ctx context.Context) error {
	if w == nil || w.self != w || w.lifecycle == nil || w.lifecycle.engine == nil || w.snapshot == nil || w.inputs == nil || ctx == nil || ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	e := w.lifecycle.engine
	if w.inputs.confirm(ctx, e, w.snapshot.Anchor()) != nil {
		return ErrSecurityBaseline
	}
	if w.source == nil {
		if !e.historicalEnrollmentSource(w.snapshot.Document()) {
			return ErrSecurityBaseline
		}
	} else if w.source.inputs != w.inputs || e.confirmBaselineEnrollmentSource(ctx, w.source, w.snapshot) != nil {
		return ErrSecurityBaseline
	}
	return nil
}

// Full original evidence is collected before and after each enclosing review
// interval. Coldness is evaluated on its OWN complete observation; the raw
// executable observation is independently classified, never substituted for it.
func (w *baselineEnrollmentSafety) collect(ctx context.Context) (*baselineEnrollmentSafetyEvidence, error) {
	if w.eligible(ctx) != nil || w.baseline == nil {
		return nil, ErrSecurityBaseline
	}
	l, e := w.lifecycle, w.lifecycle.engine
	checks, ok := l.checks.(*clusterLifecycleChecks)
	if !ok || checks == nil || checks.prerequisites == nil || checks.cold == nil {
		return nil, ErrSecurityBaseline
	}
	p, d := checks.prerequisites, w.snapshot.Document()
	plan := e.plans[d.TargetPackage]
	if !plan.IsTrusted() || w.baseline.access.checkVersion(ctx, plan.Profile()) != nil || p.authorizeObservationReads(ctx, w.snapshot, nil) != nil {
		return nil, ErrSecurityBaseline
	}
	// Historical/source eligibility already requires the exact target-ready
	// catalog. Prove its signed whole objects and CRD health without demanding
	// current workload availability: an unready original is not a foreign one.
	if _, err := l.original(ctx, w.snapshot); err != nil || l.inventory(ctx, w.snapshot, true, false) != nil {
		return nil, ErrSecurityBaseline
	}
	observed := &baselineEnrollmentSafetyEvidence{}
	transferred := false
	defer func() {
		if !transferred {
			observed.release()
		}
	}()
	var err error
	secrets, caID, err := l.secrets.readRetainedObjects(ctx, w.snapshot, w.options.Activation.CAFile, w.options.Now)
	if err != nil || caID != w.inputs.caID {
		return nil, ErrSecurityBaseline
	}
	observed.secrets = secrets
	observed.access, err = e.baseline.readOriginalRuntimeAccess(ctx, w.snapshot)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	observed.policies, err = e.retirementPolicies(ctx, w.snapshot)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	observed.executables, err = w.baseline.collectExecutables(ctx, w.snapshot)
	if err != nil || baselineDeniedObservation(w.snapshot, observed.executables) != nil {
		return nil, ErrSecurityBaseline
	}
	observed.metadata, err = w.baseline.originalMetadata(ctx, w.snapshot)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	observed.parents, err = w.baseline.originalParents(ctx, w.snapshot, observed.executables)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	observed.family, err = e.baselineDescendants(d, observed.parents, observed.access, observed.executables.observation.Collections())
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	request := LifecycleCheck{Checkpoint: ColdSafety, Snapshot: w.snapshot, Mode: d.Mode, Target: plan, Options: w.options}
	cold, err := p.collectOriginalObservation(ctx, request)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	observed.worlds, _, _, _, err = checks.cold.evaluateEvidence(ctx, request, cold)
	if err != nil || w.source != nil && w.source.matchesWorlds(observed.worlds) != nil {
		return nil, ErrSecurityBaseline
	}
	objects := baselineEnrollmentColdExecutables(cold)
	observed.coldFamily, err = e.baselineDescendants(d, observed.parents, observed.access, objects)
	if err != nil || !reflect.DeepEqual(observed.family, observed.coldFamily) {
		return nil, ErrSecurityBaseline
	}
	if w.closeAuthority(ctx, observed) != nil {
		return nil, ErrSecurityBaseline
	}
	if _, err := l.original(ctx, w.snapshot); err != nil {
		return nil, ErrSecurityBaseline
	}
	// The final original read is itself a remote interval. Close both original
	// Secrets afterwards, then only confirm already-held local descriptors.
	secrets, caID, err = l.secrets.readRetainedObjects(ctx, w.snapshot, w.options.Activation.CAFile, w.options.Now)
	if err != nil || caID != w.inputs.caID || !reflect.DeepEqual(secrets, observed.secrets) || w.confirmLocal(ctx, observed) != nil {
		return nil, ErrSecurityBaseline
	}
	transferred = true
	return observed, nil
}

func (w *baselineEnrollmentSafety) closeAuthority(ctx context.Context, evidence *baselineEnrollmentSafetyEvidence) error {
	if w.eligible(ctx) != nil || evidence == nil {
		return ErrSecurityBaseline
	}
	e := w.lifecycle.engine
	for pass := 0; pass < 2; pass++ {
		access, err := e.baseline.readOriginalRuntimeAccess(ctx, w.snapshot)
		if err != nil || !reflect.DeepEqual(access, evidence.access) {
			return ErrSecurityBaseline
		}
		if pass == 0 {
			policies, err := e.retirementPolicies(ctx, w.snapshot)
			if err != nil || !reflect.DeepEqual(policies, evidence.policies) {
				return ErrSecurityBaseline
			}
		}
	}
	return nil
}

func baselineEnrollmentColdExecutables(observation *installobserve.Observation) *installobserve.ExecutableCollections {
	if observation == nil {
		return nil
	}
	s, r := observation.Snapshot(), observation.Runtime()
	if s == nil || r == nil {
		return nil
	}
	return &installobserve.ExecutableCollections{Pods: s.Pods, Jobs: s.Jobs, Deployments: r.Deployments, ReplicaSets: r.ReplicaSets, StatefulSets: r.StatefulSets, DaemonSets: r.DaemonSets, ReplicationControllers: r.ReplicationControllers, CronJobs: r.CronJobs}
}

func sameBaselineEnrollmentSafety(a, b *baselineEnrollmentSafetyEvidence) bool {
	if a == nil || b == nil || a.worlds == nil || b.worlds == nil || len(a.secrets) != 2 || len(b.secrets) != 2 || a.access == nil || b.access == nil || len(a.policies) != 12 || len(b.policies) != 12 || a.family == nil || b.family == nil || a.coldFamily == nil || b.coldFamily == nil {
		return false
	}
	before, err := a.worlds.witness()
	after, afterErr := b.worlds.witness()
	return err == nil && afterErr == nil && before == after && reflect.DeepEqual(a.secrets, b.secrets) && reflect.DeepEqual(a.access, b.access) && reflect.DeepEqual(a.policies, b.policies) &&
		sameBaselineExecutables(a.executables, b.executables) && sameBaselineMetadata(a.metadata, b.metadata) && sameBaselineParents(a.parents, b.parents) &&
		reflect.DeepEqual(a.family, b.family) && reflect.DeepEqual(a.coldFamily, b.coldFamily)
}

// Final local checks follow the LAST original remote fence. Keep the opening
// owners alive: reacquiring equivalent files would not detect replacement.
func (w *baselineEnrollmentSafety) confirmLocal(ctx context.Context, evidence *baselineEnrollmentSafetyEvidence) error {
	if w.eligible(ctx) != nil || evidence == nil || evidence.metadata == nil || evidence.parents == nil || baselineDeniedObservation(w.snapshot, evidence.executables) != nil {
		return ErrSecurityBaseline
	}
	e := w.lifecycle.engine
	family, err := e.baselineDescendants(w.snapshot.Document(), evidence.parents, evidence.access, evidence.executables.observation.Collections())
	if err != nil || !reflect.DeepEqual(family, evidence.family) || !reflect.DeepEqual(family, evidence.coldFamily) {
		return ErrSecurityBaseline
	}
	for key, identity := range evidence.access {
		if !baselineMetadataKey(w.snapshot.Anchor().Namespace, key) {
			continue
		}
		object := evidence.metadata.objects[key]
		if object == nil || object.whole == nil || object.template == nil || object.whole.GetUID() != identity.UID || object.whole.GetResourceVersion() != identity.ResourceVersion || object.template.Hash() != identity.TemplateSHA256 {
			return ErrSecurityBaseline
		}
	}
	if e.confirmBaselineMetadataReceipts(evidence.metadata) != nil || e.confirmBaselineParentReceipts(w.snapshot.Document(), evidence.parents) != nil ||
		w.source != nil && w.source.matchesWorlds(evidence.worlds) != nil || ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

func (w *baselineEnrollmentSafety) close(ctx context.Context) error {
	if w == nil || w.opening == nil || w.eligible(ctx) != nil {
		return ErrSecurityBaseline
	}
	closing, err := w.collect(ctx)
	if err != nil {
		return ErrSecurityBaseline
	}
	defer closing.release()
	if !sameBaselineEnrollmentSafety(w.opening, closing) || w.confirmLocal(ctx, w.opening) != nil {
		return ErrSecurityBaseline
	}
	return nil
}

// Reviews the existing two software identities only. No new accounts, grants,
// tokens, dry-run workload probes or reusable actor clients escape. Wildcard
// impersonation SSAR decisions are NOT actual header-impersonation/admission
// behavior; that full new-baseline proof remains mandatory after settlement.
func (w *baselineEnrollmentSafety) verifyActorContainment(ctx context.Context) error {
	if w == nil || w.opening == nil || w.confirmLocal(ctx, w.opening) != nil {
		return ErrSecurityBaseline
	}
	e, access := w.lifecycle.engine, w.baseline.access
	scope, err := e.baselineDeniedCatalog(w.snapshot.Document(), w.opening.access, w.opening.executables.guarded)
	if err != nil {
		return ErrSecurityBaseline
	}
	maintenance, denied, rules := map[admissionActor]*HTTPAccess{}, map[admissionActor]*HTTPAccess{}, map[admissionActor]*HTTPAccess{}
	openingRules := map[admissionActor]*baselineRulesEvidence{}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		permission := baselineMaintenancePermission(w.snapshot.Anchor().Namespace)
		permission.ResourceAttributes.Name = actor.account()
		if access.authorize(ctx, permission) != nil {
			return ErrSecurityBaseline
		}
		maintenance[actor], err = access.actorClientForPurpose(actor, w.snapshot.Anchor().Namespace, baselineAdmissionPurpose)
		if err != nil {
			return ErrSecurityBaseline
		}
		denied[actor], err = access.baselineDeniedClient(actor, scope)
		if err != nil {
			return ErrSecurityBaseline
		}
		rules[actor], err = access.baselineRulesClient(actor, w.snapshot.Anchor().Namespace)
		if err != nil {
			return ErrSecurityBaseline
		}
		openingRules[actor], err = rules[actor].baselineRules(ctx)
		if err != nil || !baselineProxyRulesContained(openingRules[actor], w.opening.executables) {
			return ErrSecurityBaseline
		}
	}
	for pass := 0; pass < 2; pass++ {
		for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
			for _, permission := range baselineAuthorizationContainmentPermissions(w.snapshot.Anchor().Namespace) {
				if maintenance[actor].authorizationDecision(ctx, permission, false) != nil {
					return ErrSecurityBaseline
				}
			}
			for _, row := range scope.rows[actor] {
				if denied[actor].authorizationDecision(ctx, authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: row.attributes()}, false) != nil {
					return ErrSecurityBaseline
				}
			}
		}
		if w.close(ctx) != nil {
			return ErrSecurityBaseline
		}
		for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
			closing, err := rules[actor].baselineRules(ctx)
			if err != nil || !baselineProxyRulesContained(closing, w.opening.executables) || !sameBaselineRules(openingRules[actor], closing) {
				return ErrSecurityBaseline
			}
		}
		// SSRRs are remote intervals too. Recollect worlds, executables and
		// original metadata/parents, not just the authority maps, afterwards.
		if w.close(ctx) != nil {
			return ErrSecurityBaseline
		}
	}
	if _, err := w.lifecycle.original(ctx, w.snapshot); err != nil {
		return ErrSecurityBaseline
	}
	secrets, caID, err := w.lifecycle.secrets.readRetainedObjects(ctx, w.snapshot, w.options.Activation.CAFile, w.options.Now)
	if err != nil || caID != w.inputs.caID || !reflect.DeepEqual(secrets, w.opening.secrets) || w.confirmLocal(ctx, w.opening) != nil {
		return ErrSecurityBaseline
	}
	return nil
}
