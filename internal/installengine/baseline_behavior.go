// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"net/http"
	"reflect"
	"sort"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// A closed observation, never caller-supplied probes, effect permission or a
// persistent success receipt. Verify dispatches to this active proof or the
// distinct retirement proof; installer enrollment and production lifecycle
// wiring remain separate requirements.
type baselineBehavior struct {
	actors      *baselineActors
	executables *baselineExecutables
	metadata    *baselineMetadata
	parents     map[string]*baselineParent
	family      *baselineFamilyWitness
}

func (b *baselineBehavior) release() {
	if b != nil {
		b.metadata.release()
		releaseBaselineParents(b.parents)
	}
}

func (c *ClusterSecurityBaseline) newBaselineBehavior(ctx context.Context, snapshot *installstate.Snapshot) (*baselineBehavior, error) {
	traceBaselineBoundary(ctx, baselineBoundaryActors)
	actors, err := c.newBaselineActors(ctx, snapshot)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	traceBaselineBoundary(ctx, baselineBoundaryExecutables)
	executables, err := c.collectExecutables(ctx, snapshot)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	traceBaselineBoundary(ctx, baselineBoundaryMetadata)
	metadata, err := c.originalMetadata(ctx, snapshot)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	transferred := false
	defer func() {
		if !transferred {
			metadata.release()
		}
	}()
	traceBaselineBoundary(ctx, baselineBoundaryParents)
	parents, err := c.originalParents(ctx, snapshot, executables)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	defer func() {
		if !transferred {
			releaseBaselineParents(parents)
		}
	}()
	traceBaselineBoundary(ctx, baselineBoundaryFamily)
	family, err := c.engine.baselineDescendants(snapshot.Document(), parents, actors.access, executables.observation.Collections())
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	// Metadata cannot silently substitute another access UID/RV or before/after
	// template than the same opening actor authority witness.
	for key, identity := range actors.access {
		if !baselineMetadataKey(snapshot.Anchor().Namespace, key) {
			continue
		}
		object := metadata.objects[key]
		if object == nil || object.whole.GetUID() != identity.UID || object.whole.GetResourceVersion() != identity.ResourceVersion || object.template.Hash() != identity.TemplateSHA256 {
			return nil, ErrSecurityBaseline
		}
	}
	traceBaselineBoundary(ctx, baselineBoundaryActorClose)
	if actors.verify(ctx) != nil {
		return nil, ErrSecurityBaseline
	}
	transferred = true
	return &baselineBehavior{actors, executables, metadata, parents, family}, nil
}

func (b *baselineBehavior) prove(ctx context.Context) error {
	if b == nil || b.actors == nil || b.actors.baseline == nil || b.actors.snapshot == nil || b.metadata == nil || b.parents == nil || b.family == nil || ctx == nil ||
		!sameBaselineMetadata(b.metadata, b.metadata) || b.metadata.snapshot.Anchor() != b.actors.snapshot.Anchor() || b.metadata.snapshot.ResourceVersion() != b.actors.snapshot.ResourceVersion() || !reflect.DeepEqual(b.metadata.snapshot.Bytes(), b.actors.snapshot.Bytes()) || baselineDeniedObservation(b.actors.snapshot, b.executables) != nil {
		return ErrSecurityBaseline
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	traceBaselineBoundary(ctx, baselineBoundaryDeniedOpening)
	if b.actors.verifyDeniedBehavior(ctx, b) != nil {
		return ErrSecurityBaseline
	}
	c := b.actors.baseline
	plan := c.engine.plans[b.actors.snapshot.Document().TargetPackage]
	templatePolicy := "arcadectl-identity-template-" + plan.Namespace()
	identityPolicy := "arcadectl-identity-identity-" + plan.Namespace()
	podPolicy := "arcadectl-identity-pod-" + plan.Namespace()
	for _, row := range []struct {
		actor admissionActor
		kind  string
	}{{ordinaryControllerActor, "Job"}, {destroyControllerActor, "Job"}, {ordinaryControllerActor, "Deployment"}} {
		nonce, err := installstate.NewID()
		if err != nil {
			return ErrSecurityBaseline
		}
		traceBaselineBoundary(ctx, baselineBoundaryProducerBefore)
		positive, err := baselineProducerProbe(plan, row.kind, nonce)
		if err != nil || b.readExact(ctx, baselineObjectKey(positive), nil) != nil {
			return ErrSecurityBaseline
		}
		start := time.Now().UTC()
		traceBaselineBoundary(ctx, baselineBoundaryProducerWire)
		reply, err := b.actors.probe(ctx, row.actor, probeCreateOperation, positive, "", "", "")
		end := time.Now().UTC()
		if err != nil {
			return ErrSecurityBaseline
		}
		traceBaselineBoundary(ctx, baselineBoundaryProducerResult)
		if !validBaselineProducerResult(plan, row.kind, nonce, reply, start, end) {
			return ErrSecurityBaseline
		}
		traceBaselineBoundary(ctx, baselineBoundaryProducerAfter)
		if b.readExact(ctx, baselineObjectKey(positive), nil) != nil {
			return ErrSecurityBaseline
		}
		traceBaselineBoundary(ctx, baselineBoundaryProducerNegative)
		for _, reserved := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
			for _, variant := range []baselineProducerNegative{baselineProducerReservedAccount, baselineProducerReservedName} {
				negative, err := baselineNegativeProducerProbe(plan, row.kind, nonce, variant, reserved)
				if err != nil {
					return ErrSecurityBaseline
				}
				key := baselineObjectKey(negative)
				if b.denial(ctx, row.actor, probeCreateOperation, negative, b.executables.whole[key], templatePolicy) != nil {
					return ErrSecurityBaseline
				}
			}
		}
	}
	traceBaselineBoundary(ctx, baselineBoundaryIdentity)
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		for _, key := range baselineMetadataKeys(plan.Namespace()) {
			if key.Kind == "Service" && actor != ordinaryControllerActor {
				continue // Unsupported tuples belong to the denied SSAR catalog.
			}
			create, err := baselineIdentityCreateProbe(plan, actor, key.Kind, key.Name)
			if err != nil {
				return ErrSecurityBaseline
			}
			var original *unstructured.Unstructured
			if object := b.metadata.objects[key]; object != nil {
				original = object.whole
			}
			if b.denial(ctx, actor, probeCreateOperation, create, original, identityPolicy) != nil {
				return ErrSecurityBaseline
			}
			if original == nil {
				continue // Proven absence, not a reason to persist a fixture seed.
			}
			operations := []admissionProbeOperation{probeDeleteIdentityOperation}
			if key.Kind == "ServiceAccount" {
				operations = []admissionProbeOperation{probeDeleteAccountOperation}
			} else if key.Kind == "Service" {
				operations = []admissionProbeOperation{probeUpdateOperation, probePatchMetadataOperation, probeDeleteIdentityOperation}
			}
			for _, operation := range operations {
				candidate := original
				if operation == probeUpdateOperation {
					candidate, err = baselineMetadataUpdateProbe(plan.Namespace(), key, original)
					if err != nil {
						return ErrSecurityBaseline
					}
				}
				if b.denial(ctx, actor, operation, candidate, original, identityPolicy) != nil {
					return ErrSecurityBaseline
				}
			}
		}
	}
	traceBaselineBoundary(ctx, baselineBoundaryParentProbe)
	for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller"} {
		parent := b.parents[name]
		if parent == nil {
			continue
		}
		for _, operation := range []admissionProbeOperation{probeUpdateOperation, probePatchMetadataOperation, probeDeleteExecutableOperation} {
			candidate := parent.whole
			if operation == probeUpdateOperation {
				var err error
				candidate, err = baselineMetadataUpdateProbe(plan.Namespace(), deploymentKey(plan.Namespace(), name), parent.whole)
				if err != nil {
					return ErrSecurityBaseline
				}
			}
			if b.denial(ctx, ordinaryControllerActor, operation, candidate, parent.whole, templatePolicy) != nil {
				return ErrSecurityBaseline
			}
		}
	}
	traceBaselineBoundary(ctx, baselineBoundaryPodProbe)
	keys := make([]installstate.Key, 0, len(b.family.pods))
	for key := range b.family.pods {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	for _, key := range keys {
		original := b.executables.whole[key]
		if original == nil || original.GetUID() != b.family.pods[key] {
			return ErrSecurityBaseline
		}
		candidate, err := baselineMetadataUpdateProbe(plan.Namespace(), key, original)
		if err != nil {
			return ErrSecurityBaseline
		}
		for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
			if b.denial(ctx, actor, probeUpdateOperation, candidate, original, podPolicy) != nil {
				return ErrSecurityBaseline
			}
		}
	}
	traceBaselineBoundary(ctx, baselineBoundaryClosing)
	return b.close(ctx)
}

func baselineObjectKey(object *unstructured.Unstructured) installstate.Key {
	if object == nil {
		return installstate.Key{}
	}
	return installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
}

func (b *baselineBehavior) denial(ctx context.Context, actor admissionActor, operation admissionProbeOperation, candidate, original *unstructured.Unstructured, policy string) error {
	key := baselineObjectKey(candidate)
	if b.readExactDiagnostic(ctx, key, original, baselineFailureDenialBefore) != nil {
		return ErrSecurityBaseline
	}
	reply, err := b.actors.probe(ctx, actor, operation, candidate, policy, policy, installbaseline.DenialMessage)
	if err != nil || reply != nil {
		traceBaselineFailure(ctx, baselineFailureDenialProbe, key.Kind, 0)
		return ErrSecurityBaseline
	}
	if b.readExactDiagnostic(ctx, key, original, baselineFailureDenialAfter) != nil {
		return ErrSecurityBaseline
	}
	return nil
}

func (b *baselineBehavior) readExact(ctx context.Context, key installstate.Key, original *unstructured.Unstructured) error {
	return b.readExactDiagnostic(ctx, key, original, 0)
}

func (b *baselineBehavior) readExactDiagnostic(ctx context.Context, key installstate.Key, original *unstructured.Unstructured, check baselineFailureCheck) error {
	refuse := func(fields baselineDifference) error {
		traceBaselineFailure(ctx, check, key.Kind, fields)
		return ErrSecurityBaseline
	}
	if b == nil || b.actors == nil || b.actors.baseline == nil || b.actors.snapshot == nil || key.Namespace != b.actors.snapshot.Anchor().Namespace {
		return refuse(0)
	}
	c := b.actors.baseline
	path, permission, err := baselineExecutableRead(key, "get")
	if err != nil && baselineMetadataKey(key.Namespace, key) {
		path, err = resourcePath(key, false)
		if err == nil {
			permission, err = publicPermission(key, "get")
		}
	}
	if err != nil {
		return refuse(0)
	}
	discovery, err := c.access.discover(ctx, key.APIVersion)
	if err != nil || !discoveredPermission(discovery, permission) || c.access.authorize(ctx, permission.spec) != nil {
		return refuse(0)
	}
	live, err := c.access.requestAt(ctx, http.MethodGet, key, nil, false, path, nil)
	if original == nil {
		if !apierrors.IsNotFound(err) {
			if err == nil && live != nil {
				return refuse(baselineDifferenceMembership)
			}
			return refuse(0)
		}
	} else if err != nil || live == nil || !reflect.DeepEqual(live.Object, original.Object) {
		if err == nil && live != nil {
			traceBaselineObjectFailure(ctx, check, key, original, live)
			return ErrSecurityBaseline
		}
		return refuse(0)
	}
	return nil
}

func (b *baselineBehavior) close(ctx context.Context) error {
	c, snapshot := b.actors.baseline, b.actors.snapshot
	executables, err := c.collectExecutables(ctx, snapshot)
	if err != nil || !sameBaselineExecutables(b.executables, executables) {
		return ErrSecurityBaseline
	}
	if b.closeOriginals(ctx, executables) != nil {
		return ErrSecurityBaseline
	}
	// Close both effective rules and complete executable membership AFTER the
	// initial metadata/parent remote windows; each of the final catalog's two
	// closing bundles repeats original metadata/parents/family too.
	if _, err := (&Lifecycle{engine: c.engine}).original(ctx, snapshot); err != nil || ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	if b.actors.verifyDeniedBehavior(ctx, b) != nil {
		return ErrSecurityBaseline
	}
	// The opening receipt identities survive through ALL final remote reads.
	if c.engine.confirmBaselineParentReceipts(snapshot.Document(), b.parents) != nil || c.engine.confirmBaselineMetadataReceipts(b.metadata) != nil || ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

// A complete closing original-object bundle inside each denied catalog pass.
// No remote trailing retry loop or atomic cluster-read claim is introduced.
func (b *baselineBehavior) closeOriginals(ctx context.Context, executables *baselineExecutables) error {
	if b == nil || b.actors == nil || b.actors.baseline == nil || b.actors.snapshot == nil {
		return ErrSecurityBaseline
	}
	c, snapshot := b.actors.baseline, b.actors.snapshot
	traceBaselineBoundary(ctx, baselineBoundaryClosingMetadata)
	metadata, err := c.originalMetadata(ctx, snapshot)
	if err != nil {
		return ErrSecurityBaseline
	}
	defer metadata.release()
	if !sameBaselineMetadata(b.metadata, metadata) {
		return ErrSecurityBaseline
	}
	traceBaselineBoundary(ctx, baselineBoundaryClosingParents)
	parents, err := c.originalParents(ctx, snapshot, executables)
	if err != nil {
		return ErrSecurityBaseline
	}
	defer releaseBaselineParents(parents)
	if !sameBaselineParents(b.parents, parents) {
		return ErrSecurityBaseline
	}
	traceBaselineBoundary(ctx, baselineBoundaryClosingFamily)
	family, err := c.engine.baselineDescendants(snapshot.Document(), parents, b.actors.access, executables.observation.Collections())
	if err != nil || !reflect.DeepEqual(b.family, family) {
		return ErrSecurityBaseline
	}
	return nil
}
