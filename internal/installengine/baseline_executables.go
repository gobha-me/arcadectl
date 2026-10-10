// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"net/http"
	"reflect"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// This is complete read-only dependency evidence, not installer ownership.
// In-flight, foreign, terminal and deleting objects stay observable without
// becoming original inventory, adopted effects, parent authority or cleanup
// targets. Native denial of an observed Pod is a separate proof obligation.
type baselineExecutables struct {
	observation *installobserve.ExecutablesObservation
	whole       map[installstate.Key]*unstructured.Unstructured
	guarded     map[installstate.Key]*unstructured.Unstructured
}

var baselineExecutableCollections = [...]proofCollection{
	{"v1", "Pod", "pods", true},
	{"batch/v1", "Job", "jobs", true},
	{"apps/v1", "Deployment", "deployments", true},
	{"apps/v1", "ReplicaSet", "replicasets", true},
	{"apps/v1", "StatefulSet", "statefulsets", true},
	{"apps/v1", "DaemonSet", "daemonsets", true},
	{"v1", "ReplicationController", "replicationcontrollers", true},
	{"batch/v1", "CronJob", "cronjobs", true},
}

// Unlike the public effect transport this private route admits ONLY GET and
// list-permission derivation for eight fixed native executable families.
func baselineExecutableRead(key installstate.Key, verb string) (string, proofPermission, error) {
	if !installrender.ValidNamespace(key.Namespace) || !addressPart(key.Name) || verb != "get" && verb != "list" {
		return "", proofPermission{}, ErrInvalid
	}
	for _, c := range baselineExecutableCollections {
		if key.APIVersion != c.gv || key.Kind != c.kind {
			continue
		}
		gv, err := schema.ParseGroupVersion(c.gv)
		if err != nil {
			return "", proofPermission{}, ErrInvalid
		}
		prefix := "/apis/" + c.gv
		if c.gv == "v1" {
			prefix = "/api/v1"
		}
		path, name := prefix+"/namespaces/"+key.Namespace+"/"+c.plural, ""
		if verb == "get" {
			name = key.Name
			path += "/" + name
		}
		permission := proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: gv.Group, Version: gv.Version, Resource: c.plural, Namespace: key.Namespace, Name: name, Verb: verb}}, kind: c.kind}
		return path, permission, nil
	}
	return "", proofPermission{}, ErrInvalid
}

func baselineGuardedExecutable(key installstate.Key, object *unstructured.Unstructured) (bool, error) {
	if object == nil || object.GetAPIVersion() != key.APIVersion || object.GetKind() != key.Kind || object.GetNamespace() != key.Namespace || object.GetName() != key.Name {
		return false, ErrSecurityBaseline
	}
	if _, _, err := baselineExecutableRead(key, "get"); err != nil {
		return false, ErrSecurityBaseline
	}
	path := []string{"spec"}
	if key.Kind == "CronJob" {
		path = []string{"spec", "jobTemplate", "spec", "template", "spec"}
	} else if key.Kind != "Pod" {
		path = []string{"spec", "template", "spec"}
	}
	guarded := baselineReservedAccount(key.Name)
	// The API's deprecated alias is included conservatively; alias handling
	// cannot conceal a reserved identity. Strict native decoding is required
	// by the complete observer before this selection is reached.
	for _, alias := range []string{"serviceAccountName", "serviceAccount"} {
		account, _, err := unstructured.NestedString(object.Object, append(path, alias)...)
		if err != nil {
			return false, ErrSecurityBaseline
		}
		guarded = guarded || baselineReservedAccount(account)
	}
	return guarded, nil
}

func (c *ClusterSecurityBaseline) collectExecutables(ctx context.Context, snapshot *installstate.Snapshot) (*baselineExecutables, error) {
	if c == nil || c.engine == nil || c.engine.baseline == nil || c.access == nil || c.engine.access != c.access || !c.access.actorCompatible() || ctx == nil || snapshot == nil {
		return nil, ErrSecurityBaseline
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	plan := c.engine.plans[snapshot.Document().TargetPackage]
	if !plan.IsTrusted() || c.access.checkVersion(ctx, plan.Profile()) != nil {
		return nil, ErrSecurityBaseline
	}
	lifecycle := &Lifecycle{engine: c.engine}
	if _, err := lifecycle.original(ctx, snapshot); err != nil {
		return nil, ErrSecurityBaseline
	}
	discoveries := map[string]*metav1.APIResourceList{}
	for _, collection := range baselineExecutableCollections {
		key := installstate.Key{APIVersion: collection.gv, Kind: collection.kind, Namespace: snapshot.Anchor().Namespace, Name: "baseline-observation"}
		_, permission, err := baselineExecutableRead(key, "list")
		discovery := discoveries[collection.gv]
		if discovery == nil {
			discovery, err = c.access.discover(ctx, collection.gv)
			discoveries[collection.gv] = discovery
		}
		if err != nil || discovery == nil || !discoveredPermission(discovery, permission) || c.access.authorize(ctx, permission.spec) != nil {
			return nil, ErrSecurityBaseline
		}
	}
	observer, err := installobserve.New(c.access.readConfig(), c.engine.journal, plan)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	observation, err := observer.CollectExecutables(ctx, snapshot.Anchor())
	if err != nil || observation == nil || observation.Journal() == nil || observation.Journal().ResourceVersion() != snapshot.ResourceVersion() || !bytes.Equal(observation.Journal().Bytes(), snapshot.Bytes()) {
		return nil, ErrSecurityBaseline
	}
	whole := observation.Whole()
	if whole == nil {
		return nil, ErrSecurityBaseline
	}
	guarded := map[installstate.Key]*unstructured.Unstructured{}
	for key, listed := range whole {
		path, permission, err := baselineExecutableRead(key, "get")
		if err != nil || !discoveredPermission(discoveries[key.APIVersion], permission) || c.access.authorize(ctx, permission.spec) != nil {
			return nil, ErrSecurityBaseline
		}
		live, err := c.access.requestAt(ctx, http.MethodGet, key, nil, false, path, nil)
		if err != nil || live == nil || !baselineExecutableListedMatches(key, listed, live) {
			return nil, ErrSecurityBaseline
		}
		selected, err := baselineGuardedExecutable(key, live)
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		whole[key] = live
		if selected {
			guarded[key] = live.DeepCopy()
		}
	}
	if _, err := lifecycle.original(ctx, snapshot); err != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	return &baselineExecutables{observation, whole, guarded}, nil
}

func baselineExecutableListedMatches(key installstate.Key, listed, live *unstructured.Unstructured) bool {
	if listed == nil || live == nil || live.GetAPIVersion() != key.APIVersion || live.GetKind() != key.Kind || live.GetName() != key.Name || live.GetNamespace() != key.Namespace {
		return false
	}
	// Explicit native LIST-only omission is not the SDK's permissive
	// empty/null inference. Preserve the raw list, add only its reviewed
	// fixed envelope to a disposable comparison copy, and compare every
	// other raw field exactly. Partial/present-malformed envelopes refuse.
	comparison := listed.DeepCopy()
	gv, hasGV := comparison.Object["apiVersion"]
	kind, hasKind := comparison.Object["kind"]
	if hasGV != hasKind || hasGV && (gv != key.APIVersion || kind != key.Kind) {
		return false
	}
	if !hasGV {
		comparison.SetAPIVersion(key.APIVersion)
		comparison.SetKind(key.Kind)
	}
	return reflect.DeepEqual(comparison.Object, live.Object)
}

func sameBaselineExecutables(before, after *baselineExecutables) bool {
	return before != nil && after != nil && before.observation != nil && after.observation != nil && reflect.DeepEqual(before.whole, after.whole) && reflect.DeepEqual(before.guarded, after.guarded)
}
