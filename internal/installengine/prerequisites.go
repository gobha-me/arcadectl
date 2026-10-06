// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var ErrPrerequisites = errors.New("installation cluster prerequisites are unproved")

// ClusterPrerequisites is the closed production version/discovery/permission
// portion of LifecycleChecks. It is NOT yet a complete LifecycleChecks provider:
// admission behavior, quiescence/cold observations and activation are separate
// mandatory checks. No successful partial proof authorizes a resource effect.
type ClusterPrerequisites struct {
	engine *Engine
	access *HTTPAccess
}

func NewClusterPrerequisites(engine *Engine, access *HTTPAccess) (*ClusterPrerequisites, error) {
	if engine == nil || access == nil || engine.access != access || engine.journal == nil || engine.files == nil || len(engine.plans) == 0 {
		return nil, ErrInvalid
	}
	return &ClusterPrerequisites{engine, access}, nil
}

type proofPermission struct {
	spec authv1.SelfSubjectAccessReviewSpec
	kind string // required exact discovery kind; not an authorization wildcard
}

type proofCollection struct {
	gv, kind, plural string
	namespaced       bool
}

var proofCollections = []proofCollection{
	{"arcade.gobha.me/v1alpha1", "GameServer", "gameservers", true},
	{"arcade.gobha.me/v1alpha1", "GameBackup", "gamebackups", true},
	{"arcade.gobha.me/v1alpha1", "GameRestore", "gamerestores", true},
	{"arcade.gobha.me/v1alpha1", "GameDestroy", "gamedestroys", true},
	{"arcade.gobha.me/v1alpha1", "ArcadeOperation", "arcadeoperations", true},
	{"batch/v1", "Job", "jobs", true}, {"v1", "Pod", "pods", true},
	{"coordination.k8s.io/v1", "Lease", "leases", true},
	{"v1", "PersistentVolumeClaim", "persistentvolumeclaims", true},
	{"v1", "Secret", "secrets", true},
	{"admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", "validatingadmissionpolicies", false},
	{"admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicyBinding", "validatingadmissionpolicybindings", false},
	{"apps/v1", "ReplicaSet", "replicasets", true},
	{"apps/v1", "Deployment", "deployments", true},
	{"apps/v1", "StatefulSet", "statefulsets", true},
	{"apps/v1", "DaemonSet", "daemonsets", true},
	{"v1", "ReplicationController", "replicationcontrollers", true},
	{"batch/v1", "CronJob", "cronjobs", true},
	{"storage.k8s.io/v1", "VolumeAttachment", "volumeattachments", false},
	{"discovery.k8s.io/v1", "EndpointSlice", "endpointslices", true},
}

func publicPermission(key installstate.Key, verb string) (proofPermission, error) {
	path, err := resourcePath(key, true)
	if err != nil {
		return proofPermission{}, err
	}
	gv, err := schema.ParseGroupVersion(key.APIVersion)
	if err != nil {
		return proofPermission{}, ErrInvalid
	}
	name := key.Name
	if verb == "create" || verb == "list" {
		name = "" // collection CREATE authorization cannot restrict metadata.name
	}
	return proofPermission{authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: gv.Group, Version: gv.Version, Resource: path[strings.LastIndex(path, "/")+1:], Namespace: key.Namespace, Name: name, Verb: verb}}, key.Kind}, nil
}

func (p *ClusterPrerequisites) permissions(request LifecycleCheck) ([]proofPermission, error) {
	if request.Snapshot == nil {
		return nil, ErrInvalid
	}
	d := request.Snapshot.Document()
	return p.documentPermissions(d, request.Mode, request.Target)
}

// documentPermissions also derives fresh bootstrap authorization without
// manufacturing a sealed namespace snapshot before the namespace exists.
func (p *ClusterPrerequisites) documentPermissions(d installstate.Document, mode installstate.Mode, target *installrender.Plan) ([]proofPermission, error) {
	if !target.IsTrusted() || p.engine.plans[target.Digest()] != target || target.Namespace() != d.Namespace || target.Profile().ID != d.ProfileID {
		return nil, ErrInvalid
	}
	trial := d
	trial.Mode, trial.TargetPackage = mode, target.Digest()
	if !p.engine.compatible(trial) {
		return nil, ErrInvalid
	}
	var permissions []proofPermission
	addPublic := func(key installstate.Key, verb string) error {
		r, err := publicPermission(key, verb)
		if err == nil {
			permissions = append(permissions, r)
		}
		return err
	}
	if err := addPublic(namespaceKey(d.Namespace), "update"); err != nil {
		return nil, err
	}
	quiescing := d.Stage == installstate.Complete || d.Stage == installstate.Preparing || d.Stage == installstate.Quiescing || d.Stage == installstate.RecoveryRequired
	for _, resource := range target.Resources() {
		key := resourceKey(resource)
		if err := addPublic(key, "get"); err != nil {
			return nil, err
		}
		if key.Kind == "Namespace" {
			continue // bootstrap alone owns namespace CREATE; never DELETE
		}
		entry, _ := p.engine.inventory(d, key)
		want, err := p.engine.contracts[target.Digest()].Template(key, false)
		if err != nil {
			return nil, err
		}
		if mode == installstate.Uninstall {
			if entry != nil && !entry.Retained {
				if err := addPublic(key, "delete"); err != nil {
					return nil, err
				}
			}
		} else if key.Kind == "Deployment" && key.Name == "arcadectl-api" && mode != installstate.Install && quiescing {
			if entry != nil {
				if err := addPublic(key, "delete"); err != nil {
					return nil, err
				}
			}
			if err := addPublic(key, "create"); err != nil {
				return nil, err
			}
		} else if entry == nil {
			if err := addPublic(key, "create"); err != nil {
				return nil, err
			}
		} else if entry.TemplateSHA256 != want.Hash() {
			if mode == installstate.Install {
				return nil, ErrOwnership
			}
			if err := addPublic(key, "update"); err != nil {
				return nil, err
			}
		}
		if key.Kind == "Deployment" && key.Name != "arcadectl-api" && mode != installstate.Install && quiescing && entry != nil {
			paused, err := p.engine.contracts[d.ActivePackage].Template(key, true)
			if err != nil {
				return nil, err
			}
			if entry.TemplateSHA256 != paused.Hash() {
				if err := addPublic(key, "update"); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, c := range proofCollections {
		gv, _ := schema.ParseGroupVersion(c.gv)
		ns := ""
		if c.namespaced {
			ns = d.Namespace
		}
		permissions = append(permissions, proofPermission{authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: gv.Group, Version: gv.Version, Resource: c.plural, Namespace: ns, Verb: "list"}}, c.kind})
		if (c.kind == "Pod" || c.kind == "ReplicaSet") && mode != installstate.Uninstall {
			permissions = append(permissions, proofPermission{authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: gv.Group, Version: gv.Version, Resource: c.plural, Namespace: ns, Verb: "get"}}, c.kind})
		}
		if c.kind == "Pod" || c.kind == "PersistentVolumeClaim" || c.kind == "GameDestroy" {
			permissions = append(permissions, proofPermission{authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: gv.Group, Version: gv.Version, Resource: c.plural, Namespace: ns, Verb: "create"}}, c.kind})
		}
	}
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		r := proofPermission{authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "v1", Resource: "secrets", Namespace: d.Namespace, Name: name, Verb: "get"}}, "Secret"}
		permissions = append(permissions, r)
		if entry, _ := p.engine.inventory(d, secretKey(d.Namespace, name)); entry == nil {
			if mode != installstate.Install || d.ActivePackage != "" {
				return nil, ErrOwnership
			}
			create := r
			attrs := *r.spec.ResourceAttributes
			attrs.Name, attrs.Verb = "", "create"
			create.spec.ResourceAttributes = &attrs
			permissions = append(permissions, create)
		}
	}
	if mode != installstate.Uninstall {
		permissions = append(permissions, proofPermission{authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "v1", Resource: "pods", Subresource: "portforward", Namespace: d.Namespace, Verb: "create"}}, "PodPortForwardOptions"})
	}
	for _, gv := range proofGroups {
		path, _ := discoveryPath(gv)
		permissions = append(permissions, proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{NonResourceAttributes: &authv1.NonResourceAttributes{Path: path, Verb: "get"}}})
	}
	permissions = append(permissions, proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{NonResourceAttributes: &authv1.NonResourceAttributes{Path: "/version", Verb: "get"}}})
	// Deterministic bounded requests; no selectors, wildcard resources, patch,
	// watch, deletecollection, impersonation, Secret updates or PVC deletes.
	unique := map[string]proofPermission{}
	for _, r := range permissions {
		encoded, _ := json.Marshal(r.spec)
		unique[string(encoded)] = r
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if len(keys) > 256 {
		return nil, ErrInvalid
	}
	result := make([]proofPermission, 0, len(keys))
	for _, key := range keys {
		result = append(result, unique[key])
	}
	return result, nil
}

func (p *ClusterPrerequisites) original(ctx context.Context, s *installstate.Snapshot) error {
	if s == nil {
		return ErrInvalid
	}
	fresh, err := p.engine.journal.Load(ctx, s.Anchor())
	if err != nil || fresh.ResourceVersion() != s.ResourceVersion() || !bytes.Equal(fresh.Bytes(), s.Bytes()) {
		return ErrConcurrent
	}
	t, err := p.engine.contracts[s.Document().TargetPackage].Template(namespaceKey(s.Anchor().Namespace), false)
	live, readErr := p.access.Get(ctx, namespaceKey(s.Anchor().Namespace))
	if err != nil || readErr != nil || t.MatchNamespace(live, s) != nil {
		return ErrOwnership
	}
	return nil
}

// Verify checks only version/discovery/permission and protected TLS/native-route
// prerequisites. Registry, CSI, game-network and repository behavior are proved
// by the corresponding actual workloads/operations, not manufactured here.
func (p *ClusterPrerequisites) Verify(ctx context.Context, request LifecycleCheck) error {
	if p == nil || ctx == nil || request.Checkpoint != Prerequisites || request.Snapshot == nil || !request.Target.IsTrusted() || request.Options.Now.IsZero() {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := p.original(ctx, request.Snapshot); err != nil {
		return ErrPrerequisites
	}
	permissions, err := p.permissions(request)
	if err != nil || p.verifyAccess(ctx, request.Target, permissions) != nil {
		return ErrPrerequisites
	}
	if request.Mode != installstate.Uninstall && p.access.native == nil {
		return ErrPrerequisites
	}
	d := request.Snapshot.Document()
	if request.Mode == installstate.Install && d.ActivePackage == "" {
		activationCA, _, boundErr := privatefs.ReadAbsolute(request.Options.Activation.CAFile, 65536, privatefs.TrustedPublic)
		if boundErr != nil {
			return ErrPrerequisites
		}
		_, _, candidateErr := p.engine.files.Read(credentialName(request.Snapshot.Anchor()), canonicaljson.MaxBytes)
		if candidateErr == nil {
			candidate, err := p.engine.LoadCredentials(ctx, request.Snapshot, request.Options.Now)
			if err != nil || !bytes.Equal(candidate.document.CA, activationCA) {
				return ErrPrerequisites
			}
		} else {
			if !errors.Is(candidateErr, privatefs.ErrNotFound) {
				return ErrPrerequisites
			}
			for _, r := range d.Resources {
				if r.Key.Kind == "Secret" {
					return ErrPrerequisites // never regenerate a lost used candidate
				}
			}
			if verifyInitialTLS(d.Namespace, request.Options) != nil {
				return ErrPrerequisites
			}
		}
	} else if _, _, err := privatefs.ReadAbsolute(request.Options.Activation.CAFile, 65536, privatefs.TrustedPublic); err != nil {
		return ErrPrerequisites
	}
	if err := p.original(ctx, request.Snapshot); err != nil {
		return ErrPrerequisites
	}
	return nil
}

func (p *ClusterPrerequisites) verifyAccess(ctx context.Context, target *installrender.Plan, permissions []proofPermission) error {
	if p.access.checkVersion(ctx, target.Profile()) != nil {
		return ErrPrerequisites
	}
	// Before CRDs exist, their resource authorization can be reviewed, but
	// discovery must wait for CRDsAvailable; builtin APIs must already exist.
	lists := map[string]*metav1.APIResourceList{}
	for _, gv := range proofGroups {
		if gv == "arcade.gobha.me/v1alpha1" {
			continue
		}
		list, err := p.access.discover(ctx, gv)
		if err != nil {
			return ErrPrerequisites
		}
		lists[gv] = list
	}
	for _, permission := range permissions {
		if attrs := permission.spec.ResourceAttributes; attrs != nil {
			gv := schema.GroupVersion{Group: attrs.Group, Version: attrs.Version}.String()
			if gv != "arcade.gobha.me/v1alpha1" && !discoveredPermission(lists[gv], permission) {
				return ErrPrerequisites
			}
		}
		if p.access.authorize(ctx, permission.spec) != nil {
			return ErrPrerequisites
		}
	}
	return nil
}

func verifyInitialTLS(namespace string, options LifecycleOptions) error {
	opts := options.Credentials
	expiry := options.Now.UTC().Add(opts.AdminLifetime)
	if options.Now.IsZero() || opts.AdminLifetime <= 0 || !expiry.After(options.Now) || expiry.Year() < 1 || expiry.Year() > 9999 {
		return ErrPrerequisites // reject impossible issuance before bootstrap
	}
	cert, _, certErr := privatefs.ReadAbsolute(opts.CertificateFile, 65536, privatefs.TrustedPublic)
	key, _, keyErr := privatefs.ReadAbsolute(opts.KeyFile, 16384, privatefs.Private)
	ca, _, caErr := privatefs.ReadAbsolute(opts.CAFile, 65536, privatefs.TrustedPublic)
	activationCA, _, activationErr := privatefs.ReadAbsolute(options.Activation.CAFile, 65536, privatefs.TrustedPublic)
	if certErr != nil || keyErr != nil || caErr != nil || activationErr != nil || !bytes.Equal(ca, activationCA) || validateTLS(cert, key, ca, namespace, options.Now) != nil {
		return ErrPrerequisites
	}
	return nil
}

// VerifyBootstrap establishes the fresh-install access/TLS prerequisites and
// absence of every fixed public address before EnsureNamespace's first write.
// It neither creates a namespace nor adopts existing same-named resources. The
// durable bootstrap receipt must still pin the one original namespace effect.
// This partial proof is not runtime, admission or data-safety certification.
func (p *ClusterPrerequisites) VerifyBootstrap(ctx context.Context, target *installrender.Plan, options LifecycleOptions) error {
	if p == nil || ctx == nil || !target.IsTrusted() || p.engine.plans[target.Digest()] != target || options.Now.IsZero() {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	d := installstate.Document{Namespace: target.Namespace(), ProfileID: target.Profile().ID, Mode: installstate.Install, TargetPackage: target.Digest(), Stage: installstate.Preparing}
	permissions, err := p.documentPermissions(d, installstate.Install, target)
	create, createErr := publicPermission(namespaceKey(d.Namespace), "create")
	permissions = append(permissions, create)
	if err != nil || createErr != nil || p.access.native == nil || verifyInitialTLS(d.Namespace, options) != nil || p.verifyAccess(ctx, target, permissions) != nil {
		return ErrPrerequisites
	}
	for _, resource := range target.Resources() {
		if _, err := p.access.Get(ctx, resourceKey(resource)); !apierrors.IsNotFound(err) {
			return ErrPrerequisites
		}
	}
	// Check the namespace again after all cluster-scoped address reads. The
	// bootstrap's own conditional creation remains the definitive no-adoption
	// barrier; these reads are not a distributed lock or atomic snapshot.
	if _, err := p.access.Get(ctx, namespaceKey(d.Namespace)); !apierrors.IsNotFound(err) {
		return ErrPrerequisites
	}
	return nil
}

func discoveredPermission(list *metav1.APIResourceList, permission proofPermission) bool {
	if list == nil || permission.spec.ResourceAttributes == nil {
		return false
	}
	a := permission.spec.ResourceAttributes
	name := a.Resource
	if a.Subresource != "" {
		name += "/" + a.Subresource
	}
	for _, r := range list.APIResources {
		if r.Name == name {
			return r.Kind == permission.kind && r.Namespaced == (a.Namespace != "") && (r.Group == "" || r.Group == a.Group) && (r.Version == "" || r.Version == a.Version) && slices.Contains(r.Verbs, a.Verb)
		}
	}
	return false
}
