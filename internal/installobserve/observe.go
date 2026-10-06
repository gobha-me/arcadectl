// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package installobserve obtains bounded, complete, uncached safety evidence.
// An observation is not an atomic cluster snapshot, a lock, an admission probe,
// or proof of quiescence. The installer must establish those independently and
// repeat observations at its mutation barriers.
package installobserve

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
)

var (
	ErrInvalid    = errors.New("invalid installation observer configuration")
	ErrRead       = errors.New("installation observation read is incomplete or invalid")
	ErrOwnership  = errors.New("installation observation ownership could not be proved")
	ErrConcurrent = errors.New("installation journal changed during observation")
)

const pageLimit = 128
const maxPages = 256
const maxContinueBytes = 8192
const maxCollectionBytes = 8 * 1024 * 1024
const observationTimeout = 5 * time.Minute

// Clients is a trusted test/instrumentation seam, not a caller-supplied source
// of cluster evidence. Metadata MUST use the strict transport installed by New;
// Discovery MUST be exact-version and uncached, never a preferred-version or
// partial-discovery REST mapper. No informer client is permitted here.
type Clients struct {
	Dynamic   dynamic.Interface
	Metadata  metadata.Interface
	Discovery func(context.Context, string) (*metav1.APIResourceList, error)
}

type Observer struct {
	clients Clients
	journal *installstate.Store
	plan    *installrender.Plan
}

// Observation seals the complete reads and their original-identity journal.
// Accessors copy mutable data. A successful read is not permission to mutate.
type Observation struct {
	snapshot *installsafety.Snapshot
	journal  *installstate.Snapshot
	runtime  *installsafety.RuntimeSnapshot
}

func (o *Observation) Runtime() *installsafety.RuntimeSnapshot {
	if o == nil {
		return nil
	}
	return o.runtime.DeepCopy()
}

func (o *Observation) Journal() *installstate.Snapshot {
	if o == nil {
		return nil
	}
	return o.journal
}

func (o *Observation) Snapshot() *installsafety.Snapshot {
	if o == nil || o.snapshot == nil {
		return nil
	}
	s := o.snapshot
	result := &installsafety.Snapshot{
		GameServers: s.GameServers.DeepCopy(), Backups: s.Backups.DeepCopy(), Restores: s.Restores.DeepCopy(),
		Destroys: s.Destroys.DeepCopy(), Operations: s.Operations.DeepCopy(), Jobs: s.Jobs.DeepCopy(),
		Pods: s.Pods.DeepCopy(), Leases: s.Leases.DeepCopy(), Claims: s.Claims.DeepCopy(),
		Secrets: s.Secrets.DeepCopy(), Policies: s.Policies.DeepCopy(), Bindings: s.Bindings.DeepCopy(),
		Owners: make([]installsafety.OwnerNode, len(s.Owners)),
	}
	for i, n := range s.Owners {
		result.Owners[i] = installsafety.OwnerNode{Key: n.Key, Metadata: *n.Metadata.DeepCopy()}
	}
	return result
}

func New(config *rest.Config, journal *installstate.Store, plan *installrender.Plan) (*Observer, error) {
	if config == nil || journal == nil || !plan.IsTrusted() {
		return nil, ErrInvalid
	}
	u, err := url.Parse(config.Host)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || config.Insecure {
		return nil, ErrInvalid
	}
	c := rest.CopyConfig(config)
	c.Timeout = 30 * time.Second
	c.WarningHandler = nil
	c.WarningHandlerWithContext = rest.NoWarnings{}
	c.AcceptContentTypes = "application/json"
	c.ContentType = "application/json"
	h, err := strictHTTPClient(c, false)
	if err != nil {
		return nil, ErrInvalid
	}
	d, err := dynamic.NewForConfigAndClient(c, h)
	if err != nil {
		return nil, ErrInvalid
	}
	discover, err := discovery.NewDiscoveryClientForConfigAndClient(c, h)
	if err != nil {
		return nil, ErrInvalid
	}
	mh, err := strictHTTPClient(c, true)
	if err != nil {
		return nil, ErrInvalid
	}
	m, err := metadata.NewForConfigAndClient(c, mh)
	if err != nil {
		return nil, ErrInvalid
	}
	return NewWithClients(Clients{d, m, discover.ServerResourcesForGroupVersionWithContext}, journal, plan)
}

func strictHTTPClient(config *rest.Config, metadataOnly bool) (*http.Client, error) {
	c := rest.CopyConfig(config)
	previous := c.WrapTransport
	c.WrapTransport = func(base http.RoundTripper) http.RoundTripper {
		// Sanitize below supplied instrumentation as well as client-go's
		// debug/auth wrappers: neither may observe private Secret metadata.
		var guarded http.RoundTripper = readTransport{next: base, metadata: metadataOnly}
		if previous != nil {
			guarded = previous(guarded)
		}
		return guarded
	}
	h, err := rest.HTTPClientFor(c)
	if err != nil {
		return nil, ErrInvalid
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRead }
	return h, nil
}

func nilClient(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	return (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil()
}

func NewWithClients(clients Clients, journal *installstate.Store, plan *installrender.Plan) (*Observer, error) {
	if nilClient(clients.Dynamic) || nilClient(clients.Metadata) || clients.Discovery == nil || journal == nil || !plan.IsTrusted() {
		return nil, ErrInvalid
	}
	return &Observer{clients: clients, journal: journal, plan: plan}, nil
}

type collection struct {
	gv, kind, resource string
	namespaced         bool
	target             runtime.Object
}

func runtimeCollections(r *installsafety.RuntimeSnapshot) []collection {
	r.Deployments, r.ReplicaSets = &appsv1.DeploymentList{}, &appsv1.ReplicaSetList{}
	r.StatefulSets, r.DaemonSets = &appsv1.StatefulSetList{}, &appsv1.DaemonSetList{}
	r.ReplicationControllers, r.CronJobs = &corev1.ReplicationControllerList{}, &batchv1.CronJobList{}
	r.Attachments = &storagev1.VolumeAttachmentList{}
	return []collection{
		{"apps/v1", "Deployment", "deployments", true, r.Deployments},
		{"apps/v1", "ReplicaSet", "replicasets", true, r.ReplicaSets},
		{"apps/v1", "StatefulSet", "statefulsets", true, r.StatefulSets},
		{"apps/v1", "DaemonSet", "daemonsets", true, r.DaemonSets},
		{"v1", "ReplicationController", "replicationcontrollers", true, r.ReplicationControllers},
		{"batch/v1", "CronJob", "cronjobs", true, r.CronJobs},
		{"storage.k8s.io/v1", "VolumeAttachment", "volumeattachments", false, r.Attachments},
	}
}

func collections(s *installsafety.Snapshot) []collection {
	s.GameServers, s.Backups, s.Restores = &arcade.GameServerList{}, &arcade.GameBackupList{}, &arcade.GameRestoreList{}
	s.Destroys, s.Operations = &arcade.GameDestroyList{}, &arcade.ArcadeOperationList{}
	s.Jobs, s.Pods, s.Leases = &batchv1.JobList{}, &corev1.PodList{}, &coordinationv1.LeaseList{}
	s.Claims, s.Secrets = &corev1.PersistentVolumeClaimList{}, &metav1.PartialObjectMetadataList{}
	s.Policies, s.Bindings = &admissionv1.ValidatingAdmissionPolicyList{}, &admissionv1.ValidatingAdmissionPolicyBindingList{}
	gv := arcade.GroupVersion.String()
	return []collection{
		{gv, "GameServer", "gameservers", true, s.GameServers}, {gv, "GameBackup", "gamebackups", true, s.Backups},
		{gv, "GameRestore", "gamerestores", true, s.Restores}, {gv, "GameDestroy", "gamedestroys", true, s.Destroys},
		{gv, "ArcadeOperation", "arcadeoperations", true, s.Operations}, {"batch/v1", "Job", "jobs", true, s.Jobs},
		{"v1", "Pod", "pods", true, s.Pods}, {"coordination.k8s.io/v1", "Lease", "leases", true, s.Leases},
		{"v1", "PersistentVolumeClaim", "persistentvolumeclaims", true, s.Claims}, {"v1", "Secret", "secrets", true, s.Secrets},
		{"admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", "validatingadmissionpolicies", false, s.Policies},
		{"admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicyBinding", "validatingadmissionpolicybindings", false, s.Bindings},
	}
}

// Collect discards the entire observation on any missing page, ambiguous owner,
// or journal change. It never retries a failed/expired list or returns partial
// evidence. Neither selectors nor ResourceVersion=0 (cache reads) are used.
func (o *Observer) Collect(ctx context.Context, anchor installstate.Anchor) (*Observation, error) {
	if o == nil || o.journal == nil || !o.plan.IsTrusted() || anchor.Namespace != o.plan.Namespace() {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, observationTimeout)
	defer cancel()
	// The library returns fixed diagnostics rather than delegating arbitrary
	// cluster payloads/errors to a caller's verbose contextual client-go logger.
	// Metadata transport sanitation additionally protects the response boundary
	// even when a client ignores contextual logging.
	ctx = logr.NewContext(ctx, logr.Discard())
	before, err := o.journal.Load(ctx, anchor)
	if err != nil || before.Anchor() != anchor {
		return nil, ErrOwnership
	}
	doc := before.Document()
	if doc.ProfileID != o.plan.Profile().ID || !slices.Contains([]string{doc.ActivePackage, doc.TargetPackage, doc.PreviousPackage}, o.plan.Digest()) {
		return nil, ErrOwnership
	}
	snapshot := &installsafety.Snapshot{}
	runtimeSnapshot := &installsafety.RuntimeSnapshot{}
	cs := append(collections(snapshot), runtimeCollections(runtimeSnapshot)...)
	graph := newOwnerGraph(o, doc.Resources, cs)
	budget := 32 * 1024 * 1024
	for _, c := range cs {
		if err := o.collectList(ctx, c, graph, &budget); err != nil {
			return nil, err
		}
	}
	owners, err := graph.collect(ctx)
	if err != nil {
		return nil, err
	}
	snapshot.Owners = owners
	after, err := o.journal.Load(ctx, anchor)
	if err != nil || after.Anchor() != anchor || after.ResourceVersion() != before.ResourceVersion() || !reflect.DeepEqual(before.Document(), after.Document()) {
		return nil, ErrConcurrent
	}
	return &Observation{snapshot: snapshot, journal: after, runtime: runtimeSnapshot}, nil
}

func (o *Observer) collectList(ctx context.Context, c collection, graph *ownerGraph, budget *int) error {
	gv, _ := schema.ParseGroupVersion(c.gv)
	gvr := gv.WithResource(c.resource)
	items, rv, err := boundedPages(ctx, func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		if c.kind == "Secret" {
			return o.clients.Metadata.Resource(gvr).Namespace(o.plan.Namespace()).List(ctx, opts)
		}
		var client dynamic.ResourceInterface = o.clients.Dynamic.Resource(gvr)
		if c.namespaced {
			client = o.clients.Dynamic.Resource(gvr).Namespace(o.plan.Namespace())
		}
		page, err := client.List(ctx, opts)
		if err != nil || page == nil || page.GetAPIVersion() != c.gv || page.GetKind() != c.kind+"List" {
			return nil, ErrRead
		}
		return page, nil
	}, budget)
	if err != nil {
		return err
	}
	converted := make([]runtime.Object, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		m, err := meta.Accessor(item)
		if err != nil || !validIdentity(m.GetResourceVersion()) || !validIdentity(string(m.GetUID())) || m.GetName() == "" || seen[m.GetName()] || c.namespaced && m.GetNamespace() != o.plan.Namespace() || !c.namespaced && m.GetNamespace() != "" {
			return ErrRead
		}
		seen[m.GetName()] = true
		key := installstate.Key{APIVersion: c.gv, Kind: c.kind, Namespace: m.GetNamespace(), Name: m.GetName()}
		if err := graph.seed(key, m); err != nil {
			return err
		}
		if c.kind == "Secret" {
			converted = append(converted, &metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: publicMetadata(m)})
			continue
		}
		u, ok := item.(*unstructured.Unstructured)
		if !ok || u.GetAPIVersion() != c.gv || u.GetKind() != c.kind {
			return ErrRead
		}
		converted = append(converted, u)
	}
	if c.kind == "Secret" {
		if err := meta.SetList(c.target, converted); err != nil {
			return ErrRead
		}
	} else {
		list := &unstructured.UnstructuredList{Object: map[string]any{"apiVersion": c.gv, "kind": c.kind + "List", "metadata": map[string]any{"resourceVersion": rv}}, Items: []unstructured.Unstructured{}}
		for _, item := range converted {
			list.Items = append(list.Items, *item.(*unstructured.Unstructured))
		}
		// A permissive unstructured conversion discards unknown spec/status
		// fields. Those cannot silently become closed safety evidence.
		body, err := json.Marshal(list.UnstructuredContent())
		if err != nil || strictDecode(body, c.target) != nil {
			return ErrRead
		}
	}
	listMeta, err := meta.ListAccessor(c.target)
	if err != nil {
		return ErrRead
	}
	listMeta.SetResourceVersion(rv)
	listMeta.SetContinue("")
	listMeta.SetRemainingItemCount(nil)
	return nil
}

func validIdentity(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "\r\n\x00")
}

func allPages(ctx context.Context, fetch func(context.Context, metav1.ListOptions) (runtime.Object, error)) ([]runtime.Object, string, error) {
	budget := maxCollectionBytes
	return boundedPages(ctx, fetch, &budget)
}

func boundedPages(ctx context.Context, fetch func(context.Context, metav1.ListOptions) (runtime.Object, error), budget *int) ([]runtime.Object, string, error) {
	items := []runtime.Object{}
	rv, token := "", ""
	bytesRead := 0
	seen := map[string]bool{}
	for range maxPages {
		if ctx.Err() != nil {
			return nil, "", ErrRead
		}
		page, err := fetch(ctx, metav1.ListOptions{Limit: pageLimit, Continue: token})
		if err != nil || nilClient(page) {
			return nil, "", ErrRead
		}
		body, err := json.Marshal(page)
		if err != nil || len(body) > maxResponseBytes || bytesRead+len(body) > maxCollectionBytes || budget == nil || len(body) > *budget {
			return nil, "", ErrRead
		}
		bytesRead += len(body)
		*budget -= len(body)
		m, err := meta.ListAccessor(page)
		if err != nil || !validIdentity(m.GetResourceVersion()) || rv != "" && rv != m.GetResourceVersion() || len(m.GetContinue()) > maxContinueBytes {
			return nil, "", ErrRead
		}
		rv = m.GetResourceVersion()
		pageItems, err := meta.ExtractList(page)
		if err != nil || len(items)+len(pageItems) > installsafety.MaxObjectsPerList {
			return nil, "", ErrRead
		}
		items = append(items, pageItems...)
		token = m.GetContinue()
		if token == "" {
			if count := m.GetRemainingItemCount(); count != nil && *count != 0 {
				return nil, "", ErrRead
			}
			return items, rv, nil
		}
		if seen[token] || m.GetRemainingItemCount() != nil && *m.GetRemainingItemCount() < 0 {
			return nil, "", ErrRead
		}
		seen[token] = true
	}
	return nil, "", ErrRead
}
