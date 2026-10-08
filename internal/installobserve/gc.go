// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// GCResource identifies the source of transformed metadata; the returned
// meta.k8s.io GVK is not the original resource kind. No mutation is provided.
type GCResource struct {
	GVR  schema.GroupVersionResource
	Kind string
}

type GCObject struct {
	Source   GCResource
	Metadata metav1.ObjectMeta
}

// GCReader enumerates namespace-scoped native GC candidates, including ignored
// Events conservatively. It is neither a cleanup authority nor a cluster lock.
// The engine must independently authorize each exact namespace LIST using its
// frozen administrator, then bind these reads to its WAL/actor/world witnesses.
type GCReader struct {
	observer *Observer
	root     *http.Client
	base     *url.URL
}

// GCDiscovery is sealed to its reader and original journal. Its public source
// copies let the engine establish exact LIST SSARs before Collect. Neither a
// caller-selected catalogue nor partial discovery can supply this seal.
type GCDiscovery struct {
	reader    *GCReader
	journal   *installstate.Snapshot
	catalogue gcCatalogue
	resources []GCResource
}

func (d *GCDiscovery) Resources() []GCResource {
	if d == nil {
		return nil
	}
	return slices.Clone(d.resources)
}

type GCObservation struct {
	journal      *installstate.Snapshot
	objects      []GCObject
	leases       *coordinationv1.LeaseList
	leasesReadAt time.Time
}

// PairedLeases returns the complete whole-object Lease read correlated inside
// this collection interval, not a later GET against aging metadata. Ordinary
// metadata-only Collect observations deliberately have no such evidence.
func (o *GCObservation) PairedLeases() (*coordinationv1.LeaseList, time.Time) {
	if o == nil || o.leases == nil {
		return nil, time.Time{}
	}
	return o.leases.DeepCopy(), o.leasesReadAt
}

func (o *GCObservation) Journal() *installstate.Snapshot {
	if o == nil {
		return nil
	}
	return o.journal
}

func (o *GCObservation) Objects() []GCObject {
	if o == nil {
		return nil
	}
	result := make([]GCObject, len(o.objects))
	for i, object := range o.objects {
		result[i] = GCObject{object.Source, *object.Metadata.DeepCopy()}
	}
	return result
}

func NewGCReader(config *rest.Config, journal *installstate.Store, plan *installrender.Plan) (*GCReader, error) {
	o, err := New(config, journal, plan)
	if err != nil {
		return nil, err
	}
	c := rest.CopyConfig(config)
	c.Timeout = 30 * time.Second
	c.WarningHandler, c.WarningHandlerWithContext = nil, rest.NoWarnings{}
	client, err := strictHTTPClient(c, false)
	base, parseErr := url.Parse(c.Host)
	if err != nil || parseErr != nil || base.RawPath != "" {
		return nil, ErrInvalid
	}
	return &GCReader{observer: o, root: client, base: base}, nil
}

func (g *GCReader) readDiscovery(ctx context.Context, path string, out any, budget *int) error {
	u := *g.base
	u.Path, u.RawQuery = strings.TrimRight(u.Path, "/")+path, ""
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ErrRead
	}
	r.Header.Set("Accept", "application/json") // legacy, uncached exact-version discovery
	response, err := g.root.Do(r)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.Body == nil || response.StatusCode != http.StatusOK {
		return ErrRead
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(body) > maxResponseBytes || budget == nil || len(body) > *budget || strictDecode(body, out) != nil || gcDiscoveryFields(body, out) != nil {
		return ErrRead
	}
	*budget -= len(body)
	return nil
}

func (g *GCReader) Discover(ctx context.Context, anchor installstate.Anchor) (*GCDiscovery, error) {
	if ctx == nil || g == nil || g.observer == nil || g.root == nil || g.base == nil || g.observer.journal == nil || !g.observer.plan.IsTrusted() || anchor.Namespace != g.observer.plan.Namespace() {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(logr.NewContext(ctx, logr.Discard()), observationTimeout)
	defer cancel()
	journal, err := g.observer.journal.Load(ctx, anchor)
	if err != nil || journal.Anchor() != anchor {
		return nil, ErrOwnership
	}
	doc := journal.Document()
	if doc.ProfileID != g.observer.plan.Profile().ID || !slices.Contains([]string{doc.TargetPackage, doc.ActivePackage, doc.PreviousPackage}, g.observer.plan.Digest()) {
		return nil, ErrOwnership
	}
	budget := 32 * 1024 * 1024
	var core metav1.APIVersions
	var groups metav1.APIGroupList
	if g.readDiscovery(ctx, "/api", &core, &budget) != nil || g.readDiscovery(ctx, "/apis", &groups, &budget) != nil {
		return nil, ErrRead
	}
	catalogue, err := gcGroups(core, groups)
	if err != nil {
		return nil, err
	}
	for _, group := range catalogue.Groups {
		for _, version := range group.Versions {
			path := "/apis/" + version.GroupVersion
			if group.Name == "" {
				path = "/api/" + version.Version
			}
			var resources metav1.APIResourceList
			if g.readDiscovery(ctx, path, &resources, &budget) != nil || resources.GroupVersion != version.GroupVersion {
				return nil, ErrRead
			}
			catalogue.Lists[version.GroupVersion] = resources
		}
	}
	resources, err := gcResources(catalogue)
	if err != nil {
		return nil, err
	}
	after, err := g.observer.journal.Load(ctx, anchor)
	if err != nil || !sameGCJournal(journal, after) {
		return nil, ErrConcurrent
	}
	return &GCDiscovery{g, after, catalogue, resources}, nil
}

func sameGCJournal(a, b *installstate.Snapshot) bool {
	return a != nil && b != nil && a.Anchor() == b.Anchor() && a.ResourceVersion() == b.ResourceVersion() && bytes.Equal(a.Bytes(), b.Bytes())
}

// Collect performs no SSAR grant, watch, full-object fallback or mutation. It
// requires fresh complete discovery matching the original seal before/after all
// unfiltered metadata pages. The engine must repeat relevant object/WAL/world
// witnesses at effect barriers; collection RVs are not a namespace-wide lock.
func (g *GCReader) Collect(ctx context.Context, discovery *GCDiscovery) (*GCObservation, error) {
	return g.collect(ctx, discovery, false)
}

// CollectWithLeases pairs complete strict whole Leases with their complete
// metadata source before the final discovery/journal barrier. It uses the same
// exact namespace LIST permission, never names, selectors, callbacks or grants.
// Every other GC source remains metadata-only, particularly Secrets.
func (g *GCReader) CollectWithLeases(ctx context.Context, discovery *GCDiscovery) (*GCObservation, error) {
	return g.collect(ctx, discovery, true)
}

func (g *GCReader) collect(ctx context.Context, discovery *GCDiscovery, pairLeases bool) (*GCObservation, error) {
	if ctx == nil || g == nil || discovery == nil || discovery.reader != g || discovery.journal == nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(logr.NewContext(ctx, logr.Discard()), observationTimeout)
	defer cancel()
	current := func() bool {
		fresh, err := g.Discover(ctx, discovery.journal.Anchor())
		return err == nil && sameGCJournal(discovery.journal, fresh.journal) && reflect.DeepEqual(discovery.catalogue, fresh.catalogue) && reflect.DeepEqual(discovery.resources, fresh.resources)
	}
	if !current() {
		return nil, ErrConcurrent
	}
	budget := 32 * 1024 * 1024
	objects := []GCObject{}
	identities := map[types.UID]GCObject{}
	var leases *coordinationv1.LeaseList
	var leasesReadAt time.Time
	// Continuously renewed Leases must not age behind every other SDK LIST's
	// rate limiter before whole-object correlation. Reorder READS only; never
	// mutate the sealed catalogue, skip a source/page, change the supplied
	// read limiter/QPS (including the installer's bounded shared default) or weaken
	// the final fresh discovery/journal barrier. Other sources keep their order.
	readOrder := make([]GCResource, 0, len(discovery.resources))
	for _, last := range []bool{false, true} {
		for _, source := range discovery.resources {
			lease := source.GVR.Group == "coordination.k8s.io" && source.GVR.Resource == "leases"
			if lease == last {
				readOrder = append(readOrder, source)
			}
		}
	}
	for _, source := range readOrder {
		start := len(objects)
		items, _, err := boundedPages(ctx, func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			return g.observer.clients.Metadata.Resource(source.GVR).Namespace(discovery.journal.Anchor().Namespace).List(ctx, opts)
		}, &budget)
		if err != nil {
			return nil, ErrRead
		}
		seen := map[string]bool{}
		for _, item := range items {
			m, ok := item.(*metav1.PartialObjectMetadata)
			key := installstate.Key{APIVersion: source.GVR.GroupVersion().String(), Kind: source.Kind, Namespace: discovery.journal.Anchor().Namespace}
			if !ok || m == nil {
				return nil, ErrRead
			}
			key.Name = m.Name
			if !validKey(key, key.Namespace) || m.Namespace != key.Namespace || !validIdentity(string(m.UID)) || !validIdentity(m.ResourceVersion) || m.Generation < 0 || seen[m.Name] || len(m.OwnerReferences) > installsafety.MaxOwnerReferences {
				return nil, ErrOwnership
			}
			for _, owner := range m.OwnerReferences {
				if !validIdentity(string(owner.UID)) || !validKey(installstate.Key{APIVersion: owner.APIVersion, Kind: owner.Kind, Namespace: key.Namespace, Name: owner.Name}, key.Namespace) {
					return nil, ErrOwnership
				}
			}
			seen[m.Name] = true
			object := GCObject{source, publicMetadata(m)}
			if prior, exists := identities[m.UID]; exists && !gcEventAlias(prior, object) {
				return nil, ErrOwnership
			}
			identities[m.UID] = object
			objects = append(objects, object)
			if len(objects) > installsafety.MaxOwnerGraphNodes {
				return nil, ErrRead
			}
		}
		if pairLeases && source.GVR.Group == "coordination.k8s.io" && source.GVR.Resource == "leases" {
			if source.GVR.Version != "v1" || source.Kind != "Lease" || leases != nil {
				return nil, ErrRead
			}
			leases = &coordinationv1.LeaseList{}
			c := collection{"coordination.k8s.io/v1", "Lease", "leases", true, leases}
			if g.observer.collectList(ctx, c, newOwnerGraph(g.observer, nil, []collection{c}), &budget) != nil {
				return nil, ErrRead
			}
			leasesReadAt = time.Now().UTC()
			if len(leases.Items) != len(objects)-start {
				return nil, ErrConcurrent
			}
			byUID := map[types.UID]metav1.ObjectMeta{}
			for _, row := range objects[start:] {
				byUID[row.Metadata.UID] = row.Metadata
			}
			for index := range leases.Items {
				lease := &leases.Items[index]
				m, ok := byUID[lease.UID]
				if !ok || !reflect.DeepEqual(m, publicMetadata(lease)) {
					return nil, ErrConcurrent
				}
				delete(byUID, lease.UID)
			}
			if len(byUID) != 0 {
				return nil, ErrConcurrent
			}
		}
	}
	if pairLeases && leases == nil {
		return nil, ErrRead
	}
	if !current() {
		return nil, ErrConcurrent
	}
	// Preserve the public observation's original canonical source order despite
	// scheduling Lease requests last; within-source page/item order is unchanged.
	slices.SortStableFunc(objects, func(a, b GCObject) int { return strings.Compare(a.Source.GVR.String(), b.Source.GVR.String()) })
	return &GCObservation{journal: discovery.journal, objects: objects, leases: leases, leasesReadAt: leasesReadAt}, nil
}

// Core and events.k8s.io Events alias the same stored objects. This is the sole
// known cross-GroupResource alias; require identical public metadata and never
// allow it to mask a conflicting UID/name/owner or duplicate within one source.
func gcEventAlias(a, b GCObject) bool {
	return a.Source.Kind == "Event" && b.Source.Kind == "Event" && a.Source.GVR.Resource == "events" && b.Source.GVR.Resource == "events" &&
		a.Source.GVR.Group != b.Source.GVR.Group && slices.Contains([]string{"", "events.k8s.io"}, a.Source.GVR.Group) && slices.Contains([]string{"", "events.k8s.io"}, b.Source.GVR.Group) && reflect.DeepEqual(a.Metadata, b.Metadata)
}

// Descendants uses all observed owner UID edges, not kind/controller flags or
// a fixed workload allowlist. It returns identities only; callers must correlate
// every allowed fixture child with independent original whole-object evidence.
func (o *GCObservation) Descendants(roots []types.UID) ([]GCObject, error) {
	if o == nil || o.journal == nil || len(roots) == 0 || len(roots) > installsafety.MaxOwnerGraphNodes {
		return nil, ErrInvalid
	}
	selected := map[types.UID]bool{}
	children := map[types.UID][]types.UID{}
	for _, root := range roots {
		if !validIdentity(string(root)) || selected[root] {
			return nil, ErrInvalid
		}
		selected[root] = true
	}
	for _, object := range o.objects {
		for _, owner := range object.Metadata.OwnerReferences {
			children[owner.UID] = append(children[owner.UID], object.Metadata.UID)
		}
	}
	queue := slices.Clone(roots)
	for i := 0; i < len(queue); i++ {
		for _, child := range children[queue[i]] {
			if !selected[child] {
				selected[child] = true
				queue = append(queue, child)
			}
		}
	}
	result := []GCObject{}
	for _, object := range o.objects {
		if selected[object.Metadata.UID] && !slices.Contains(roots, object.Metadata.UID) {
			result = append(result, GCObject{object.Source, *object.Metadata.DeepCopy()})
		}
	}
	return result, nil
}
