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
	"strconv"
	"strings"
	"sync/atomic"
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
	observer   *Observer
	root       *http.Client
	base       *url.URL
	diagnostic atomic.Uint32
}

// DiagnosticStage reports only a fixed collection boundary, never an object,
// source, identity, response or raw error. Read it after Collect returns; it is
// not evidence, an authority, a retry classification or a concurrent snapshot.
func (g *GCReader) DiagnosticStage() string {
	if g == nil {
		return "unknown"
	}
	switch g.diagnostic.Load() {
	case gcStageOpening:
		return "opening"
	case gcStageMetadataPages:
		return "metadata-pages"
	case gcStageMetadataShape:
		return "metadata-shape"
	case gcStageMetadataUIDs:
		return "metadata-uid-correlation"
	case gcStageEventAliasRV:
		return "event-alias-rv-conflict"
	case gcStageEventAliasMetadata:
		return "event-alias-metadata-conflict"
	case gcStageGraphBound:
		return "metadata-graph-bound"
	case gcStageLeasePages:
		return "lease-pages"
	case gcStageLeaseMembership:
		return "lease-membership"
	case gcStageLeaseCorrelation:
		return "lease-correlation"
	case gcStageLeaseSource:
		return "lease-source"
	case gcStageClosing:
		return "closing"
	case gcStageComplete:
		return "complete"
	}
	return "unknown"
}

const (
	gcStageOpening uint32 = iota + 1
	gcStageMetadataPages
	gcStageMetadataShape
	gcStageMetadataUIDs
	gcStageEventAliasRV
	gcStageEventAliasMetadata
	gcStageGraphBound
	gcStageLeasePages
	gcStageLeaseMembership
	gcStageLeaseCorrelation
	gcStageLeaseSource
	gcStageClosing
	gcStageComplete
)

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
	return g.collect(ctx, discovery, false, nil, nil)
}

// CollectWithLeases pairs complete strict whole Leases with their complete
// metadata source before the final discovery/journal barrier. It uses the same
// exact namespace LIST permission, never names, selectors, callbacks or grants.
// Every other GC source remains metadata-only, particularly Secrets.
func (g *GCReader) CollectWithLeases(ctx context.Context, discovery *GCDiscovery) (*GCObservation, error) {
	return g.collect(ctx, discovery, true, nil, nil)
}

func (g *GCReader) collect(ctx context.Context, discovery *GCDiscovery, pairLeases bool, refusal **LeaseRVConflict, sharedBudget *int) (*GCObservation, error) {
	if g != nil {
		g.diagnostic.Store(0)
	}
	if ctx == nil || g == nil || discovery == nil || discovery.reader != g || discovery.journal == nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(logr.NewContext(ctx, logr.Discard()), observationTimeout)
	defer cancel()
	current := func() bool {
		fresh, err := g.Discover(ctx, discovery.journal.Anchor())
		return err == nil && sameGCJournal(discovery.journal, fresh.journal) && reflect.DeepEqual(discovery.catalogue, fresh.catalogue) && reflect.DeepEqual(discovery.resources, fresh.resources)
	}
	g.diagnostic.Store(gcStageOpening)
	if !current() {
		return nil, ErrConcurrent
	}
	budget := 32 * 1024 * 1024
	if sharedBudget == nil {
		sharedBudget = &budget
	}
	rvConflict := false
	objects := []GCObject{}
	identities := map[types.UID]GCObject{}
	var leases *coordinationv1.LeaseList
	var leasesReadAt time.Time
	// Continuously renewed Leases must not age behind every other SDK LIST's
	// rate limiter before whole-object correlation. Reorder READS only; never
	// mutate the sealed catalogue, skip a source/page, change the supplied
	// read limiter/QPS (including the installer's bounded shared default) or weaken
	// the final fresh discovery/journal barrier. Read the known Event aliases
	// adjacently before Leases so unrelated SDK requests do not unnecessarily
	// separate their exact metadata correlation. This is not an atomic snapshot:
	// any observed alias mismatch still refuses without retry or normalization.
	// Preserve canonical order inside each scheduling class and in the result.
	readOrder := make([]GCResource, 0, len(discovery.resources))
	for class := range 3 {
		for _, source := range discovery.resources {
			sourceClass := 0
			if gcNativeEvent(source) {
				sourceClass = 1
			} else if source.GVR.Group == "coordination.k8s.io" && source.GVR.Resource == "leases" {
				sourceClass = 2
			}
			if sourceClass == class {
				readOrder = append(readOrder, source)
			}
		}
	}
	for _, source := range readOrder {
		start := len(objects)
		g.diagnostic.Store(gcStageMetadataPages)
		items, _, err := boundedPages(ctx, func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			return g.observer.clients.Metadata.Resource(source.GVR).Namespace(discovery.journal.Anchor().Namespace).List(ctx, opts)
		}, sharedBudget)
		if err != nil {
			return nil, ErrRead
		}
		seen := map[string]bool{}
		for _, item := range items {
			g.diagnostic.Store(gcStageMetadataShape)
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
			g.diagnostic.Store(gcStageMetadataUIDs)
			if prior, exists := identities[m.UID]; exists && !gcEventAlias(prior, object) {
				// Fixed diagnostics only: never feed this distinction into
				// acceptance, a retry decision, or a new collection capability.
				if gcKnownEventAlias(prior, object) {
					g.diagnostic.Store(gcStageEventAliasMetadata)
					if gcEventRVOnlyConflict(prior, object) {
						g.diagnostic.Store(gcStageEventAliasRV)
					}
				}
				return nil, ErrOwnership
			}
			identities[m.UID] = object
			objects = append(objects, object)
			if len(objects) > installsafety.MaxOwnerGraphNodes {
				g.diagnostic.Store(gcStageGraphBound)
				return nil, ErrRead
			}
		}
		if pairLeases && source.GVR.Group == "coordination.k8s.io" && source.GVR.Resource == "leases" {
			g.diagnostic.Store(gcStageLeaseSource)
			if source.GVR.Version != "v1" || source.Kind != "Lease" || leases != nil {
				return nil, ErrRead
			}
			leases = &coordinationv1.LeaseList{}
			c := collection{"coordination.k8s.io/v1", "Lease", "leases", true, leases}
			g.diagnostic.Store(gcStageLeasePages)
			if g.observer.collectList(ctx, c, newOwnerGraph(g.observer, nil, []collection{c}), sharedBudget) != nil {
				return nil, ErrRead
			}
			leasesReadAt = time.Now().UTC()
			g.diagnostic.Store(gcStageLeaseMembership)
			if len(leases.Items) != len(objects)-start {
				return nil, ErrConcurrent
			}
			byUID := map[types.UID]metav1.ObjectMeta{}
			for _, row := range objects[start:] {
				byUID[row.Metadata.UID] = row.Metadata
			}
			g.diagnostic.Store(gcStageLeaseCorrelation)
			for index := range leases.Items {
				lease := &leases.Items[index]
				m, ok := byUID[lease.UID]
				if !ok {
					return nil, ErrConcurrent
				}
				whole := publicMetadata(lease)
				if !reflect.DeepEqual(m, whole) {
					// The ordinary entry points still refuse immediately. The
					// opt-in route retains ONLY forward RV-only discrepancies,
					// never membership/owner/shape changes or a successful seal.
					oldRV, oldErr := strconv.ParseUint(m.ResourceVersion, 10, 64)
					newRV, newErr := strconv.ParseUint(whole.ResourceVersion, 10, 64)
					whole.ResourceVersion = m.ResourceVersion
					if refusal == nil || oldErr != nil || newErr != nil || newRV <= oldRV || !reflect.DeepEqual(m, whole) {
						return nil, ErrConcurrent
					}
					rvConflict = true
				}
				delete(byUID, lease.UID)
			}
			if len(byUID) != 0 {
				g.diagnostic.Store(gcStageLeaseMembership)
				return nil, ErrConcurrent
			}
		}
	}
	if pairLeases && leases == nil {
		g.diagnostic.Store(gcStageLeaseSource)
		return nil, ErrRead
	}
	g.diagnostic.Store(gcStageClosing)
	if !current() {
		return nil, ErrConcurrent
	}
	// Preserve the public observation's original canonical source order despite
	// scheduling Event aliases together and Lease requests last; within-source
	// page/item order is unchanged.
	slices.SortStableFunc(objects, func(a, b GCObject) int { return strings.Compare(a.Source.GVR.String(), b.Source.GVR.String()) })
	if rvConflict {
		*refusal = &LeaseRVConflict{journal: discovery.journal, objects: objects, leases: leases, readAt: leasesReadAt}
		g.diagnostic.Store(gcStageLeaseCorrelation)
		return nil, ErrConcurrent
	}
	g.diagnostic.Store(gcStageComplete)
	return &GCObservation{journal: discovery.journal, objects: objects, leases: leases, leasesReadAt: leasesReadAt}, nil
}

// Core and events.k8s.io Events alias the same stored objects. This is the sole
// known cross-GroupResource alias; require identical public metadata and never
// allow it to mask a conflicting UID/name/owner or duplicate within one source.
func gcEventAlias(a, b GCObject) bool {
	return gcKnownEventAlias(a, b) && reflect.DeepEqual(a.Metadata, b.Metadata)
}

func gcNativeEvent(source GCResource) bool {
	return source.Kind == "Event" && source.GVR.Resource == "events" && slices.Contains([]string{"", "events.k8s.io"}, source.GVR.Group)
}

func gcKnownEventAlias(a, b GCObject) bool {
	return gcNativeEvent(a.Source) && gcNativeEvent(b.Source) && a.Source.GVR.Group != b.Source.GVR.Group
}

// Diagnostic classification of already-refused sanitized metadata only. Keep
// both observed RVs intact; this helper cannot create successful evidence.
func gcEventRVOnlyConflict(a, b GCObject) bool {
	x, y := a.Metadata, b.Metadata
	return gcKnownEventAlias(a, b) && x.ResourceVersion != y.ResourceVersion &&
		x.Name == y.Name && x.Namespace == y.Namespace && x.UID == y.UID && x.Generation == y.Generation &&
		reflect.DeepEqual(x.OwnerReferences, y.OwnerReferences) && reflect.DeepEqual(x.DeletionTimestamp, y.DeletionTimestamp)
}

// Descendants uses all observed owner UID edges, not kind/controller flags or
// a fixed workload allowlist. It returns identities only; callers must correlate
// every allowed fixture child with independent original whole-object evidence.
func (o *GCObservation) Descendants(roots []types.UID) ([]GCObject, error) {
	if o == nil {
		return nil, ErrInvalid
	}
	return gcDescendants(o.journal, o.objects, roots)
}

func gcDescendants(journal *installstate.Snapshot, objects []GCObject, roots []types.UID) ([]GCObject, error) {
	if journal == nil || len(roots) == 0 || len(roots) > installsafety.MaxOwnerGraphNodes {
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
	for _, object := range objects {
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
	for _, object := range objects {
		if selected[object.Metadata.UID] && !slices.Contains(roots, object.Metadata.UID) {
			result = append(result, GCObject{object.Source, *object.Metadata.DeepCopy()})
		}
	}
	return result, nil
}
