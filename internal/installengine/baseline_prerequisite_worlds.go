// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Whole passive rows are private observation evidence, NEVER installer
// inventory, adoption, credential contents or cleanup authority. Secret rows
// contain only the deliberately public metadata projection; their contents
// remain a distinct SecretWorkflow obligation at the lifecycle boundary.
type prerequisiteRetainedRow struct {
	source   installobserve.GCResource
	metadata metav1.ObjectMeta
	hash     string
}

type prerequisiteRetainedEvidence struct {
	passive   map[installstate.Key]prerequisiteRetainedRow
	originals map[installstate.Key]prerequisiteRetainedRow
	volumes   map[installstate.Key]admissionIdentity
}

func baselineRetainedObjectHash(object any) (string, error) {
	body, err := json.Marshal(object)
	if err != nil || len(body) > 32*1024*1024 {
		return "", ErrSecurityBaseline
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

// Only exact native versions already checked by the strict typed observer.
// A newly served preferred version is not a waiver of typed/GC correlation.
func prerequisiteRetainedSources(sources []installobserve.GCResource) bool {
	if !baselinePrerequisiteSources(sources) {
		return false
	}
	required := map[schema.GroupVersionResource]string{
		{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gameservers"}:      "GameServer",
		{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamebackups"}:      "GameBackup",
		{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamerestores"}:     "GameRestore",
		{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "gamedestroys"}:     "GameDestroy",
		{Group: "arcade.gobha.me", Version: "v1alpha1", Resource: "arcadeoperations"}: "ArcadeOperation",
		{Group: "coordination.k8s.io", Version: "v1", Resource: "leases"}:             "Lease",
	}
	for _, source := range sources {
		if kind, found := required[source.GVR]; found {
			if kind != source.Kind {
				return false
			}
			delete(required, source.GVR)
		}
	}
	return len(required) == 0
}

func prerequisiteRetainedRows(namespace string, snapshot *installsafety.Snapshot) (map[installstate.Key]prerequisiteRetainedRow, error) {
	if snapshot == nil {
		return nil, ErrSecurityBaseline
	}
	rows := map[installstate.Key]prerequisiteRetainedRow{}
	seenUIDs := map[string]bool{}
	for _, collection := range []struct {
		version, kind, plural string
		list                  runtime.Object
	}{
		{"arcade.gobha.me/v1alpha1", "GameServer", "gameservers", snapshot.GameServers},
		{"arcade.gobha.me/v1alpha1", "GameBackup", "gamebackups", snapshot.Backups},
		{"arcade.gobha.me/v1alpha1", "GameRestore", "gamerestores", snapshot.Restores},
		{"arcade.gobha.me/v1alpha1", "GameDestroy", "gamedestroys", snapshot.Destroys},
		{"arcade.gobha.me/v1alpha1", "ArcadeOperation", "arcadeoperations", snapshot.Operations},
		{"coordination.k8s.io/v1", "Lease", "leases", snapshot.Leases},
		{"v1", "PersistentVolumeClaim", "persistentvolumeclaims", snapshot.Claims},
		{"v1", "Secret", "secrets", snapshot.Secrets},
	} {
		if reflect.ValueOf(collection.list).IsNil() {
			return nil, ErrSecurityBaseline
		}
		list, err := meta.ListAccessor(collection.list)
		if err != nil || list.GetResourceVersion() == "" || list.GetContinue() != "" || list.GetRemainingItemCount() != nil && *list.GetRemainingItemCount() != 0 {
			return nil, ErrSecurityBaseline
		}
		items, err := meta.ExtractList(collection.list)
		if err != nil || len(items) > installsafety.MaxObjectsPerList {
			return nil, ErrSecurityBaseline
		}
		gv, err := schema.ParseGroupVersion(collection.version)
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		for _, item := range items {
			metadata, err := meta.Accessor(item)
			if err != nil || metadata.GetNamespace() != namespace || metadata.GetName() == "" || !receiptUID.MatchString(string(metadata.GetUID())) || !receiptUID.MatchString(metadata.GetResourceVersion()) || metadata.GetDeletionTimestamp() != nil || seenUIDs[string(metadata.GetUID())] {
				return nil, ErrSecurityBaseline
			}
			seenUIDs[string(metadata.GetUID())] = true
			key := installstate.Key{APIVersion: collection.version, Kind: collection.kind, Namespace: namespace, Name: metadata.GetName()}
			if _, duplicate := rows[key]; duplicate {
				return nil, ErrSecurityBaseline
			}
			hash, err := baselineRetainedObjectHash(item)
			if err != nil {
				return nil, ErrSecurityBaseline
			}
			rows[key] = prerequisiteRetainedRow{installobserve.GCResource{GVR: gv.WithResource(collection.plural), Kind: collection.kind}, fixtureGCMetadata(metadata), hash}
		}
	}
	return rows, nil
}

func (c *ClusterSecurityBaseline) collectPrerequisiteRetained(ctx context.Context, s *installstate.Snapshot, operation *baselinePrerequisite, receipt *prerequisiteReceiptWitness) (*prerequisiteRetainedEvidence, error) {
	if c == nil || c.engine == nil || c.access == nil || c.engine.access != c.access || ctx == nil || ctx.Err() != nil || receipt == nil || receipt.source == nil || c.engine.confirmPrerequisiteReceipt(s, operation, receipt) != nil {
		return nil, ErrSecurityBaseline
	}
	e := c.engine
	// Original retired policy UID/RV/health evidence still applies, but the old
	// completed-uninstall absence of withdrawn access does NOT. Observe the
	// genuine current Install journal, not a reconstructed historical Snapshot.
	policies, err := e.retirementPolicies(ctx, s)
	if err != nil || !slices.Equal(policies, receipt.source.retirement.receipt.Policies) {
		return nil, ErrSecurityBaseline
	}
	baseline, err := e.retirementBaselinePolicies(ctx, s)
	if err != nil || !slices.Equal(baseline, receipt.source.retirement.receipt.Baseline) {
		return nil, ErrSecurityBaseline
	}
	prerequisites, err := NewClusterPrerequisites(e, c.access)
	if err != nil || prerequisites.authorizeObservationReads(ctx, s, []installstate.Key{operation.key}) != nil {
		return nil, ErrSecurityBaseline
	}
	d := s.Document()
	request := LifecycleCheck{Checkpoint: ColdSafety, Snapshot: s, Mode: d.Mode, Target: e.plans[d.TargetPackage], Options: LifecycleOptions{Now: time.Now().UTC()}}
	observation, err := prerequisites.collectOriginalObservation(ctx, request)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	cold, err := NewClusterCold(prerequisites)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	_, _, volumes, _, err := cold.evaluateEvidence(ctx, request, observation)
	snapshot := observation.Snapshot()
	if err != nil || !bootstrapRuntimeAbsent(snapshot, observation.Runtime()) || !bootstrapCredentials(d, snapshot) {
		return nil, ErrSecurityBaseline
	}
	passive, err := prerequisiteRetainedRows(d.Namespace, snapshot)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	originals, err := c.prerequisiteRetainedOriginals(ctx, s, operation, receipt, passive)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	volumeRows := map[installstate.Key]admissionIdentity{}
	for _, volume := range volumes {
		if volume == nil {
			return nil, ErrSecurityBaseline
		}
		hash, err := baselineRetainedObjectHash(volume)
		key := installstate.Key{APIVersion: "v1", Kind: "PersistentVolume", Name: volume.Name}
		if err != nil || volumeRows[key].UID != "" {
			return nil, ErrSecurityBaseline
		}
		volumeRows[key] = admissionIdentity{volume.UID, volume.ResourceVersion, hash}
	}
	if _, err := (&Lifecycle{engine: e}).original(ctx, s); err != nil || e.confirmPrerequisiteReceipt(s, operation, receipt) != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	return &prerequisiteRetainedEvidence{passive, originals, volumeRows}, nil
}

func (c *ClusterSecurityBaseline) prerequisiteRetainedOriginals(ctx context.Context, s *installstate.Snapshot, operation *baselinePrerequisite, receipt *prerequisiteReceiptWitness, passive map[installstate.Key]prerequisiteRetainedRow) (map[installstate.Key]prerequisiteRetainedRow, error) {
	d := s.Document()
	rows := map[installstate.Key]prerequisiteRetainedRow{}
	for _, entry := range d.Resources {
		if entry.Key == namespaceKey(d.Namespace) {
			continue
		}
		if entry.Key.APIVersion == "v1" && entry.Key.Kind == "Secret" {
			row, found := passive[entry.Key]
			if !found || !entry.Retained || entry.TemplateSHA256 != "" || row.metadata.UID != entry.UID {
				return nil, ErrSecurityBaseline
			}
			rows[entry.Key] = row // original public metadata, NEVER Secret data
			continue
		}
		template, err := c.engine.contracts[d.TargetPackage].Template(entry.Key, false)
		live, readErr := c.access.Get(ctx, entry.Key)
		if err != nil || readErr != nil || template.MatchLive(live, entry.UID) != nil {
			return nil, ErrSecurityBaseline
		}
		gv, err := schema.ParseGroupVersion(entry.Key.APIVersion)
		path, pathErr := resourcePath(entry.Key, true)
		if err != nil || pathErr != nil {
			return nil, ErrSecurityBaseline
		}
		rows[entry.Key] = prerequisiteRetainedRow{source: installobserve.GCResource{GVR: gv.WithResource(path[strings.LastIndex(path, "/")+1:]), Kind: entry.Key.Kind}, metadata: fixtureGCMetadata(live), hash: template.Hash()}
	}
	target, err := c.access.Get(ctx, operation.key)
	if !apierrors.IsNotFound(err) {
		if err != nil || target == nil || d.Pending == nil || receipt.uid == "" || target.GetUID() != receipt.uid {
			return nil, ErrSecurityBaseline
		}
		template, err := c.engine.prerequisiteContext(s, operation)
		if err != nil || !effectMatches(template, d.Pending, target) {
			return nil, ErrSecurityBaseline
		}
		gv, err := schema.ParseGroupVersion(operation.key.APIVersion)
		path, pathErr := resourcePath(operation.key, true)
		if err != nil || pathErr != nil {
			return nil, ErrSecurityBaseline
		}
		rows[operation.key] = prerequisiteRetainedRow{source: installobserve.GCResource{GVR: gv.WithResource(path[strings.LastIndex(path, "/")+1:]), Kind: operation.key.Kind}, metadata: fixtureGCMetadata(target), hash: template.Hash()}
	}
	return rows, nil
}

func (c *ClusterSecurityBaseline) prerequisiteRetainedNamespaceReceipt(ctx context.Context, s *installstate.Snapshot, operation *baselinePrerequisite, receipt *prerequisiteReceiptWitness) (map[installstate.Key]admissionIdentity, error) {
	opening, err := c.collectPrerequisiteRetained(ctx, s, operation, receipt)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	d := s.Document()
	reader, err := installobserve.NewGCReader(c.access.readConfig(), c.engine.journal, c.engine.plans[d.TargetPackage])
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	discovery, err := reader.Discover(ctx, s.Anchor())
	if err != nil || !discovery.CoversNamespaceLists() || !prerequisiteRetainedSources(discovery.Resources()) {
		return nil, ErrSecurityBaseline
	}
	for _, source := range discovery.Resources() {
		if c.access.authorize(ctx, gcMetadataPermission(source, d.Namespace).spec) != nil {
			return nil, ErrSecurityBaseline
		}
	}
	observation, err := reader.Collect(ctx, discovery)
	if err != nil || observation == nil || observation.Journal() == nil || observation.Journal().Anchor() != s.Anchor() || observation.Journal().ResourceVersion() != s.ResourceVersion() || !bytes.Equal(observation.Journal().Bytes(), s.Bytes()) {
		return nil, ErrSecurityBaseline
	}
	witness := maps.Clone(opening.volumes)
	for key, row := range opening.originals {
		witness[key] = admissionIdentity{row.metadata.UID, row.metadata.ResourceVersion, row.hash}
	}
	for key, row := range opening.passive {
		witness[key] = admissionIdentity{row.metadata.UID, row.metadata.ResourceVersion, row.hash}
	}
	seen := map[installstate.Key]bool{}
	for _, row := range observation.Objects() {
		if baselinePrerequisiteEvent(row.Source) {
			continue
		}
		key := installstate.Key{APIVersion: row.Source.GVR.GroupVersion().String(), Kind: row.Source.Kind, Namespace: row.Metadata.Namespace, Name: row.Metadata.Name}
		if seen[key] || row.Metadata.DeletionTimestamp != nil {
			return nil, ErrSecurityBaseline
		}
		seen[key] = true
		if original, found := opening.passive[key]; found {
			if row.Source != original.source || !reflect.DeepEqual(row.Metadata, original.metadata) {
				return nil, ErrSecurityBaseline
			}
			continue
		}
		if original, found := opening.originals[key]; found {
			if row.Source != original.source || !reflect.DeepEqual(row.Metadata, original.metadata) {
				return nil, ErrSecurityBaseline
			}
			continue
		}
		if !c.benignPrerequisiteDefault(ctx, row) {
			return nil, ErrSecurityBaseline // unknown source/member never earns a waiver
		}
		witness[key] = admissionIdentity{row.Metadata.UID, row.Metadata.ResourceVersion, ""}
	}
	for _, rows := range []map[installstate.Key]prerequisiteRetainedRow{opening.passive, opening.originals} {
		for key := range rows {
			if key.Namespace != "" && !seen[key] {
				return nil, ErrSecurityBaseline
			}
		}
	}
	closing, err := c.collectPrerequisiteRetained(ctx, s, operation, receipt)
	if err != nil || !reflect.DeepEqual(opening, closing) {
		return nil, ErrSecurityBaseline
	}
	if _, err := (&Lifecycle{engine: c.engine}).original(ctx, s); err != nil || c.engine.confirmPrerequisiteReceipt(s, operation, receipt) != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	return witness, nil
}
