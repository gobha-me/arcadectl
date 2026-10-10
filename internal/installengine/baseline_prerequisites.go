// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"maps"
	"net/http"
	"reflect"
	"time"

	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// A private, signed operation description, not a stage-based exemption or
// caller-configurable callback. Only fresh or authenticated retained-source
// nonexecuting CREATE is eligible.
type baselinePrerequisite struct {
	key     installstate.Key
	digest  string
	hash    string
	nonce   string
	secrets *retainedBootstrapSecrets
}

func baselinePrerequisiteKey(key installstate.Key, namespace string) bool {
	switch key.APIVersion + "/" + key.Kind {
	case "apiextensions.k8s.io/v1/CustomResourceDefinition", "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy", "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicyBinding", "rbac.authorization.k8s.io/v1/ClusterRole", "rbac.authorization.k8s.io/v1/ClusterRoleBinding":
		return key.Namespace == ""
	case "v1/ServiceAccount", "rbac.authorization.k8s.io/v1/Role", "rbac.authorization.k8s.io/v1/RoleBinding":
		return key.Namespace == namespace
	}
	return false
}

func (e *Engine) prerequisiteOperation(s *installstate.Snapshot, key installstate.Key, digest string) (*baselinePrerequisite, error) {
	if e == nil || e.baseline == nil || s == nil {
		return nil, ErrSecurityBaseline
	}
	d := s.Document()
	if !baselinePrerequisiteKey(key, d.Namespace) || digest != d.TargetPackage {
		return nil, ErrSecurityBaseline
	}
	c := e.contracts[digest]
	if c == nil {
		return nil, ErrSecurityBaseline
	}
	template, err := c.Template(key, false)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	operation := &baselinePrerequisite{key: key, digest: digest, hash: template.Hash()}
	if pending := d.Pending; pending != nil {
		operation.nonce = pending.CreateNonce
	}
	if _, err := e.prerequisiteContext(s, operation); err != nil {
		return nil, err
	}
	return operation, nil
}

// Check the exact operation, original signed inventory and durable CREATE
// intent. Recovery never changes the snapshot's pending bytes to pass a gate.
func (e *Engine) prerequisiteContext(s *installstate.Snapshot, operation *baselinePrerequisite) (*installcontract.Template, error) {
	if e == nil || e.baseline == nil || s == nil || operation == nil {
		return nil, ErrSecurityBaseline
	}
	d := s.Document()
	if d.Mode != installstate.Install || d.Stage != installstate.Applying || d.Installed || d.AdmissionRetirementRevision != 0 || d.TargetPackage != operation.digest || !baselinePrerequisiteKey(operation.key, d.Namespace) {
		return nil, ErrSecurityBaseline
	}
	baseline := d.SecurityBaseline
	if baseline == nil || baseline.Stage != installstate.BaselineVerified || baseline.Pending != nil || baseline.ArtifactDigest != e.baselinePlan().Digest() {
		return nil, ErrSecurityBaseline
	}
	c := e.contracts[operation.digest]
	if c == nil {
		return nil, ErrSecurityBaseline
	}
	template, err := c.Template(operation.key, false)
	if err != nil || template.Hash() != operation.hash {
		return nil, ErrSecurityBaseline
	}
	var source *reinstallSourceWitness
	if d.ActivePackage == "" {
		if d.AdmissionReinstall != nil {
			return nil, ErrSecurityBaseline
		}
	} else {
		// A package/stage flag is not an exemption. Authenticate the exact
		// completed source and its original retirement inventory locally;
		// the outer prerequisite witness holds these descriptors during all
		// subsequent remote observations and recovery settlement.
		source, err = e.openReinstallSource(s)
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		defer source.release()
		if template.Retained() || !accessRetirementKey(operation.key) || len(source.source.Resources) != 20 {
			return nil, ErrSecurityBaseline
		}
	}
	for _, entry := range d.Resources {
		if entry.Key == namespaceKey(d.Namespace) {
			continue // original Namespace is independently checked at each edge
		}
		if source != nil {
			retained, _ := e.inventory(source.source, entry.Key)
			if retained != nil {
				if !retained.Retained || *retained != entry || entry.Key == operation.key {
					return nil, ErrSecurityBaseline
				}
				continue
			}
			// Close the union, not merely source20 subset inclusion. Only
			// original signed nonretained access prerequisites may accumulate
			// before the complete active runtime proof becomes possible.
			if entry.Retained || !accessRetirementKey(entry.Key) {
				return nil, ErrSecurityBaseline
			}
		}
		if !baselinePrerequisiteKey(entry.Key, d.Namespace) || entry.Key == operation.key {
			return nil, ErrSecurityBaseline
		}
		original, err := c.Template(entry.Key, false)
		if err != nil || original.Hash() != entry.TemplateSHA256 || original.Phase() != entry.Phase || original.Retained() != entry.Retained {
			return nil, ErrSecurityBaseline
		}
	}
	if p := d.Pending; p != nil && (p.Action != installstate.Create || p.Key != operation.key || p.AfterSHA256 != operation.hash || p.CreateNonce != operation.nonce || p.BeforeUID != "" || p.BeforeResourceVersion != "" || p.BeforeSHA256 != "") {
		return nil, ErrSecurityBaseline
	}
	if source != nil && e.closeReinstallSource(source) != nil {
		return nil, ErrSecurityBaseline
	}
	return template, nil
}

// The ordinary current() gate stays unchanged. This private dispatch binds ONE
// prerequisite CREATE to its signed key/hash/nonce and repeats the complete
// closed production proof. It is not a generic configuration/stage exemption.
func (e *Engine) currentEffect(ctx context.Context, s *installstate.Snapshot, operation *baselinePrerequisite) (*installstate.Snapshot, error) {
	if operation == nil {
		return e.current(ctx, s)
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	receipt, err := e.openPrerequisiteReceipt(s, operation)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	defer receipt.release()
	return e.currentPrerequisiteEffect(ctx, s, operation, receipt)
}

// Recovery supplies its outer owner so the same receipt remains held through
// proof, target observation, the final journal fence and settlement CAS.
func (e *Engine) currentPrerequisiteEffect(ctx context.Context, s *installstate.Snapshot, operation *baselinePrerequisite, receipt *prerequisiteReceiptWitness) (*installstate.Snapshot, error) {
	if e == nil || e.baseline == nil || e.baseline.prerequisites == nil {
		return nil, ErrSecurityBaseline
	}
	if ctx == nil || ctx.Err() != nil || e.confirmPrerequisiteReceipt(s, operation, receipt) != nil {
		return nil, ErrSecurityBaseline
	}
	// Read-only prerequisite observation may omit private Secret contents;
	// retained effects and settlement may not. Only the lifecycle supplies an
	// owned, same-engine Secret/CA witness, held through this entire operation.
	if s.Document().ActivePackage != "" && operation.secrets == nil {
		return nil, ErrSecurityBaseline
	}
	if operation.secrets != nil && operation.secrets.verify(ctx, s) != nil {
		return nil, ErrSecurityBaseline
	}
	lifecycle := &Lifecycle{engine: e}
	fresh, err := lifecycle.original(ctx, s)
	if err != nil {
		return nil, err
	}
	if e.baseline.prerequisites.verifyPrerequisiteReceipt(ctx, fresh, operation, receipt) != nil {
		return nil, ErrSecurityBaseline
	}
	if operation.secrets != nil && operation.secrets.verify(ctx, fresh) != nil {
		return nil, ErrSecurityBaseline
	}
	closed, err := lifecycle.original(ctx, fresh)
	if err != nil || e.confirmPrerequisiteReceipt(closed, operation, receipt) != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	return closed, nil
}

func (e *Engine) applyPrerequisite(ctx context.Context, s *installstate.Snapshot, key installstate.Key, digest string) (*installstate.Snapshot, error) {
	return e.applyPrerequisiteOwned(ctx, s, key, digest, nil)
}

func (e *Engine) applyPrerequisiteOwned(ctx context.Context, s *installstate.Snapshot, key installstate.Key, digest string, secrets *retainedBootstrapSecrets) (*installstate.Snapshot, error) {
	operation, err := e.prerequisiteOperation(s, key, digest)
	if err != nil || s.Document().Pending != nil {
		return s, ErrSecurityBaseline
	}
	operation.secrets = secrets
	return e.apply(ctx, s, key, digest, false, operation)
}

// This complete READ-only proof does not implement the runtime guard. It
// proves only that ONE original signed prerequisite CREATE can be considered;
// the effect engine must repeat it at each intent/effect/settlement boundary.
// Workloads, Secrets, Services, world writes and UPDATE/DELETE remain excluded.
func (c *ClusterSecurityBaseline) verifyPrerequisite(ctx context.Context, s *installstate.Snapshot, operation *baselinePrerequisite) error {
	if c == nil || c.engine == nil || ctx == nil || s == nil || c.access == nil || c.engine.access != c.access || !c.access.actorCompatible() {
		return ErrSecurityBaseline
	}
	if ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	receipt, err := c.engine.openPrerequisiteReceipt(s, operation)
	if err != nil {
		return ErrSecurityBaseline
	}
	defer receipt.release()
	return c.verifyPrerequisiteReceipt(ctx, s, operation, receipt)
}

func (c *ClusterSecurityBaseline) verifyPrerequisiteReceipt(ctx context.Context, s *installstate.Snapshot, operation *baselinePrerequisite, receipt *prerequisiteReceiptWitness) error {
	if c == nil || c.engine == nil || ctx == nil || ctx.Err() != nil || s == nil || c.access == nil || c.engine.access != c.access || !c.access.actorCompatible() || c.engine.confirmPrerequisiteReceipt(s, operation, receipt) != nil {
		return ErrSecurityBaseline
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	before, err := c.configured(ctx, s)
	if err != nil {
		return ErrSecurityBaseline
	}
	var previous map[installstate.Key]admissionIdentity
	for pass := 0; pass < 2; pass++ {
		observed, err := c.prerequisiteEmptyNamespaceReceipt(ctx, s, operation, receipt)
		if err != nil || pass != 0 && !reflect.DeepEqual(previous, observed) {
			return ErrSecurityBaseline
		}
		previous = observed
	}
	after, err := c.configured(ctx, s)
	if err != nil || !reflect.DeepEqual(before, after) || c.engine.confirmPrerequisiteReceipt(s, operation, receipt) != nil || ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

func (c *ClusterSecurityBaseline) prerequisiteEmptyNamespace(ctx context.Context, s *installstate.Snapshot, operation *baselinePrerequisite) (map[installstate.Key]admissionIdentity, error) {
	if c == nil || c.engine == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	receipt, err := c.engine.openPrerequisiteReceipt(s, operation)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	defer receipt.release()
	return c.prerequisiteEmptyNamespaceReceipt(ctx, s, operation, receipt)
}

func (c *ClusterSecurityBaseline) prerequisiteEmptyNamespaceReceipt(ctx context.Context, s *installstate.Snapshot, operation *baselinePrerequisite, receipt *prerequisiteReceiptWitness) (map[installstate.Key]admissionIdentity, error) {
	if c == nil || c.engine == nil || ctx == nil || ctx.Err() != nil || c.engine.confirmPrerequisiteReceipt(s, operation, receipt) != nil {
		return nil, ErrSecurityBaseline
	}
	if receipt != nil && receipt.source != nil {
		return c.prerequisiteRetainedNamespaceReceipt(ctx, s, operation, receipt)
	}
	lifecycle := &Lifecycle{engine: c.engine}
	if _, err := lifecycle.original(ctx, s); err != nil {
		return nil, ErrSecurityBaseline
	}
	d := s.Document()
	originals, err := c.prerequisiteOriginalsReceipt(ctx, s, operation, receipt)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	witness := maps.Clone(originals)
	reader, err := installobserve.NewGCReader(c.access.readConfig(), c.engine.journal, c.engine.plans[d.TargetPackage])
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	discovery, err := reader.Discover(ctx, s.Anchor())
	if err != nil || !discovery.CoversNamespaceLists() || !baselinePrerequisiteSources(discovery.Resources()) {
		return nil, ErrSecurityBaseline
	}
	for _, source := range discovery.Resources() {
		if c.access.authorize(ctx, gcMetadataPermission(source, d.Namespace).spec) != nil {
			return nil, ErrSecurityBaseline
		}
	}
	if _, err := lifecycle.original(ctx, s); err != nil {
		return nil, ErrSecurityBaseline
	}
	observation, err := reader.Collect(ctx, discovery)
	if err != nil || observation == nil || observation.Journal() == nil {
		return nil, ErrSecurityBaseline
	}
	journal := observation.Journal()
	if journal.Anchor() != s.Anchor() || journal.ResourceVersion() != s.ResourceVersion() || !bytes.Equal(journal.Bytes(), s.Bytes()) {
		return nil, ErrSecurityBaseline
	}
	seen := map[installstate.Key]bool{}
	for _, row := range observation.Objects() {
		key := installstate.Key{APIVersion: row.Source.GVR.GroupVersion().String(), Kind: row.Source.Kind, Namespace: row.Metadata.Namespace, Name: row.Metadata.Name}
		if baselinePrerequisiteEvent(row.Source) {
			continue // informational aliases cannot execute or confer authority
		}
		if seen[key] || row.Metadata.DeletionTimestamp != nil {
			return nil, ErrSecurityBaseline
		}
		seen[key] = true
		if original, found := witness[key]; found {
			if original.UID != row.Metadata.UID || original.ResourceVersion != row.Metadata.ResourceVersion {
				return nil, ErrSecurityBaseline
			}
			continue
		}
		if !c.benignPrerequisiteDefault(ctx, row) {
			return nil, ErrSecurityBaseline // foreign, executable or world objects
		}
		witness[key] = admissionIdentity{row.Metadata.UID, row.Metadata.ResourceVersion, ""}
	}
	// Complete lists must also contain every recorded namespaced prerequisite,
	// including a pending acknowledged target if its original UID is present.
	for key := range originals {
		if key.Namespace != "" && !seen[key] {
			return nil, ErrSecurityBaseline
		}
	}
	closing, err := c.prerequisiteOriginalsReceipt(ctx, s, operation, receipt)
	if err != nil || !reflect.DeepEqual(originals, closing) {
		return nil, ErrSecurityBaseline
	}
	if _, err := lifecycle.original(ctx, s); err != nil || c.engine.confirmPrerequisiteReceipt(s, operation, receipt) != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	return witness, nil
}

// Repeated whole-object reads also close original CLUSTER-scoped prerequisite
// and pending-target identities, which namespace metadata cannot witness.
func (c *ClusterSecurityBaseline) prerequisiteOriginals(ctx context.Context, s *installstate.Snapshot, operation *baselinePrerequisite) (map[installstate.Key]admissionIdentity, error) {
	if c == nil || c.engine == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	receipt, err := c.engine.openPrerequisiteReceipt(s, operation)
	if err != nil {
		return nil, ErrSecurityBaseline
	}
	defer receipt.release()
	return c.prerequisiteOriginalsReceipt(ctx, s, operation, receipt)
}

func (c *ClusterSecurityBaseline) prerequisiteOriginalsReceipt(ctx context.Context, s *installstate.Snapshot, operation *baselinePrerequisite, receipt *prerequisiteReceiptWitness) (map[installstate.Key]admissionIdentity, error) {
	if c == nil || c.engine == nil || ctx == nil || ctx.Err() != nil || c.access == nil || c.engine.confirmPrerequisiteReceipt(s, operation, receipt) != nil {
		return nil, ErrSecurityBaseline
	}
	d := s.Document()
	witness := map[installstate.Key]admissionIdentity{}
	for _, entry := range d.Resources {
		if entry.Key.Kind == "Namespace" {
			continue
		}
		template, err := c.engine.contracts[d.TargetPackage].Template(entry.Key, false)
		live, readErr := c.access.Get(ctx, entry.Key)
		if err != nil || readErr != nil || template.MatchLive(live, entry.UID) != nil {
			return nil, ErrSecurityBaseline
		}
		witness[entry.Key] = admissionIdentity{entry.UID, live.GetResourceVersion(), template.Hash()}
	}
	// Cluster-scoped prerequisites do not appear in namespace metadata lists.
	// Observe the exact target independently too: unrecorded matching names
	// cannot become bootstrap authority. A pending acknowledged CREATE requires
	// its protected original UID receipt and complete signed effect shape.
	target, targetErr := c.access.Get(ctx, operation.key)
	if !apierrors.IsNotFound(targetErr) {
		if targetErr != nil || target == nil || d.Pending == nil || receipt == nil || receipt.uid == "" {
			return nil, ErrSecurityBaseline
		}
		uid := receipt.uid
		template, contextErr := c.engine.prerequisiteContext(s, operation)
		if contextErr != nil || uid != target.GetUID() || !effectMatches(template, d.Pending, target) {
			return nil, ErrSecurityBaseline
		}
		witness[operation.key] = admissionIdentity{uid, target.GetResourceVersion(), template.Hash()}
	}
	if c.engine.confirmPrerequisiteReceipt(s, operation, receipt) != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	return witness, nil
}

func baselinePrerequisiteEvent(source installobserve.GCResource) bool {
	return source.Kind == "Event" && source.GVR.Resource == "events" && source.GVR.Version == "v1" && (source.GVR.Group == "" || source.GVR.Group == "events.k8s.io")
}

// Native defaults confer no new installation authority. Whole reads check
// finalizers too: the GC reader's intentionally public owner projection omits
// them. Root-CA contents are NEVER trust material, adopted or mutated.
func (c *ClusterSecurityBaseline) benignPrerequisiteDefault(ctx context.Context, row installobserve.GCObject) bool {
	m := row.Metadata
	if m.Namespace != c.engine.baselinePlan().Namespace() || m.UID == "" || m.ResourceVersion == "" || len(m.OwnerReferences) != 0 || len(m.Finalizers) != 0 || m.DeletionTimestamp != nil {
		return false
	}
	if row.Source.GVR == (schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}) && row.Source.Kind == "ConfigMap" && m.Name == "kube-root-ca.crt" {
		key := installstate.Key{APIVersion: "v1", Kind: "ConfigMap", Namespace: m.Namespace, Name: m.Name}
		// Closed benign read, not an expanded generic runtime effect route.
		live, err := c.access.requestAt(ctx, http.MethodGet, key, nil, false, "/api/v1/namespaces/"+m.Namespace+"/configmaps/kube-root-ca.crt", nil)
		var rootCA corev1.ConfigMap
		return err == nil && decodeServing(live, &rootCA) == nil && rootCA.UID == m.UID && rootCA.ResourceVersion == m.ResourceVersion && len(rootCA.OwnerReferences) == 0 && len(rootCA.Finalizers) == 0 && rootCA.DeletionTimestamp == nil
	}
	if row.Source.GVR != (schema.GroupVersionResource{Version: "v1", Resource: "serviceaccounts"}) || row.Source.Kind != "ServiceAccount" || m.Name != "default" {
		return false
	}
	key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: m.Namespace, Name: m.Name}
	live, err := c.access.Get(ctx, key)
	var account corev1.ServiceAccount
	return err == nil && decodeServing(live, &account) == nil && account.UID == m.UID && account.ResourceVersion == m.ResourceVersion && len(account.Secrets) == 0 && len(account.ImagePullSecrets) == 0 && len(account.OwnerReferences) == 0 && len(account.Finalizers) == 0 && account.DeletionTimestamp == nil && (account.AutomountServiceAccountToken == nil || !*account.AutomountServiceAccountToken)
}

// Require the known native executable/storage/credential lists explicitly.
// All additional discovered sources are still collected, never skipped. The
// reader selects preferred per-GroupResource versions; v1 is required here
// because it is the exact native version supported by both declared profiles.
func baselinePrerequisiteSources(sources []installobserve.GCResource) bool {
	required := map[schema.GroupVersionResource]string{
		{Version: "v1", Resource: "pods"}: "Pod", {Version: "v1", Resource: "persistentvolumeclaims"}: "PersistentVolumeClaim",
		{Version: "v1", Resource: "secrets"}: "Secret", {Version: "v1", Resource: "serviceaccounts"}: "ServiceAccount",
		{Version: "v1", Resource: "configmaps"}: "ConfigMap", {Version: "v1", Resource: "services"}: "Service",
		{Version: "v1", Resource: "replicationcontrollers"}:     "ReplicationController",
		{Group: "apps", Version: "v1", Resource: "deployments"}: "Deployment", {Group: "apps", Version: "v1", Resource: "replicasets"}: "ReplicaSet",
		{Group: "apps", Version: "v1", Resource: "daemonsets"}: "DaemonSet", {Group: "apps", Version: "v1", Resource: "statefulsets"}: "StatefulSet",
		{Group: "batch", Version: "v1", Resource: "jobs"}: "Job", {Group: "batch", Version: "v1", Resource: "cronjobs"}: "CronJob",
		{Group: "discovery.k8s.io", Version: "v1", Resource: "endpointslices"}: "EndpointSlice",
		{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}: "Role", {Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}: "RoleBinding",
	}
	for _, source := range sources {
		if kind, found := required[source.GVR]; found {
			if source.Kind != kind {
				return false
			}
			delete(required, source.GVR)
		}
	}
	return len(required) == 0
}
