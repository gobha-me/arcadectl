// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// Selection only: neither retirement nor a familiar name proves leafness.
func retiredNamespaceAccessLeaf(d installstate.Document) bool {
	if !retiringAccessDelete(d) || d.Pending.Key.Namespace != d.Namespace {
		return false
	}
	key := d.Pending.Key
	switch key.Kind {
	case "Role", "RoleBinding":
		return key.APIVersion == "rbac.authorization.k8s.io/v1"
	case "ServiceAccount":
		return key.APIVersion == "v1"
	}
	return false
}

// Fresh read-only leaf barrier AFTER the existing full pre-effect guards and
// durable original intent. No caller callback, fixture adoption, finalizer
// editing, permission grant, fallback or replay is permitted. These temporal
// observations are not a namespace lock: concurrent child creation after its
// collection page remains outside Kubernetes' atomic UID/RV preconditions.
func (e *Engine) prepareRetiredLeafDelete(ctx context.Context, s *installstate.Snapshot) error {
	if e == nil || ctx == nil || ctx.Err() != nil || s == nil {
		return ErrInvalid
	}
	d := s.Document()
	access, ok := e.access.(*HTTPAccess)
	if !ok || !access.actorCompatible() || !retiredNamespaceAccessLeaf(d) {
		return ErrInvalid
	}
	p := d.Pending
	r, template := e.inventory(d, p.Key)
	if !deletionAllowed(d, r, template) || r.UID != p.BeforeUID || r.TemplateSHA256 != p.BeforeSHA256 {
		return ErrOwnership
	}
	witness, err := e.openRetirementEvidence(d)
	if err != nil {
		return ErrAdmission
	}
	defer witness.release()
	reader, err := installobserve.NewGCReader(access.readConfig(), e.journal, e.plans[d.TargetPackage])
	if err != nil {
		return ErrRead
	}
	discovery, err := reader.Discover(ctx, s.Anchor())
	if err != nil || !discovery.CoversNamespaceLists() {
		return ErrRead
	}
	for _, source := range discovery.Resources() {
		if access.authorize(ctx, gcMetadataPermission(source, d.Namespace).spec) != nil {
			return ErrRead
		}
	}
	observation, err := reader.Collect(ctx, discovery)
	if err != nil || observation == nil {
		return ErrRead
	}
	journal := observation.Journal()
	if journal == nil || journal.Anchor() != s.Anchor() || journal.ResourceVersion() != s.ResourceVersion() || !bytes.Equal(journal.Bytes(), s.Bytes()) {
		return ErrConcurrent
	}
	plural := map[string]string{"Role": "roles", "RoleBinding": "rolebindings", "ServiceAccount": "serviceaccounts"}[p.Key.Kind]
	gv, err := schema.ParseGroupVersion(p.Key.APIVersion)
	if err != nil {
		return ErrInvalid
	}
	source := installobserve.GCResource{GVR: gv.WithResource(plural), Kind: p.Key.Kind}
	found := 0
	for _, object := range observation.Objects() {
		m := object.Metadata
		if m.UID == p.BeforeUID {
			if object.Source != source || m.Namespace != d.Namespace || m.Name != p.Key.Name || m.ResourceVersion != p.BeforeResourceVersion || m.DeletionTimestamp != nil || len(m.OwnerReferences) != 0 {
				return ErrOwnership
			}
			found++
		}
	}
	// Descendants intentionally supports absent roots for other GC readers;
	// here emptiness is insufficient unless the exact original root was read.
	children, err := observation.Descendants([]types.UID{p.BeforeUID})
	if found != 1 || err != nil || len(children) != 0 {
		return ErrOwnership
	}
	// GC reads trail the preceding full runtime proof. Close that added read
	// interval against the receipt's exact original live policy UID/RVs and
	// access subset; unchanged Namespace/file bytes alone cannot detect live
	// policy changes. This nonrecursive core grants no new actor authority.
	if e.verifyRetiredAdmissionCore(ctx, s) != nil {
		return ErrAdmission
	}
	live, err := access.Get(ctx, p.Key)
	if err != nil || template.MatchLive(live, p.BeforeUID) != nil || live.GetResourceVersion() != p.BeforeResourceVersion {
		return ErrOwnership
	}
	if _, err := e.currentOriginal(ctx, s); err != nil {
		return err
	}
	if e.closeRetirementEvidence(witness) != nil || ctx.Err() != nil {
		return ErrAdmission
	}
	return nil
}
