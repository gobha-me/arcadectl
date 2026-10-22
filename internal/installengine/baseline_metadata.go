// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// All sixteen exact addresses occur, including nil = an actual native 404.
// Missing map entries are unknown, not proven absence. This witness does not
// substitute for complete access, actor authorization or effective admission.
type baselineMetadata struct {
	snapshot *installstate.Snapshot
	objects  map[installstate.Key]*baselineOriginalObject
}

func (m *baselineMetadata) release() {
	if m != nil {
		for _, object := range m.objects {
			object.release()
		}
	}
}

func baselineMetadataKeys(namespace string) []installstate.Key {
	keys := make([]installstate.Key, 0, 16)
	for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
		for _, kind := range []string{"ServiceAccount", "Role", "RoleBinding", "Service"} {
			version := "v1"
			if kind == "Role" || kind == "RoleBinding" {
				version = "rbac.authorization.k8s.io/v1"
			}
			keys = append(keys, installstate.Key{APIVersion: version, Kind: kind, Namespace: namespace, Name: name})
		}
	}
	return keys
}

func baselineMetadataKey(namespace string, key installstate.Key) bool {
	for _, want := range baselineMetadataKeys(namespace) {
		if key == want {
			return true
		}
	}
	return false
}

func (c *ClusterSecurityBaseline) originalMetadata(ctx context.Context, snapshot *installstate.Snapshot) (*baselineMetadata, error) {
	if c == nil || c.engine == nil || c.engine.baseline == nil || c.access == nil || c.engine.access != c.access || !c.access.actorCompatible() || ctx == nil || snapshot == nil {
		return nil, ErrSecurityBaseline
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	plan := c.engine.plans[snapshot.Document().TargetPackage]
	if !plan.IsTrusted() || c.access.checkVersion(ctx, plan.Profile()) != nil {
		return nil, ErrSecurityBaseline
	}
	var opening *baselineMetadata
	transferred := false
	defer func() {
		if !transferred {
			opening.release()
		}
	}()
	for pass := 0; pass < 2; pass++ {
		observed, err := c.originalMetadataPass(ctx, snapshot)
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		if pass == 0 {
			opening = observed
		} else {
			same := sameBaselineMetadata(opening, observed)
			observed.release()
			if !same {
				return nil, ErrSecurityBaseline
			}
		}
	}
	// Reconfirm the opening receipt AFTER the second closing remote fence.
	// A later full guard must repeat this after its own final remote reads.
	if c.engine.confirmBaselineMetadataReceipts(opening) != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	transferred = true
	return opening, nil
}

func (c *ClusterSecurityBaseline) originalMetadataPass(ctx context.Context, snapshot *installstate.Snapshot) (*baselineMetadata, error) {
	lifecycle := &Lifecycle{engine: c.engine}
	if _, err := lifecycle.original(ctx, snapshot); err != nil {
		return nil, ErrSecurityBaseline
	}
	d := snapshot.Document()
	// Discovery is private to this pass and frozen before workers launch. It
	// carries no authorization verdict: EACH row still validates that discovery
	// and performs its own fresh named administrator review before its exact GET.
	type metadataRead struct {
		key        installstate.Key
		permission proofPermission
		discovery  *metav1.APIResourceList
	}
	var frozen []metadataRead
	discoveries := map[string]*metav1.APIResourceList{}
	for _, key := range baselineMetadataKeys(d.Namespace) {
		permission, err := publicPermission(key, "get")
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		discovery := discoveries[key.APIVersion]
		if discovery == nil {
			discovery, err = c.access.discover(ctx, key.APIVersion)
			discoveries[key.APIVersion] = discovery
		}
		if err != nil || discovery == nil {
			return nil, ErrSecurityBaseline
		}
		frozen = append(frozen, metadataRead{key, permission, discovery})
	}
	results := make([]*baselineOriginalObject, len(frozen))
	transferred := false
	defer func() {
		if !transferred {
			// Run only after ALL workers join. A successful Pending CREATE row
			// owns its independent receipt even when a sibling later refuses.
			for _, object := range results {
				object.release()
			}
		}
	}()
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	read := func(row metadataRead) (*baselineOriginalObject, error) {
		if !discoveredPermission(row.discovery, row.permission) || c.access.authorize(readCtx, row.permission.spec) != nil {
			return nil, ErrSecurityBaseline
		}
		live, err := c.access.Get(readCtx, row.key)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, ErrSecurityBaseline
			}
			live = nil
		} else if live == nil {
			return nil, ErrSecurityBaseline
		}
		return c.engine.originalBaselineObject(d, row.key, live)
	}
	var failures [baselineReadLanes]error
	var readers sync.WaitGroup
	for lane := range baselineReadLanes {
		readers.Go(func() {
			for index := lane; index < len(frozen); index += baselineReadLanes {
				if readCtx.Err() != nil {
					failures[lane] = ErrSecurityBaseline
					return
				}
				object, err := read(frozen[index])
				results[index] = object // own any acquired receipt through join
				if err != nil || readCtx.Err() != nil {
					failures[lane] = ErrSecurityBaseline
					cancel()
					return
				}
			}
		})
	}
	// No partial map, receipt release, next pass or closing remote fence may
	// outrun a sibling authorization/GET/body/classifier operation.
	readers.Wait()
	if ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	for _, err := range failures {
		if err != nil {
			return nil, ErrSecurityBaseline
		}
	}
	observed := &baselineMetadata{snapshot: snapshot, objects: make(map[installstate.Key]*baselineOriginalObject, len(frozen))}
	for index, row := range frozen {
		observed.objects[row.key] = results[index]
	}
	if _, err := lifecycle.original(ctx, snapshot); err != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	transferred = true
	return observed, nil
}

func sameBaselineMetadata(a, b *baselineMetadata) bool {
	if a == nil || b == nil || a.snapshot == nil || b.snapshot == nil || a.snapshot.Anchor() != b.snapshot.Anchor() || a.snapshot.ResourceVersion() != b.snapshot.ResourceVersion() || !reflect.DeepEqual(a.snapshot.Bytes(), b.snapshot.Bytes()) || len(a.objects) != 16 || len(b.objects) != 16 {
		return false
	}
	return sameBaselineMetadataObjects(a, b)
}

// Whole original objects only, NOT journal continuity or an effect permit.
// The historical cross-CAS owner separately proves both actual snapshots and
// the baseline-only transition, without rebasing either metadata observation.
func sameBaselineMetadataObjects(a, b *baselineMetadata) bool {
	if a == nil || b == nil || a.snapshot == nil || b.snapshot == nil || a.snapshot.Anchor() != b.snapshot.Anchor() || len(a.objects) != 16 || len(b.objects) != 16 {
		return false
	}
	for _, key := range baselineMetadataKeys(a.snapshot.Anchor().Namespace) {
		left, leftExists := a.objects[key]
		right, rightExists := b.objects[key]
		if !leftExists || !rightExists || (left == nil) != (right == nil) {
			return false
		}
		if left == nil {
			continue
		}
		if left.whole == nil || right.whole == nil || left.template == nil || right.template == nil || left.template.Key() != key || right.template.Key() != key || left.template.Hash() != right.template.Hash() || !reflect.DeepEqual(left.whole.Object, right.whole.Object) || !sameBaselineOriginalReceipt(left.receipt, right.receipt) {
			return false
		}
	}
	return true
}

func (e *Engine) confirmBaselineMetadataReceipts(observed *baselineMetadata) error {
	if e == nil || observed == nil || !sameBaselineMetadata(observed, observed) || !e.baselineObservable(observed.snapshot.Document()) {
		return ErrSecurityBaseline
	}
	d := observed.snapshot.Document()
	for _, key := range baselineMetadataKeys(d.Namespace) {
		object := observed.objects[key]
		if object != nil && e.confirmBaselineOriginalReceipt(d, key, object) != nil {
			return ErrSecurityBaseline
		}
	}
	return nil
}
