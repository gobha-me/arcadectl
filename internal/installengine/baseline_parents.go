// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"reflect"

	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Original parent identity is NOT availability, adoption, execution authority,
// or proof that a foreground deletion has completed. Whole native evidence is
// retained unchanged for the caller's closing collection and descendant proof.
type baselineParent struct {
	whole    *unstructured.Unstructured
	parent   *appsv1.Deployment
	template *installcontract.Template
	receipt  *baselineParentReceipt
}

type baselineParentReceipt = baselineOriginalReceipt

func (p *baselineParent) release() {
	if p != nil {
		p.receipt.release()
	}
}

func releaseBaselineParents(parents map[string]*baselineParent) {
	for _, parent := range parents {
		parent.release()
	}
}

func sameBaselineParents(a, b map[string]*baselineParent) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for name, left := range a {
		right, exists := b[name]
		if !exists || (left == nil) != (right == nil) {
			return false
		}
		if left == nil {
			continue
		}
		if left.whole == nil || right.whole == nil || left.template == nil || right.template == nil || left.template.Key() != right.template.Key() || left.template.Hash() != right.template.Hash() || !reflect.DeepEqual(left.whole.Object, right.whole.Object) || !reflect.DeepEqual(left.parent, right.parent) || !sameBaselineOriginalReceipt(left.receipt, right.receipt) {
			return false
		}
	}
	return true
}

// This private reader does not re-enter current(), serving, or the admission
// driver. It consumes the complete LIST/whole GET observation. An absent fresh
// parent is legitimate; a same-looking unrecorded parent is never accepted.
func (c *ClusterSecurityBaseline) originalParents(ctx context.Context, snapshot *installstate.Snapshot, executables *baselineExecutables) (map[string]*baselineParent, error) {
	if c == nil || c.engine == nil || c.engine.baseline == nil || c.access == nil || c.engine.access != c.access || ctx == nil || snapshot == nil || executables == nil || executables.observation == nil || executables.whole == nil {
		return nil, ErrSecurityBaseline
	}
	observed := executables.observation.Journal()
	if observed == nil || observed.Anchor() != snapshot.Anchor() || observed.ResourceVersion() != snapshot.ResourceVersion() || !bytes.Equal(observed.Bytes(), snapshot.Bytes()) {
		return nil, ErrSecurityBaseline
	}
	lifecycle := &Lifecycle{engine: c.engine}
	if _, err := lifecycle.original(ctx, snapshot); err != nil {
		return nil, ErrSecurityBaseline
	}
	d := snapshot.Document()
	parents := map[string]*baselineParent{}
	transferred := false
	defer func() {
		if !transferred {
			releaseBaselineParents(parents)
		}
	}()
	for _, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api"} {
		key := deploymentKey(d.Namespace, name)
		parent, err := c.engine.originalBaselineParent(d, key, executables.whole[key])
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		if parent != nil {
			parents[name] = parent
		}
	}
	if _, err := lifecycle.original(ctx, snapshot); err != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	if c.engine.confirmBaselineParentReceipts(d, parents) != nil || ctx.Err() != nil {
		return nil, ErrSecurityBaseline
	}
	transferred = true
	return parents, nil
}

// Close protected CREATE evidence AFTER the last remote original fence. The
// eventual full guard must call this again after its own final remote reads;
// the wrapper's bracket does not cover subsequent actor/inventory checks.
func (e *Engine) confirmBaselineParentReceipts(d installstate.Document, parents map[string]*baselineParent) error {
	if e == nil || parents == nil || !e.baselineObservable(d) {
		return ErrSecurityBaseline
	}
	for name, parent := range parents {
		if parent == nil || parent.whole == nil || parent.parent == nil || parent.template == nil || name != "arcadectl-controller" && name != "arcadectl-destroy-controller" && name != "arcadectl-api" || name != parent.parent.Name || parent.parent.Namespace != d.Namespace {
			return ErrSecurityBaseline
		}
		if parent.receipt == nil {
			if d.Pending != nil && d.Pending.Action == installstate.Create && d.Pending.Key == deploymentKey(d.Namespace, name) {
				return ErrSecurityBaseline
			}
			continue
		}
		if parent.whole.GetUID() != parent.parent.UID {
			return ErrSecurityBaseline
		}
		if e.confirmBaselineOriginalReceipt(d, deploymentKey(d.Namespace, name), &baselineOriginalObject{whole: parent.whole, template: parent.template, receipt: parent.receipt}) != nil {
			return ErrSecurityBaseline
		}
	}
	return nil
}

func (e *Engine) originalBaselineParent(d installstate.Document, key installstate.Key, live *unstructured.Unstructured) (*baselineParent, error) {
	if e == nil || !e.baselineObservable(d) || key != deploymentKey(d.Namespace, key.Name) || key.Name != "arcadectl-controller" && key.Name != "arcadectl-destroy-controller" && key.Name != "arcadectl-api" {
		return nil, ErrSecurityBaseline
	}
	original, err := e.originalBaselineObject(d, key, live)
	if err != nil || original == nil {
		return nil, err
	}
	parent, err := baselineAcceptedParent(original.whole, original.template)
	if err != nil {
		original.release()
		return nil, ErrSecurityBaseline
	}
	parent.receipt = original.receipt
	return parent, nil
}

// Shared sealed original/effect classification; its address domain is only
// the three installation parents and the fixed sixteen reserved metadata keys.
// The parent and metadata wrappers retain their separate narrower domains.
func (e *Engine) originalBaselineObject(d installstate.Document, key installstate.Key, live *unstructured.Unstructured) (*baselineOriginalObject, error) {
	if e == nil || !e.baselineObservable(d) || !baselineOriginalKey(d.Namespace, key) {
		return nil, ErrSecurityBaseline
	}
	entry, before := e.inventory(d, key)
	pending := d.Pending
	if pending == nil || pending.Key != key {
		if entry == nil {
			if live != nil {
				return nil, ErrSecurityBaseline
			}
			return nil, nil
		}
		if before == nil || before.MatchLive(live, entry.UID) != nil {
			return nil, ErrSecurityBaseline
		}
		return baselineAcceptedOriginal(key, live, before)
	}
	if !nonceID.MatchString(pending.CreateNonce) {
		return nil, ErrSecurityBaseline
	}
	if pending.Action == installstate.Delete {
		if entry == nil || before == nil || pending.BeforeUID != entry.UID || pending.BeforeSHA256 != before.Hash() || !baselineParentRV(pending.BeforeResourceVersion) || pending.AfterSHA256 != "" || !deletionAllowed(d, entry, before) {
			return nil, ErrSecurityBaseline
		}
		if live == nil {
			return nil, nil // exact original DELETE intent; absence is not adoption
		}
		if !baselineDeletingOriginal(before, pending, live) {
			return nil, ErrSecurityBaseline
		}
		return baselineAcceptedOriginal(key, live, before)
	}
	// Only action derivation gets a disposable pending-free document. The
	// protected snapshot, original intent and journal bytes remain untouched.
	contextDoc := d
	contextDoc.Pending = nil
	digest, paused := d.TargetPackage, false
	if d.Stage == installstate.Quiescing {
		digest, paused = d.ActivePackage, true
	}
	after, err := e.desired(contextDoc, key, digest, paused)
	if err != nil || after.Hash() != pending.AfterSHA256 {
		return nil, ErrSecurityBaseline
	}
	switch pending.Action {
	case installstate.Create:
		if entry != nil || before != nil || pending.BeforeUID != "" || pending.BeforeResourceVersion != "" || pending.BeforeSHA256 != "" {
			return nil, ErrSecurityBaseline
		}
		if live == nil {
			return nil, nil // original request may not have taken effect yet
		}
		if e.files == nil {
			return nil, ErrSecurityBaseline
		}
		// A public nonce and matching template do not establish original UID.
		// Missing/empty protected acknowledgement stays unresolved: no first
		// UID pin, CREATE replay, or copied-nonce adoption occurs in this guard.
		name := "create-" + pending.CreateNonce + ".json"
		body, identity, pin, err := e.files.Pin(name, 4096)
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		transferred := false
		defer func() {
			if !transferred {
				_ = pin.Close()
			}
		}()
		if pin.Confirm() != nil {
			return nil, ErrSecurityBaseline
		}
		uid, err := e.loadCreateUID(d)
		want, bodyErr := receiptBody(d, uid)
		closedBody, closedIdentity, closeErr := e.files.Read(name, 4096)
		if err != nil || bodyErr != nil || closeErr != nil || closedIdentity != identity || !bytes.Equal(body, want) || !bytes.Equal(body, closedBody) || pin.Confirm() != nil || live.GetUID() != uid || !effectMatches(after, pending, live) {
			return nil, ErrSecurityBaseline
		}
		parent, err := baselineAcceptedOriginal(key, live, after)
		if err != nil {
			return nil, ErrSecurityBaseline
		}
		parent.receipt = &baselineParentReceipt{identity: identity, body: bytes.Clone(body), pin: pin}
		transferred = true
		return parent, nil
	case installstate.Update:
		if entry == nil || before == nil || pending.BeforeUID != entry.UID || pending.BeforeSHA256 != before.Hash() || !baselineParentRV(pending.BeforeResourceVersion) || live == nil || live.GetUID() != entry.UID {
			return nil, ErrSecurityBaseline
		}
		if live.GetResourceVersion() == pending.BeforeResourceVersion && live.GetAnnotations()[installstate.MutationAnnotation] != pending.CreateNonce && before.MatchLive(live, entry.UID) == nil {
			return baselineAcceptedOriginal(key, live, before)
		}
		if effectMatches(after, pending, live) {
			return baselineAcceptedOriginal(key, live, after)
		}
	}
	return nil, ErrSecurityBaseline
}

func baselineAcceptedParent(live *unstructured.Unstructured, template *installcontract.Template) (*baselineParent, error) {
	if live == nil || template == nil || !receiptUID.MatchString(string(live.GetUID())) || !baselineParentRV(live.GetResourceVersion()) {
		return nil, ErrSecurityBaseline
	}
	var parent appsv1.Deployment
	if decodeServing(live, &parent) != nil {
		return nil, ErrSecurityBaseline
	}
	return &baselineParent{whole: live.DeepCopy(), parent: parent.DeepCopy(), template: template}, nil
}

// Narrow private identity/shape check for an authorized original foreground
// DELETE. Public MatchLive is unchanged. Only validated native deletion fields
// are removed from a disposable comparison; raw evidence remains exact.
func baselineDeletingParent(before *installcontract.Template, pending *installstate.Pending, live *unstructured.Unstructured) bool {
	return before != nil && before.Key().Kind == "Deployment" && baselineOriginalKey(before.Key().Namespace, before.Key()) && baselineDeletingOriginal(before, pending, live)
}
