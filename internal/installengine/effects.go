// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package installengine executes journal-before-effect public resource writes.
// It is an internal administrator primitive, NOT a complete installer or an
// authorization/safety/quiescence proof. Lifecycle orchestration must establish
// those barriers independently before calling these methods.
package installengine

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"

	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var (
	ErrInvalid        = errors.New("invalid installation mutation request")
	ErrRead           = errors.New("installation mutation read or response is unproved")
	ErrOwnership      = errors.New("installation resource original ownership is unproved")
	ErrConcurrent     = errors.New("installation journal changed concurrently")
	ErrOutcomeUnknown = errors.New("installation mutation remains pending; observe original intent before recovery")
)

type Engine struct {
	access    Access
	journal   *installstate.Store
	files     *privatefs.Store
	plans     map[string]*installrender.Plan
	contracts map[string]*installcontract.Contract
	templates map[installstate.Key]map[string]*installcontract.Template
}

// NewWithAccess is a trusted instrumentation seam. Production must use
// HTTPAccess for both the resource access and journal NamespaceAccess.
func NewWithAccess(access Access, journal *installstate.Store, files *privatefs.Store, plans ...*installrender.Plan) (*Engine, error) {
	if access == nil || reflect.ValueOf(access).Kind() == reflect.Pointer && reflect.ValueOf(access).IsNil() || journal == nil || files == nil || len(plans) < 1 || len(plans) > 3 {
		return nil, ErrInvalid
	}
	e := &Engine{access: access, journal: journal, files: files, plans: map[string]*installrender.Plan{}, contracts: map[string]*installcontract.Contract{}, templates: map[installstate.Key]map[string]*installcontract.Template{}}
	for _, p := range plans {
		if !p.IsTrusted() || p.Namespace() != plans[0].Namespace() || p.Profile().ID != plans[0].Profile().ID || e.plans[p.Digest()] != nil {
			return nil, ErrInvalid
		}
		c, err := installcontract.New(p)
		if err != nil {
			return nil, ErrInvalid
		}
		e.plans[p.Digest()], e.contracts[p.Digest()] = p, c
		for _, r := range p.Resources() {
			o := r.Object
			key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
			if e.templates[key] == nil {
				e.templates[key] = map[string]*installcontract.Template{}
			}
			for _, paused := range []bool{false, true} {
				t, err := c.Template(key, paused)
				if err == nil {
					e.templates[key][t.Hash()] = t
				}
			}
		}
	}
	return e, nil
}

// current binds a full Namespace read to the exact sealed original journal.
// This is a CAS barrier, not a distributed lock or atomic cluster snapshot.
func (e *Engine) current(ctx context.Context, s *installstate.Snapshot) (*installstate.Snapshot, error) {
	if e == nil || s == nil || ctx == nil {
		return nil, ErrInvalid
	}
	fresh, err := e.journal.Load(ctx, s.Anchor())
	if err != nil {
		return nil, ErrOwnership
	}
	if fresh.ResourceVersion() != s.ResourceVersion() || !bytes.Equal(fresh.Bytes(), s.Bytes()) {
		return nil, ErrConcurrent
	}
	d := fresh.Document()
	c := e.contracts[d.TargetPackage]
	if c == nil || !e.compatible(d) {
		return nil, ErrInvalid
	}
	key := namespaceKey(d.Namespace)
	t, err := c.Template(key, false)
	if err != nil {
		return nil, ErrInvalid
	}
	live, err := e.access.Get(ctx, key)
	if err != nil || t.MatchNamespace(live, fresh) != nil {
		return nil, ErrOwnership
	}
	return fresh, nil
}

func (e *Engine) compatible(d installstate.Document) bool {
	target, active := e.plans[d.TargetPackage], e.plans[d.ActivePackage]
	if target == nil {
		return false
	}
	switch d.Mode {
	case installstate.Install:
		return d.ActivePackage == "" || d.ActivePackage == d.TargetPackage
	case installstate.Upgrade:
		return active != nil && d.Installed && predecessor(target, active)
	case installstate.Rollback:
		return active != nil && d.Installed && d.PreviousPackage == d.TargetPackage && predecessor(active, target)
	case installstate.Uninstall:
		return active != nil && d.Installed && d.ActivePackage == d.TargetPackage
	}
	return false
}
func predecessor(newPlan, oldPlan *installrender.Plan) bool {
	m := oldPlan.Manifest()
	for _, p := range newPlan.Manifest().Predecessors {
		if p.PackageSHA256 == oldPlan.Digest() && p.SourceSHA == m.SourceSHA && p.Images == m.Images && p.Namespace == oldPlan.Namespace() && slices.Contains(p.ProfileIDs, oldPlan.Profile().ID) {
			return true
		}
	}
	return false
}

func (e *Engine) inventory(d installstate.Document, key installstate.Key) (*installstate.Resource, *installcontract.Template) {
	for _, r := range d.Resources {
		if r.Key == key {
			t := e.templates[key][r.TemplateSHA256]
			return &r, t
		}
	}
	return nil, nil
}

func (e *Engine) desired(d installstate.Document, key installstate.Key, digest string, paused bool) (*installcontract.Template, error) {
	if key.Kind == "Namespace" || key.Kind == "Secret" || d.Pending != nil {
		return nil, ErrInvalid
	}
	c := e.contracts[digest]
	if c == nil {
		return nil, ErrInvalid
	}
	t, err := c.Template(key, paused)
	if err != nil {
		return nil, ErrInvalid
	}
	if d.Stage == installstate.Quiescing {
		if digest != d.ActivePackage || !paused || t.Phase() != installrender.Controllers {
			return nil, ErrInvalid
		}
	} else if d.Stage != installstate.Applying || d.Mode == installstate.Uninstall || paused || digest != d.TargetPackage {
		return nil, ErrInvalid
	}
	return t, nil
}

func deletionAllowed(d installstate.Document, r *installstate.Resource, t *installcontract.Template) bool {
	if r == nil || t == nil || r.Retained || r.Key.Kind == "Namespace" || r.Key.Kind == "Secret" {
		return false
	}
	if d.Stage == installstate.Quiescing {
		return r.Key.Kind == "Deployment" && r.Phase == installrender.API
	}
	return d.Mode == installstate.Uninstall && d.Stage == installstate.Applying
}

// Apply persists an exact public nonce and before UID/RV before ONE real create
// or update. Dry-run is independently checked against signed desired defaults.
// An existing unowned object is never adopted, even when its shape matches.
func (e *Engine) Apply(ctx context.Context, s *installstate.Snapshot, key installstate.Key, digest string, paused bool) (*installstate.Snapshot, error) {
	fresh, err := e.current(ctx, s)
	if err != nil {
		return nil, err
	}
	d := fresh.Document()
	t, err := e.desired(d, key, digest, paused)
	if err != nil {
		return nil, err
	}
	r, old := e.inventory(d, key)
	nonce, err := installstate.NewID()
	if err != nil {
		return nil, ErrInvalid
	}
	p := &installstate.Pending{Key: key, CreateNonce: nonce, AfterSHA256: t.Hash()}
	var candidate *unstructured.Unstructured
	live, readErr := e.access.Get(ctx, key)
	if r == nil {
		if d.Stage == installstate.Quiescing {
			return nil, ErrOwnership
		}
		if !apierrors.IsNotFound(readErr) {
			return nil, ErrOwnership
		}
		candidate, err = t.Candidate(nonce)
		p.Action = installstate.Create
	} else {
		if readErr != nil || old == nil || old.MatchLive(live, r.UID) != nil {
			return nil, ErrOwnership
		}
		candidate, err = t.UpdateCandidate(old, live, r.UID, nonce)
		p.Action, p.BeforeUID, p.BeforeResourceVersion, p.BeforeSHA256 = installstate.Update, r.UID, live.GetResourceVersion(), r.TemplateSHA256
	}
	if err != nil {
		return nil, ErrInvalid
	}
	var admitted *unstructured.Unstructured
	if p.Action == installstate.Create {
		admitted, err = e.access.Create(ctx, key, candidate, true)
	} else {
		admitted, err = e.access.Update(ctx, key, candidate, true)
	}
	if err != nil || admitted == nil || t.MatchAdmitted(admitted) != nil || admitted.GetAnnotations()[installstate.MutationAnnotation] != nonce || p.Action == installstate.Update && admitted.GetUID() != p.BeforeUID {
		return nil, ErrRead
	}
	// Refuse a stale Namespace even when dry-run itself succeeded.
	fresh, err = e.current(ctx, fresh)
	if err != nil {
		return nil, err
	}
	d.Revision++
	d.Pending = p
	intent, err := e.journal.Commit(ctx, fresh, d)
	if err != nil {
		return nil, err
	} // NO target effect on unconfirmed intent
	if p.Action == installstate.Create {
		if err := e.prepareCreateReceipt(intent.Document()); err != nil {
			return intent, ErrOutcomeUnknown
		}
	}
	if _, err = e.current(ctx, intent); err != nil {
		return intent, ErrOutcomeUnknown
	}
	var ack *unstructured.Unstructured
	if p.Action == installstate.Create {
		ack, err = e.access.Create(ctx, key, candidate, false)
	} else {
		ack, err = e.access.Update(ctx, key, candidate, false)
	}
	// A successful acknowledgement must agree with the independently observed
	// effect. A lost response is correlated by the exact saved nonce instead.
	if err == nil && p.Action == installstate.Create && ack != nil {
		if pinErr := e.saveCreateUID(intent.Document(), ack.GetUID()); pinErr != nil {
			return intent, ErrOutcomeUnknown
		}
	}
	if err == nil && (ack == nil || !effectMatches(t, p, ack)) {
		return intent, ErrOutcomeUnknown
	}
	return e.recover(ctx, intent, ack, err == nil, ambiguousCreateResponse(err))
}

func ambiguousCreateResponse(err error) bool {
	return err != nil && !installstate.CreateResponseRejected(err) && !errors.Is(err, ErrOwnership) && !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrConcurrent)
}

func effectMatches(t *installcontract.Template, p *installstate.Pending, live *unstructured.Unstructured) bool {
	if live == nil || live.GetAnnotations()[installstate.MutationAnnotation] != p.CreateNonce || live.GetUID() == "" || live.GetResourceVersion() == "" {
		return false
	}
	uid := live.GetUID()
	if p.Action == installstate.Update {
		uid = p.BeforeUID
		if live.GetResourceVersion() == p.BeforeResourceVersion {
			return false
		}
	}
	return t.MatchLive(live, uid) == nil
}

// Delete is restricted to original, non-retained runtime inventory. Foreground
// deletion acceptance is not completion: settlement waits for actual absence.
// The caller MUST already prove GC retention closure and lifecycle quiescence.
func (e *Engine) Delete(ctx context.Context, s *installstate.Snapshot, key installstate.Key) (*installstate.Snapshot, error) {
	fresh, err := e.current(ctx, s)
	if err != nil {
		return nil, err
	}
	d := fresh.Document()
	r, t := e.inventory(d, key)
	if d.Pending != nil || !deletionAllowed(d, r, t) {
		return nil, ErrInvalid
	}
	live, err := e.access.Get(ctx, key)
	if err != nil || t.MatchLive(live, r.UID) != nil {
		return nil, ErrOwnership
	}
	nonce, err := installstate.NewID()
	if err != nil {
		return nil, ErrInvalid
	}
	p := &installstate.Pending{Action: installstate.Delete, Key: key, CreateNonce: nonce, BeforeUID: r.UID, BeforeResourceVersion: live.GetResourceVersion(), BeforeSHA256: r.TemplateSHA256}
	d.Revision++
	d.Pending = p
	intent, err := e.journal.Commit(ctx, fresh, d)
	if err != nil {
		return nil, err
	}
	if _, err = e.current(ctx, intent); err != nil {
		return intent, ErrOutcomeUnknown
	}
	uid, rv := p.BeforeUID, p.BeforeResourceVersion
	foreground := metav1.DeletePropagationForeground
	_ = e.access.Delete(ctx, key, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}, PropagationPolicy: &foreground})
	return e.recover(ctx, intent, nil, false, false)
}

// Recover observes and CAS-settles a proved original intent. It NEVER reissues
// create/update/delete or dry-run. NotFound after an uncertain create, unchanged
// before-state, or a deleting object leaves the intent pending: the original
// request may still finish later. Same-name replacements are not adopted.
func (e *Engine) Recover(ctx context.Context, s *installstate.Snapshot) (*installstate.Snapshot, error) {
	return e.recover(ctx, s, nil, false, false)
}
func (e *Engine) recover(ctx context.Context, s *installstate.Snapshot, ack *unstructured.Unstructured, hasAck, allowInitialObservation bool) (*installstate.Snapshot, error) {
	fresh, err := e.current(ctx, s)
	if err != nil {
		return s, ErrOutcomeUnknown
	}
	d := fresh.Document()
	p := d.Pending
	if p == nil || p.Key.Kind == "Secret" || p.Key.Kind == "Namespace" {
		return s, ErrInvalid
	}
	// Schema-valid public journal bytes do not authorize a different package,
	// paused target, action or stage. Bind recovery to the same action contract.
	var target *installcontract.Template
	if p.Action == installstate.Delete {
		r, old := e.inventory(d, p.Key)
		if !deletionAllowed(d, r, old) {
			return fresh, ErrInvalid
		}
	} else {
		copyDoc := d
		copyDoc.Pending = nil
		digest, paused := d.TargetPackage, false
		if d.Stage == installstate.Quiescing {
			digest, paused = d.ActivePackage, true
		}
		target, err = e.desired(copyDoc, p.Key, digest, paused)
		if err != nil || target.Hash() != p.AfterSHA256 || d.Stage == installstate.Quiescing && p.Action != installstate.Update {
			return fresh, ErrInvalid
		}
	}
	live, readErr := e.access.Get(ctx, p.Key)
	index := slices.IndexFunc(d.Resources, func(r installstate.Resource) bool { return r.Key == p.Key })
	if p.Action == installstate.Delete {
		if !apierrors.IsNotFound(readErr) || index < 0 || d.Resources[index].UID != p.BeforeUID || d.Resources[index].Retained {
			return fresh, ErrOutcomeUnknown
		}
		d.Resources = slices.Delete(d.Resources, index, index+1)
	} else {
		t := target
		if readErr != nil || t == nil || !effectMatches(t, p, live) || hasAck && ack.GetUID() != live.GetUID() {
			return fresh, ErrOutcomeUnknown
		}
		if p.Action == installstate.Create {
			if index >= 0 {
				return fresh, ErrOutcomeUnknown
			}
			// A restarted invocation cannot know whether an acknowledged UID
			// was lost before receipt fsync. Only the original call may establish
			// first identity from a genuinely lost response's immediate readback.
			if allowInitialObservation {
				if err := e.saveCreateUID(d, live.GetUID()); err != nil {
					return fresh, ErrOutcomeUnknown
				}
			}
			originalUID, err := e.loadCreateUID(d)
			if err != nil || originalUID != live.GetUID() {
				return fresh, ErrOutcomeUnknown
			}
			d.Resources = append(d.Resources, installstate.Resource{Key: p.Key, UID: live.GetUID(), TemplateSHA256: t.Hash(), Retained: t.Retained(), Phase: t.Phase()})
		} else if p.Action == installstate.Update && index >= 0 && d.Resources[index].UID == p.BeforeUID {
			d.Resources[index].TemplateSHA256 = t.Hash()
		} else {
			return fresh, ErrOutcomeUnknown
		}
	}
	installstate.SortResources(d.Resources)
	d.Revision++
	d.Pending = nil
	settled, err := e.journal.Commit(ctx, fresh, d)
	if err != nil {
		return fresh, ErrOutcomeUnknown
	}
	return settled, nil
}
