// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"

	"github.com/go-logr/logr"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ServiceAccountsObservation seals a complete, bounded namespace collection.
// It grants no mutation, ownership, token, RBAC or owner-closure authority.
// Preserve both typed and raw values: typed decoding alone collapses optional
// nulls and cannot establish exact whole LIST/GET agreement.
type ServiceAccountsObservation struct {
	journal  *installstate.Snapshot
	accounts *corev1.ServiceAccountList
	whole    []*unstructured.Unstructured
}

func (o *ServiceAccountsObservation) Journal() *installstate.Snapshot {
	if o == nil {
		return nil
	}
	return o.journal
}

func (o *ServiceAccountsObservation) Accounts() *corev1.ServiceAccountList {
	if o == nil || o.accounts == nil {
		return nil
	}
	return o.accounts.DeepCopy()
}

func (o *ServiceAccountsObservation) Whole() []*unstructured.Unstructured {
	if o == nil || o.whole == nil {
		return nil
	}
	objects := make([]*unstructured.Unstructured, len(o.whole))
	for i, object := range o.whole {
		objects[i] = object.DeepCopy()
	}
	return objects
}

// CollectServiceAccounts is opt-in; ordinary observations and their historical
// phase encoding remain unchanged. No selector, cached RV, partial collection,
// expired-list fallback, token read or owner-resolution exception is admitted.
func (o *Observer) CollectServiceAccounts(ctx context.Context, anchor installstate.Anchor) (*ServiceAccountsObservation, error) {
	if o == nil || o.journal == nil || ctx == nil || !o.plan.IsTrusted() || anchor.Namespace != o.plan.Namespace() {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, observationTimeout)
	defer cancel()
	ctx = logr.NewContext(ctx, logr.Discard())
	before, err := o.journal.Load(ctx, anchor)
	if err != nil || before.Anchor() != anchor {
		return nil, ErrOwnership
	}
	doc := before.Document()
	if doc.ProfileID != o.plan.Profile().ID || !slices.Contains([]string{doc.ActivePackage, doc.TargetPackage, doc.PreviousPackage}, o.plan.Digest()) {
		return nil, ErrOwnership
	}
	budget := maxCollectionBytes
	items, rv, err := boundedPages(ctx, func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		page, err := o.clients.Dynamic.Resource(schema.GroupVersionResource{Version: "v1", Resource: "serviceaccounts"}).Namespace(anchor.Namespace).List(ctx, opts)
		if err != nil || page == nil || page.GetAPIVersion() != "v1" || page.GetKind() != "ServiceAccountList" {
			return nil, ErrRead
		}
		return page, nil
	}, &budget)
	if err != nil {
		return nil, ErrRead
	}
	accounts := &corev1.ServiceAccountList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccountList"}, ListMeta: metav1.ListMeta{ResourceVersion: rv}, Items: []corev1.ServiceAccount{}}
	whole := make([]*unstructured.Unstructured, 0, len(items))
	names, uids := map[string]bool{}, map[string]bool{}
	for _, item := range items {
		object, ok := item.(*unstructured.Unstructured)
		if !ok || object == nil || object.GetAPIVersion() != "v1" || object.GetKind() != "ServiceAccount" || object.GetNamespace() != anchor.Namespace || object.GetName() == "" || !validIdentity(string(object.GetUID())) || !validIdentity(object.GetResourceVersion()) || names[object.GetName()] || uids[string(object.GetUID())] {
			return nil, ErrRead
		}
		body, err := json.Marshal(object.Object)
		var account corev1.ServiceAccount
		if err != nil || strictDecode(body, &account) != nil {
			return nil, ErrRead
		}
		names[object.GetName()], uids[string(object.GetUID())] = true, true
		accounts.Items = append(accounts.Items, account)
		whole = append(whole, object.DeepCopy())
	}
	after, err := o.journal.Load(ctx, anchor)
	if err != nil || after.Anchor() != anchor || after.ResourceVersion() != before.ResourceVersion() || !bytes.Equal(before.Bytes(), after.Bytes()) {
		return nil, ErrConcurrent
	}
	if ctx.Err() != nil {
		return nil, ErrRead
	}
	return &ServiceAccountsObservation{after, accounts, whole}, nil
}
