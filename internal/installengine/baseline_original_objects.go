// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"strconv"

	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// These are original identity/shape witnesses, not availability, adoption,
// deletion completion, effect permission or coldness. Whole replies stay exact.
type baselineOriginalObject struct {
	whole    *unstructured.Unstructured
	template *installcontract.Template
	receipt  *baselineOriginalReceipt
}

type baselineOriginalReceipt struct {
	identity privatefs.FileIdentity
	body     []byte
	pin      *privatefs.FilePin
}

func (r *baselineOriginalReceipt) release() {
	if r != nil {
		_ = r.pin.Close()
	}
}

func (o *baselineOriginalObject) release() {
	if o != nil {
		o.receipt.release()
	}
}

// Independently acquired witnesses have different owned handles. Compare
// exact evidence only; handle liveness remains a separate final confirmation.
func sameBaselineOriginalReceipt(a, b *baselineOriginalReceipt) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.identity == b.identity && (a.body == nil) == (b.body == nil) && bytes.Equal(a.body, b.body)
}

func baselineOriginalKey(namespace string, key installstate.Key) bool {
	if baselineMetadataKey(namespace, key) {
		return true
	}
	return key == deploymentKey(namespace, key.Name) && (key.Name == "arcadectl-controller" || key.Name == "arcadectl-destroy-controller" || key.Name == "arcadectl-api")
}

func baselineOriginalMeta(key installstate.Key, live *unstructured.Unstructured) (*metav1.ObjectMeta, error) {
	if live == nil || !baselineOriginalKey(key.Namespace, key) || live.GetAPIVersion() != key.APIVersion || live.GetKind() != key.Kind || live.GetNamespace() != key.Namespace || live.GetName() != key.Name {
		return nil, ErrSecurityBaseline
	}
	// Strict concrete decoding preserves the native kind-specific schema. In
	// particular Service/SA/RBAC generation zero is valid, unlike a Deployment.
	switch key.Kind {
	case "Deployment":
		var object appsv1.Deployment
		if decodeServing(live, &object) == nil {
			return &object.ObjectMeta, nil
		}
	case "ServiceAccount":
		var object corev1.ServiceAccount
		if decodeServing(live, &object) == nil {
			return &object.ObjectMeta, nil
		}
	case "Service":
		var object corev1.Service
		if decodeServing(live, &object) == nil {
			return &object.ObjectMeta, nil
		}
	case "Role":
		var object rbacv1.Role
		if decodeServing(live, &object) == nil {
			return &object.ObjectMeta, nil
		}
	case "RoleBinding":
		var object rbacv1.RoleBinding
		if decodeServing(live, &object) == nil {
			return &object.ObjectMeta, nil
		}
	}
	return nil, ErrSecurityBaseline
}

func baselineAcceptedOriginal(key installstate.Key, live *unstructured.Unstructured, template *installcontract.Template) (*baselineOriginalObject, error) {
	if template == nil || template.Key() != key || live == nil || !receiptUID.MatchString(string(live.GetUID())) || !baselineParentRV(live.GetResourceVersion()) {
		return nil, ErrSecurityBaseline
	}
	if _, err := baselineOriginalMeta(key, live); err != nil {
		return nil, ErrSecurityBaseline
	}
	return &baselineOriginalObject{whole: live.DeepCopy(), template: template}, nil
}

func baselineParentRV(value string) bool {
	rv, err := strconv.ParseUint(value, 10, 64)
	return err == nil && rv > 0 && strconv.FormatUint(rv, 10) == value
}

// Public MatchLive stays strict. Only an authorized pending-original DELETE
// may accommodate this exact foreground envelope on a disposable comparison.
// No raw fields, allocation fields, owner references or status are discarded.
func baselineDeletingOriginal(before *installcontract.Template, pending *installstate.Pending, live *unstructured.Unstructured) bool {
	if before == nil || pending == nil || live == nil || pending.Key != before.Key() || pending.Action != installstate.Delete || live.GetUID() != pending.BeforeUID || !baselineParentRV(live.GetResourceVersion()) {
		return false
	}
	meta, err := baselineOriginalMeta(before.Key(), live)
	if err != nil {
		return false
	}
	if meta.DeletionTimestamp == nil {
		return live.GetResourceVersion() == pending.BeforeResourceVersion && before.MatchLive(live, pending.BeforeUID) == nil
	}
	if meta.DeletionTimestamp.IsZero() || live.GetResourceVersion() == pending.BeforeResourceVersion || meta.DeletionGracePeriodSeconds != nil && *meta.DeletionGracePeriodSeconds != 0 || len(meta.Finalizers) != 1 || meta.Finalizers[0] != metav1.FinalizerDeleteDependents {
		return false
	}
	comparison := live.DeepCopy()
	for _, field := range []string{"deletionTimestamp", "deletionGracePeriodSeconds", "finalizers"} {
		unstructured.RemoveNestedField(comparison.Object, "metadata", field)
	}
	return before.MatchLive(comparison, pending.BeforeUID) == nil
}

// Keep the OPENING protected receipt identity through every subsequent remote
// read. An identical-body atomic replacement is not the original ACK receipt.
func (e *Engine) confirmBaselineOriginalReceipt(d installstate.Document, key installstate.Key, object *baselineOriginalObject) error {
	if e == nil || !e.baselineObservable(d) || !baselineOriginalKey(d.Namespace, key) || object == nil || object.whole == nil || object.template == nil || object.template.Key() != key {
		return ErrSecurityBaseline
	}
	if _, err := baselineOriginalMeta(key, object.whole); err != nil {
		return ErrSecurityBaseline
	}
	pending := d.Pending
	if object.receipt == nil {
		if pending != nil && pending.Action == installstate.Create && pending.Key == key {
			return ErrSecurityBaseline
		}
		return nil
	}
	if e.files == nil || object.receipt.pin == nil || pending == nil || pending.Action != installstate.Create || !nonceID.MatchString(pending.CreateNonce) || pending.Key != key {
		return ErrSecurityBaseline
	}
	want, err := receiptBody(d, object.whole.GetUID())
	if err != nil || !bytes.Equal(want, object.receipt.body) {
		return ErrSecurityBaseline
	}
	name := "create-" + pending.CreateNonce + ".json"
	body, identity, err := e.files.Read(name, 4096)
	if err != nil || identity != object.receipt.identity || !bytes.Equal(body, object.receipt.body) || object.receipt.pin.Confirm() != nil {
		return ErrSecurityBaseline
	}
	return nil
}
