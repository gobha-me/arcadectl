// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// Only the same acknowledged retired-access DELETE may wait on this original
// foreground envelope. This comparison grants no authority or completion:
// full retired guards and independent recovery remain required after absence.
// General MatchLive and public/restarted recovery stay strict while draining.
func retiredAccessDeletingOriginal(before *installcontract.Template, pending *installstate.Pending, live *unstructured.Unstructured) bool {
	if before == nil || pending == nil || live == nil || !accessRetirementKey(pending.Key) || pending.Key != before.Key() || pending.Action != installstate.Delete || pending.BeforeSHA256 != before.Hash() || !nonceID.MatchString(pending.CreateNonce) || pending.AfterSHA256 != "" || !baselineParentRV(pending.BeforeResourceVersion) || live.GetUID() != pending.BeforeUID || !baselineParentRV(live.GetResourceVersion()) {
		return false
	}
	var object runtime.Object
	switch pending.Key.Kind {
	case "ServiceAccount":
		object = &corev1.ServiceAccount{}
	case "Role":
		object = &rbacv1.Role{}
	case "RoleBinding":
		object = &rbacv1.RoleBinding{}
	case "ClusterRole":
		object = &rbacv1.ClusterRole{}
	case "ClusterRoleBinding":
		object = &rbacv1.ClusterRoleBinding{}
	default:
		return false
	}
	if decodeServing(live, object) != nil {
		return false
	}
	m, err := meta.Accessor(object)
	if err != nil {
		return false
	}
	stamp := m.GetDeletionTimestamp()
	if stamp == nil {
		return live.GetResourceVersion() == pending.BeforeResourceVersion && before.MatchLive(live, pending.BeforeUID) == nil
	}
	grace, finalizers := m.GetDeletionGracePeriodSeconds(), m.GetFinalizers()
	if stamp.IsZero() || live.GetResourceVersion() == pending.BeforeResourceVersion || grace != nil && *grace != 0 || len(finalizers) != 1 || finalizers[0] != metav1.FinalizerDeleteDependents {
		return false
	}
	comparison := live.DeepCopy()
	for _, field := range []string{"deletionTimestamp", "deletionGracePeriodSeconds", "finalizers"} {
		unstructured.RemoveNestedField(comparison.Object, "metadata", field)
	}
	return before.MatchLive(comparison, pending.BeforeUID) == nil
}
