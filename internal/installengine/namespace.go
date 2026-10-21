// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"

	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

type namespaces struct{ access *HTTPAccess }

// Namespaces supplies the same at-most-one HTTP write guarantee to bootstrap
// and journal CAS. Do not substitute an ordinary retrying typed client in the
// production installer. Tests may use a trusted fake implementing this seam.
func (a *HTTPAccess) Namespaces() installstate.NamespaceAccess { return namespaces{a} }
func namespaceKey(name string) installstate.Key {
	return installstate.Key{APIVersion: "v1", Kind: "Namespace", Name: name}
}
func namespaceResult(o *unstructured.Unstructured, err error) (*corev1.Namespace, error) {
	if err != nil {
		return nil, err
	}
	n := &corev1.Namespace{}
	if o == nil || runtime.DefaultUnstructuredConverter.FromUnstructured(o.Object, n) != nil {
		return nil, ErrRead
	}
	return n, nil
}
func (n namespaces) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Namespace, error) {
	if opts.ResourceVersion != "" {
		return nil, ErrInvalid
	}
	return namespaceResult(n.access.Get(ctx, namespaceKey(name)))
}
func (n namespaces) Create(ctx context.Context, o *corev1.Namespace, opts metav1.CreateOptions) (*corev1.Namespace, error) {
	if o == nil || len(opts.DryRun) != 0 || opts.FieldManager != "" || opts.FieldValidation != "" {
		return nil, ErrInvalid
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(o)
	if err != nil {
		return nil, ErrInvalid
	}
	obj["apiVersion"], obj["kind"] = "v1", "Namespace"
	return namespaceResult(n.access.Create(ctx, namespaceKey(o.Name), &unstructured.Unstructured{Object: obj}, false))
}
func (n namespaces) Update(ctx context.Context, o *corev1.Namespace, opts metav1.UpdateOptions) (*corev1.Namespace, error) {
	if o == nil || len(opts.DryRun) != 0 || opts.FieldManager != "" || opts.FieldValidation != "" || o.UID == "" || o.ResourceVersion == "" {
		return nil, ErrInvalid
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(o)
	if err != nil {
		return nil, ErrInvalid
	}
	obj["apiVersion"], obj["kind"] = "v1", "Namespace"
	return namespaceResult(n.access.Update(ctx, namespaceKey(o.Name), &unstructured.Unstructured{Object: obj}, false))
}
