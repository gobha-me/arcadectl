// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package installcontract checks whole live/admitted objects against sealed
// signed templates and reviewed Kubernetes defaults. Admission output does not
// define the contract: dry-run and actual readbacks are checked independently.
// Original identity, mutation ordering, policy behavior and quiescence remain
// responsibilities of the installer engine.
package installcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

const maxObjectBytes = 1024 * 1024

var (
	ErrInvalid  = errors.New("invalid installation template contract")
	ErrIdentity = errors.New("installation resource original identity is unproved")
	ErrDrift    = errors.New("installation resource differs from the signed contract")
	ErrCRD      = errors.New("installation CRD storage, conversion or establishment is unsafe")
	nonceID     = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

type Contract struct {
	plan      *installrender.Plan
	resources map[installstate.Key]installrender.Resource
}

// Template is a sealed signed desired state. Paused variants exist only for the
// two controller Deployments, never for the API admission Deployment.
type Template struct {
	contract *Contract
	resource installrender.Resource
	key      installstate.Key
	expected runtime.Object
	hash     string
	paused   bool
}

func New(plan *installrender.Plan) (*Contract, error) {
	if !plan.IsTrusted() {
		return nil, ErrInvalid
	}
	c := &Contract{plan: plan, resources: map[installstate.Key]installrender.Resource{}}
	for _, r := range plan.Resources() {
		o := r.Object
		key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
		c.resources[key] = r
		if _, err := c.Template(key, false); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Contract) Template(key installstate.Key, paused bool) (*Template, error) {
	if c == nil || !c.plan.IsTrusted() {
		return nil, ErrInvalid
	}
	r, exists := c.resources[key]
	if !exists || paused && (key.Kind != "Deployment" || r.Phase != installrender.Controllers) {
		return nil, ErrInvalid
	}
	r.Object = r.Object.DeepCopy()
	if paused {
		if err := unstructured.SetNestedField(r.Object.Object, int64(0), "spec", "replicas"); err != nil {
			return nil, ErrInvalid
		}
	}
	body, err := json.Marshal(r.Object.Object)
	if err != nil {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(body)
	expected, err := decode(r.Object)
	if err != nil {
		return nil, err
	}
	defaults(expected)
	return &Template{contract: c, resource: r, key: key, expected: expected, hash: hex.EncodeToString(sum[:]), paused: paused}, nil
}

func (t *Template) Hash() string {
	if t == nil {
		return ""
	}
	return t.hash
}
func (t *Template) Key() installstate.Key {
	if t == nil {
		return installstate.Key{}
	}
	return t.key
}
func (t *Template) Retained() bool { return t != nil && t.resource.Retained }
func (t *Template) Phase() installrender.Phase {
	if t == nil {
		return ""
	}
	return t.resource.Phase
}

// PodTemplate returns a defensive copy of the signed, independently defaulted
// Deployment template. It grants no Pod mutation or live ownership authority.
func (t *Template) PodTemplate() (*corev1.PodTemplateSpec, error) {
	if t == nil {
		return nil, ErrInvalid
	}
	d, ok := t.expected.(*appsv1.Deployment)
	if !ok || d == nil {
		return nil, ErrInvalid
	}
	return d.Spec.Template.DeepCopy(), nil
}

// Candidate produces only reviewed raw desired fields plus a public mutation
// nonce. The engine must journal that exact nonce BEFORE sending this object.
// Namespace creation belongs exclusively to the durable bootstrap workflow.
func (t *Template) Candidate(nonce string) (*unstructured.Unstructured, error) {
	if t == nil || t.expected == nil || t.key.Kind == "Namespace" || !nonceID.MatchString(nonce) {
		return nil, ErrInvalid
	}
	o := t.resource.Object.DeepCopy()
	a := o.GetAnnotations()
	if a == nil {
		a = map[string]string{}
	}
	a[installstate.MutationAnnotation] = nonce
	o.SetAnnotations(a)
	return o, nil
}

// MatchLive's UID must be durable original inventory, never a freshly looked-up
// name. Status is evaluated separately by readiness/storage checks. Unknown
// fields are refused before typed conversion can discard them.
func (t *Template) MatchLive(object *unstructured.Unstructured, originalUID types.UID) error {
	if object == nil || originalUID == "" || object.GetUID() != originalUID || !identity(object.GetResourceVersion()) {
		return ErrIdentity
	}
	return t.match(object, nil)
}

// MatchAdmitted checks shape only. It grants no ownership and does not prove
// that the actual write took effect. The engine checks actual readback again.
func (t *Template) MatchAdmitted(object *unstructured.Unstructured) error {
	return t.match(object, nil)
}

// MatchNamespace additionally binds dynamic journal annotations to the sealed
// original Namespace observation; arbitrary annotation exemptions are forbidden.
func (t *Template) MatchNamespace(object *unstructured.Unstructured, journal *installstate.Snapshot) error {
	if object == nil || journal == nil || t == nil || t.key.Kind != "Namespace" || journal.Anchor().Namespace != t.key.Name || journal.Anchor().UID != object.GetUID() || journal.ResourceVersion() != object.GetResourceVersion() {
		return ErrIdentity
	}
	return t.match(object, journal)
}

func (t *Template) match(object *unstructured.Unstructured, journal *installstate.Snapshot) error {
	if t == nil || t.expected == nil || object == nil || object.GetAPIVersion() != t.key.APIVersion || object.GetKind() != t.key.Kind || object.GetName() != t.key.Name || object.GetNamespace() != t.key.Namespace {
		return ErrInvalid
	}
	if object.GetDeletionTimestamp() != nil || len(object.GetOwnerReferences()) != 0 || len(object.GetFinalizers()) != 0 {
		return ErrDrift
	}
	actual, err := decode(object)
	if err != nil {
		return err
	}
	m, err := meta.Accessor(actual)
	if err != nil {
		return ErrInvalid
	}
	if m.GetUID() != "" && !identity(string(m.GetUID())) || m.GetResourceVersion() != "" && !identity(m.GetResourceVersion()) || m.GetGeneration() < 0 {
		return ErrIdentity
	}
	m.SetUID("")
	m.SetResourceVersion("")
	m.SetGeneration(0)
	m.SetCreationTimestamp(metav1.Time{})
	m.SetManagedFields(nil)
	m.SetOwnerReferences(nil)
	m.SetFinalizers(nil)
	if m.GetSelfLink() != "" || m.GetGenerateName() != "" || m.GetDeletionGracePeriodSeconds() != nil {
		return ErrDrift
	}
	a := m.GetAnnotations()
	if nonce, exists := a[installstate.MutationAnnotation]; exists {
		if !nonceID.MatchString(nonce) {
			return ErrDrift
		}
		delete(a, installstate.MutationAnnotation)
	}
	if t.key.Kind == "Deployment" {
		if revision, exists := a["deployment.kubernetes.io/revision"]; exists {
			v, err := strconv.ParseUint(revision, 10, 64)
			if err != nil || v == 0 || len(revision) > 20 || strconv.FormatUint(v, 10) != revision {
				return ErrDrift
			}
			delete(a, "deployment.kubernetes.io/revision")
		}
	}
	if t.key.Kind == "Namespace" {
		if journal == nil || a[installstate.BootstrapAnnotation] != journal.Anchor().InstallationID || !bytes.Equal([]byte(a[installstate.Annotation]), journal.Bytes()) {
			return ErrIdentity
		}
		delete(a, installstate.BootstrapAnnotation)
		delete(a, installstate.Annotation)
	}
	if len(a) == 0 {
		a = nil
	}
	m.SetAnnotations(a)
	switch o := actual.(type) {
	case *appsv1.Deployment:
		o.Status = appsv1.DeploymentStatus{}
		if o.Spec.Template.Spec.DeprecatedServiceAccount != "" && o.Spec.Template.Spec.DeprecatedServiceAccount != o.Spec.Template.Spec.ServiceAccountName {
			return ErrDrift
		}
		o.Spec.Template.Spec.DeprecatedServiceAccount = ""
	case *corev1.Service:
		if !validAllocation(o) {
			return ErrDrift
		}
		o.Spec.ClusterIP = ""
		o.Spec.ClusterIPs = nil
		o.Spec.IPFamilies = nil
		o.Status = corev1.ServiceStatus{}
	case *corev1.Namespace:
		labels := o.Labels
		if labels["kubernetes.io/metadata.name"] != t.key.Name {
			return ErrDrift
		}
		delete(labels, "kubernetes.io/metadata.name")
		o.Status = corev1.NamespaceStatus{}
	case *crdv1.CustomResourceDefinition:
		// Nested schema unions have custom JSON decoders. Compare their raw
		// signed shape too, so unknown schema fields cannot disappear there.
		if !sameCRDSpec(t.resource.Object, object) {
			return ErrDrift
		}
		o.Status = crdv1.CustomResourceDefinitionStatus{}
	case *admissionv1.ValidatingAdmissionPolicy:
		o.Status = admissionv1.ValidatingAdmissionPolicyStatus{}
	}
	expected := t.expected.DeepCopyObject()
	// Strict decoding and the raw CRD comparison have already rejected unknown
	// fields. Kubernetes semantic equality additionally compares quantities by
	// numeric value, including different formats (64Mi == 67108864 bytes).
	if !apiequality.Semantic.DeepEqual(expected, actual) {
		return ErrDrift
	}
	return nil
}

// UpdateCandidate preserves only original UID/RV, validated server revision,
// and validated Service allocation. It does not copy unknown live fields.
// The previous template must independently match before construction.
func (t *Template) UpdateCandidate(previous *Template, live *unstructured.Unstructured, originalUID types.UID, nonce string) (*unstructured.Unstructured, error) {
	if t == nil || previous == nil || t.contract == nil || previous.contract == nil || t.key != previous.key || t.contract.plan.Namespace() != previous.contract.plan.Namespace() || t.contract.plan.Profile().ID != previous.contract.plan.Profile().ID || previous.MatchLive(live, originalUID) != nil {
		return nil, ErrDrift
	}
	if t.key.Kind == "CustomResourceDefinition" && !sameCRDSpec(previous.resource.Object, t.resource.Object) {
		return nil, ErrCRD
	}
	o, err := t.Candidate(nonce)
	if err != nil {
		return nil, err
	}
	o.SetUID(originalUID)
	o.SetResourceVersion(live.GetResourceVersion())
	if t.key.Kind == "Service" {
		for _, name := range []string{"clusterIP", "clusterIPs", "ipFamilies", "ipFamilyPolicy"} {
			value, exists, err := unstructured.NestedFieldCopy(live.Object, "spec", name)
			if err != nil || !exists {
				return nil, ErrDrift
			}
			if err := unstructured.SetNestedField(o.Object, value, "spec", name); err != nil {
				return nil, ErrInvalid
			}
		}
	}
	if t.key.Kind == "Deployment" {
		if revision := live.GetAnnotations()["deployment.kubernetes.io/revision"]; revision != "" {
			a := o.GetAnnotations()
			a["deployment.kubernetes.io/revision"] = revision
			o.SetAnnotations(a)
		}
	}
	return o, nil
}

func identity(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "\r\n\x00")
}

func decode(object *unstructured.Unstructured) (runtime.Object, error) {
	var result runtime.Object
	switch object.GetAPIVersion() + "/" + object.GetKind() {
	case "v1/Namespace":
		result = &corev1.Namespace{}
	case "v1/ServiceAccount":
		result = &corev1.ServiceAccount{}
	case "v1/Service":
		result = &corev1.Service{}
	case "apps/v1/Deployment":
		result = &appsv1.Deployment{}
	case "rbac.authorization.k8s.io/v1/Role":
		result = &rbacv1.Role{}
	case "rbac.authorization.k8s.io/v1/RoleBinding":
		result = &rbacv1.RoleBinding{}
	case "rbac.authorization.k8s.io/v1/ClusterRole":
		result = &rbacv1.ClusterRole{}
	case "rbac.authorization.k8s.io/v1/ClusterRoleBinding":
		result = &rbacv1.ClusterRoleBinding{}
	case "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy":
		result = &admissionv1.ValidatingAdmissionPolicy{}
	case "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicyBinding":
		result = &admissionv1.ValidatingAdmissionPolicyBinding{}
	case "apiextensions.k8s.io/v1/CustomResourceDefinition":
		result = &crdv1.CustomResourceDefinition{}
	default:
		return nil, ErrInvalid
	}
	body, err := json.Marshal(object.Object)
	if err != nil || len(body) > maxObjectBytes {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(result); err != nil {
		return nil, ErrDrift
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrDrift
	}
	return result, nil
}

func validAllocation(o *corev1.Service) bool {
	if len(o.Spec.ClusterIPs) != 1 || len(o.Spec.IPFamilies) != 1 || o.Spec.ClusterIP != o.Spec.ClusterIPs[0] || o.Spec.IPFamilyPolicy == nil || *o.Spec.IPFamilyPolicy != corev1.IPFamilyPolicySingleStack {
		return false
	}
	ip, err := netip.ParseAddr(o.Spec.ClusterIP)
	return err == nil && ip.IsGlobalUnicast() && ip.Zone() == "" && !ip.Is4In6() && (ip.Is4() && o.Spec.IPFamilies[0] == corev1.IPv4Protocol || ip.Is6() && o.Spec.IPFamilies[0] == corev1.IPv6Protocol)
}

func sameCRDSpec(a, b *unstructured.Unstructured) bool {
	copySpec := func(o *unstructured.Unstructured) map[string]any {
		spec, exists, err := unstructured.NestedMap(o.Object, "spec")
		if err != nil || !exists {
			return nil
		}
		if _, exists := spec["conversion"]; !exists {
			spec["conversion"] = map[string]any{"strategy": "None"}
		}
		// An absent deprecated false field is equivalent to explicitly false.
		if value, exists := spec["preserveUnknownFields"]; exists && value == false {
			delete(spec, "preserveUnknownFields")
		}
		return spec
	}
	aa, bb := copySpec(a), copySpec(b)
	if aa == nil || bb == nil {
		return false
	}
	want, wantErr := json.Marshal(aa)
	got, gotErr := json.Marshal(bb)
	// Unstructured int64 and typed-schema float64 can describe the same
	// integral JSON number. Compare their encoded shape without dropping keys.
	return wantErr == nil && gotErr == nil && bytes.Equal(want, got)
}
