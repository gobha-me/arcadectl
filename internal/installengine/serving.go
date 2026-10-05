// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

var ErrServing = errors.New("original installation API serving identity is unproved")

// Serving is sealed, bounded serving evidence, not a cluster lock or a proof
// that authenticated activation happened. It cannot authorize mutations.
type Serving struct {
	engine                      *Engine
	namespace, podName, address string
	podUID                      types.UID
	fingerprint                 [32]byte
}

func (Serving) String() string             { return "installation serving evidence" }
func (Serving) GoString() string           { return "installation serving evidence" }
func (Serving) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "installation serving evidence") }

func decodeServing(o *unstructured.Unstructured, out any) error {
	if o == nil {
		return ErrServing
	}
	body, err := json.Marshal(o.Object)
	if err != nil || len(body) > 1024*1024 {
		return ErrServing
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrServing
	}
	return nil
}

func originalOwner(meta metav1.ObjectMeta, version, kind, name string, uid types.UID) bool {
	if len(meta.OwnerReferences) != 1 {
		return false
	}
	o := meta.OwnerReferences[0]
	return o.APIVersion == version && o.Kind == kind && o.Name == name && o.UID == uid && o.Controller != nil && *o.Controller && o.BlockOwnerDeletion != nil && *o.BlockOwnerDeletion
}

func servingMetadata(meta metav1.ObjectMeta, namespace string) bool {
	return meta.Namespace == namespace && addressPart(meta.Name) && receiptUID.MatchString(string(meta.UID)) && receiptUID.MatchString(meta.ResourceVersion) && meta.Generation >= 0 && meta.DeletionTimestamp == nil && meta.DeletionGracePeriodSeconds == nil && len(meta.Finalizers) == 0 && meta.SelfLink == ""
}

// ObserveServing checks original signed Service/Deployment/SA inventory, complete
// EndpointSlice data and the actual Pod->ReplicaSet->Deployment owner chain.
// Runtime Pod defaults are independently reviewed, never inferred from a
// matching webhook or accepted by wildcard. Original journal barriers surround
// all reads. Callers must repeat this evidence around authenticated activation.
func (e *Engine) ObserveServing(ctx context.Context, s *installstate.Snapshot, access ServingAccess) (*Serving, error) {
	if nilAccess(access) || ctx == nil {
		return nil, ErrServing
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	fresh, err := e.current(ctx, s)
	if err != nil {
		return nil, ErrServing
	}
	d := fresh.Document()
	if d.Pending != nil || d.Stage != installstate.Verifying || d.Mode == installstate.Uninstall {
		return nil, ErrServing
	}
	objects := make([]*unstructured.Unstructured, 0, 3)
	for _, key := range []installstate.Key{{APIVersion: "v1", Kind: "Service", Namespace: d.Namespace, Name: "arcadectl-api"}, {APIVersion: "apps/v1", Kind: "Deployment", Namespace: d.Namespace, Name: "arcadectl-api"}, {APIVersion: "v1", Kind: "ServiceAccount", Namespace: d.Namespace, Name: "arcadectl-api"}} {
		r, t := e.inventory(d, key)
		desired, wantErr := e.contracts[d.TargetPackage].Template(key, false)
		if r == nil || t == nil || wantErr != nil || r.TemplateSHA256 != desired.Hash() {
			return nil, ErrServing
		}
		obj, getErr := e.access.Get(ctx, key)
		if getErr != nil || t.MatchLive(obj, r.UID) != nil {
			return nil, ErrServing
		}
		objects = append(objects, obj)
	}
	var service corev1.Service
	var deployment appsv1.Deployment
	var sa corev1.ServiceAccount
	if decodeServing(objects[0], &service) != nil || decodeServing(objects[1], &deployment) != nil || decodeServing(objects[2], &sa) != nil || !readyDeployment(&deployment) || sa.AutomountServiceAccountToken != nil && !*sa.AutomountServiceAccountToken || len(sa.ImagePullSecrets) != 0 {
		return nil, ErrServing
	}
	list, err := access.ListEndpointSlices(ctx, d.Namespace)
	if err != nil || list == nil || list.ResourceVersion == "" || list.Continue != "" || list.RemainingItemCount != nil && *list.RemainingItemCount != 0 || len(list.Items) > 1000 {
		return nil, ErrServing
	}
	var selected *discoveryv1.Endpoint
	selectedSlices := make([]discoveryv1.EndpointSlice, 0, 2)
	seenUIDs := map[types.UID]bool{}
	seenNames := map[string]bool{}
	for _, slice := range list.Items {
		if slice.Namespace != d.Namespace || slice.UID == "" || slice.ResourceVersion == "" || seenUIDs[slice.UID] || seenNames[slice.Name] {
			return nil, ErrServing
		}
		seenUIDs[slice.UID] = true
		seenNames[slice.Name] = true
		if slice.Labels[discoveryv1.LabelServiceName] != service.Name {
			continue
		}
		if !validServingSlice(&slice, &service) {
			return nil, ErrServing
		}
		selectedSlices = append(selectedSlices, *slice.DeepCopy())
		for _, endpoint := range slice.Endpoints {
			if selected != nil || !validServingEndpoint(&endpoint, slice.AddressType, d.Namespace) {
				return nil, ErrServing
			}
			selected = endpoint.DeepCopy()
		}
	}
	if selected == nil {
		return nil, ErrServing
	}
	podObject, err := access.GetPod(ctx, d.Namespace, selected.TargetRef.Name)
	if err != nil {
		return nil, ErrServing
	}
	var pod corev1.Pod
	if decodeServing(podObject, &pod) != nil || pod.APIVersion != "v1" || pod.Kind != "Pod" || pod.UID != selected.TargetRef.UID || !servingMetadata(pod.ObjectMeta, d.Namespace) || pod.Status.PodIP != selected.Addresses[0] || selected.NodeName == nil || *selected.NodeName != pod.Spec.NodeName || !readyPod(&pod) || len(pod.OwnerReferences) != 1 {
		return nil, ErrServing
	}
	owner := pod.OwnerReferences[0]
	if owner.APIVersion != "apps/v1" || owner.Kind != "ReplicaSet" || !addressPart(owner.Name) || owner.UID == "" {
		return nil, ErrServing
	}
	rsObject, err := access.GetReplicaSet(ctx, d.Namespace, owner.Name)
	if err != nil {
		return nil, ErrServing
	}
	var rs appsv1.ReplicaSet
	if decodeServing(rsObject, &rs) != nil || rs.APIVersion != "apps/v1" || rs.Kind != "ReplicaSet" || rs.UID != owner.UID || !validServingReplicaSet(&rs, &deployment) || !originalOwner(pod.ObjectMeta, "apps/v1", "ReplicaSet", rs.Name, rs.UID) || !validServingPodTemplate(&pod, &rs) {
		return nil, ErrServing
	}
	if _, err := e.current(ctx, fresh); err != nil {
		return nil, ErrServing
	}
	slices.SortFunc(selectedSlices, func(a, b discoveryv1.EndpointSlice) int { return strings.Compare(a.Name, b.Name) })
	// Include exact resource versions and shapes, not only a Pod URL or name.
	body, err := json.Marshal(struct {
		Journal         []byte
		Objects         []*unstructured.Unstructured
		Slices          []discoveryv1.EndpointSlice
		Pod, ReplicaSet *unstructured.Unstructured
	}{fresh.Bytes(), objects, selectedSlices, podObject, rsObject})
	if err != nil || len(body) > 4*1024*1024 {
		return nil, ErrServing
	}
	return &Serving{engine: e, namespace: d.Namespace, podName: pod.Name, podUID: pod.UID, address: pod.Status.PodIP, fingerprint: sha256.Sum256(body)}, nil
}

func readyDeployment(d *appsv1.Deployment) bool {
	return d.Generation > 0 && d.Spec.Replicas != nil && *d.Spec.Replicas == 1 && d.Spec.Strategy.Type == appsv1.RecreateDeploymentStrategyType && d.Status.ObservedGeneration == d.Generation && d.Status.Replicas == 1 && d.Status.UpdatedReplicas == 1 && d.Status.ReadyReplicas == 1 && d.Status.AvailableReplicas == 1 && d.Status.UnavailableReplicas == 0 && (d.Status.TerminatingReplicas == nil || *d.Status.TerminatingReplicas == 0)
}

func validServingSlice(s *discoveryv1.EndpointSlice, service *corev1.Service) bool {
	if !servingMetadata(s.ObjectMeta, service.Namespace) || !originalOwner(s.ObjectMeta, "v1", "Service", service.Name, service.UID) || s.GenerateName != service.Name+"-" || len(s.Ports) != 1 || len(s.Endpoints) > 100 {
		return false
	}
	if len(service.Spec.IPFamilies) != 1 || service.Spec.IPFamilies[0] == corev1.IPv4Protocol && s.AddressType != discoveryv1.AddressTypeIPv4 || service.Spec.IPFamilies[0] == corev1.IPv6Protocol && s.AddressType != discoveryv1.AddressTypeIPv6 {
		return false
	}
	labels := map[string]string{}
	for k, v := range service.Labels {
		labels[k] = v
	}
	labels[discoveryv1.LabelServiceName] = service.Name
	labels[discoveryv1.LabelManagedBy] = "endpointslice-controller.k8s.io"
	if !apiequality.Semantic.DeepEqual(s.Labels, labels) {
		return false
	}
	for key, value := range s.Annotations {
		if key != "endpoints.kubernetes.io/last-change-trigger-time" {
			return false
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
			return false
		}
	}
	p := s.Ports[0]
	return p.Name != nil && *p.Name == "https" && p.Protocol != nil && *p.Protocol == corev1.ProtocolTCP && p.Port != nil && *p.Port == 8443 && p.AppProtocol == nil && (s.AddressType == discoveryv1.AddressTypeIPv4 || s.AddressType == discoveryv1.AddressTypeIPv6)
}

func validServingEndpoint(e *discoveryv1.Endpoint, kind discoveryv1.AddressType, namespace string) bool {
	if len(e.Addresses) != 1 || e.TargetRef == nil || e.TargetRef.Kind != "Pod" || e.TargetRef.APIVersion != "" && e.TargetRef.APIVersion != "v1" || e.TargetRef.Namespace != namespace || !addressPart(e.TargetRef.Name) || !receiptUID.MatchString(string(e.TargetRef.UID)) || e.TargetRef.ResourceVersion != "" || e.TargetRef.FieldPath != "" || e.Hostname != nil || e.Hints != nil || e.NodeName == nil || len(validation.IsDNS1123Subdomain(*e.NodeName)) != 0 || e.Conditions.Ready == nil || !*e.Conditions.Ready || e.Conditions.Serving == nil || !*e.Conditions.Serving || e.Conditions.Terminating == nil || *e.Conditions.Terminating {
		return false
	}
	if e.Zone != nil && (len(*e.Zone) > 63 || len(validation.IsValidLabelValue(*e.Zone)) != 0) {
		return false
	}
	ip, err := netip.ParseAddr(e.Addresses[0])
	return err == nil && ip.String() == e.Addresses[0] && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && !ip.Is4In6() && (kind == discoveryv1.AddressTypeIPv4 && ip.Is4() || kind == discoveryv1.AddressTypeIPv6 && ip.Is6())
}

func validServingReplicaSet(rs *appsv1.ReplicaSet, d *appsv1.Deployment) bool {
	if !servingMetadata(rs.ObjectMeta, d.Namespace) || rs.Generation < 1 || !originalOwner(rs.ObjectMeta, "apps/v1", "Deployment", d.Name, d.UID) || rs.GenerateName != "" || rs.Spec.Replicas == nil || *rs.Spec.Replicas != 1 || rs.Spec.MinReadySeconds != d.Spec.MinReadySeconds || rs.Status.ObservedGeneration != rs.Generation || rs.Status.Replicas != 1 || rs.Status.FullyLabeledReplicas != 1 || rs.Status.ReadyReplicas != 1 || rs.Status.AvailableReplicas != 1 || rs.Status.TerminatingReplicas != nil && *rs.Status.TerminatingReplicas != 0 {
		return false
	}
	hash := rs.Labels[appsv1.DefaultDeploymentUniqueLabelKey]
	if hash == "" || len(hash) > 63 || len(validation.IsDNS1123Label(hash)) != 0 || rs.Name != d.Name+"-"+hash {
		return false
	}
	want := d.Spec.Template.DeepCopy()
	if want.Labels == nil {
		return false
	}
	want.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = hash
	actual := rs.Spec.Template.DeepCopy()
	if !normalizeSAAlias(&want.Spec) || !normalizeSAAlias(&actual.Spec) || !apiequality.Semantic.DeepEqual(want, actual) || !apiequality.Semantic.DeepEqual(rs.Labels, want.Labels) {
		return false
	}
	selector := d.Spec.Selector.DeepCopy()
	selector.MatchLabels[appsv1.DefaultDeploymentUniqueLabelKey] = hash
	if !apiequality.Semantic.DeepEqual(selector, rs.Spec.Selector) {
		return false
	}
	annotations := map[string]string{}
	for key, value := range d.Annotations {
		annotations[key] = value
	}
	revision := d.Annotations["deployment.kubernetes.io/revision"]
	if !canonicalPositive(revision) {
		return false
	}
	annotations["deployment.kubernetes.io/desired-replicas"] = "1"
	annotations["deployment.kubernetes.io/max-replicas"] = "1"
	if history, ok := rs.Annotations["deployment.kubernetes.io/revision-history"]; ok {
		parts := strings.Split(history, ",")
		if len(parts) > 128 {
			return false
		}
		seen := map[string]bool{}
		limit, _ := strconv.ParseUint(revision, 10, 64)
		for _, part := range parts {
			value, _ := strconv.ParseUint(part, 10, 64)
			if !canonicalPositive(part) || value >= limit || seen[part] {
				return false
			}
			seen[part] = true
		}
		annotations["deployment.kubernetes.io/revision-history"] = history
	}
	return apiequality.Semantic.DeepEqual(rs.Annotations, annotations)
}

func canonicalPositive(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
}
func normalizeSAAlias(s *corev1.PodSpec) bool {
	if s.DeprecatedServiceAccount != "" && s.DeprecatedServiceAccount != s.ServiceAccountName {
		return false
	}
	s.DeprecatedServiceAccount = ""
	return true
}

func readyPod(p *corev1.Pod) bool {
	if p.Status.Phase != corev1.PodRunning || len(p.Status.ContainerStatuses) != 1 || len(p.Status.InitContainerStatuses) != 0 || len(p.Status.EphemeralContainerStatuses) != 0 {
		return false
	}
	c := p.Status.ContainerStatuses[0]
	if c.Name != "api" || !c.Ready || c.Started != nil && !*c.Started || c.State.Running == nil || c.State.Waiting != nil || c.State.Terminated != nil {
		return false
	}
	seen := map[corev1.PodConditionType]bool{}
	for _, condition := range p.Status.Conditions {
		if seen[condition.Type] {
			return false
		}
		seen[condition.Type] = true
		if (condition.Type == corev1.PodReady || condition.Type == corev1.ContainersReady || condition.Type == corev1.PodScheduled || condition.Type == corev1.PodInitialized) && condition.Status != corev1.ConditionTrue {
			return false
		}
	}
	return seen[corev1.PodReady] && seen[corev1.ContainersReady] && seen[corev1.PodScheduled] && seen[corev1.PodInitialized]
}

func validServingPodTemplate(p *corev1.Pod, rs *appsv1.ReplicaSet) bool {
	if p.GenerateName != rs.Name+"-" || !generatedServingName(p.Name, p.GenerateName) || !apiequality.Semantic.DeepEqual(p.Labels, rs.Spec.Template.Labels) || !apiequality.Semantic.DeepEqual(p.Annotations, rs.Spec.Template.Annotations) {
		return false
	}
	want, actual := rs.Spec.Template.Spec.DeepCopy(), p.Spec.DeepCopy()
	if !normalizeSAAlias(want) || !normalizeSAAlias(actual) || actual.NodeName == "" || len(validation.IsDNS1123Subdomain(actual.NodeName)) != 0 || actual.EnableServiceLinks == nil || !*actual.EnableServiceLinks || actual.Priority != nil && *actual.Priority != 0 || actual.PreemptionPolicy != nil && *actual.PreemptionPolicy != corev1.PreemptLowerPriority || len(actual.Tolerations) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, toleration := range actual.Tolerations {
		if (toleration.Key != "node.kubernetes.io/not-ready" && toleration.Key != "node.kubernetes.io/unreachable") || seen[toleration.Key] || toleration.Operator != corev1.TolerationOpExists || toleration.Effect != corev1.TaintEffectNoExecute || toleration.Value != "" || toleration.TolerationSeconds == nil || *toleration.TolerationSeconds != 300 {
			return false
		}
		seen[toleration.Key] = true
	}
	actual.NodeName = ""
	actual.EnableServiceLinks = nil
	actual.Priority = nil
	actual.PreemptionPolicy = nil
	actual.Tolerations = nil
	if len(actual.Volumes) != len(want.Volumes)+1 || len(actual.Containers) != 1 || len(actual.Containers[0].VolumeMounts) != len(want.Containers[0].VolumeMounts)+1 {
		return false
	}
	v := actual.Volumes[len(actual.Volumes)-1]
	if !generatedServingName(v.Name, "kube-api-access-") {
		return false
	}
	projection := corev1.Volume{Name: v.Name, VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{DefaultMode: ptr.To[int32](0644), Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: ptr.To[int64](3607)}}, {ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}, Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}}}, {DownwardAPI: &corev1.DownwardAPIProjection{Items: []corev1.DownwardAPIVolumeFile{{Path: "namespace", FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"}}}}}}}}}
	mount := corev1.VolumeMount{Name: v.Name, MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true}
	if !apiequality.Semantic.DeepEqual(v, projection) || !apiequality.Semantic.DeepEqual(actual.Containers[0].VolumeMounts[len(actual.Containers[0].VolumeMounts)-1], mount) {
		return false
	}
	actual.Volumes = actual.Volumes[:len(actual.Volumes)-1]
	actual.Containers[0].VolumeMounts = actual.Containers[0].VolumeMounts[:len(actual.Containers[0].VolumeMounts)-1]
	return apiequality.Semantic.DeepEqual(want, actual)
}

func generatedServingName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+5 {
		return false
	}
	for _, c := range name[len(prefix):] {
		if !strings.ContainsRune("bcdfghjklmnpqrstvwxz2456789", c) {
			return false
		}
	}
	return true
}
