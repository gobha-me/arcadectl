// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

type fakeServing struct {
	pod   *corev1.Pod
	rs    *appsv1.ReplicaSet
	list  *discoveryv1.EndpointSliceList
	onPod func()
}

func servingObject(t *testing.T, o runtime.Object) *unstructured.Unstructured {
	t.Helper()
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(o)
	if err != nil {
		t.Fatal(err)
	}
	return &unstructured.Unstructured{Object: raw}
}
func (a *fakeServing) GetPod(_ context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	if a.onPod != nil {
		a.onPod()
	}
	if namespace != a.pod.Namespace || name != a.pod.Name {
		return nil, ErrRead
	}
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(a.pod.DeepCopy())
	return &unstructured.Unstructured{Object: raw}, err
}
func (a *fakeServing) GetReplicaSet(_ context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	if namespace != a.rs.Namespace || name != a.rs.Name {
		return nil, ErrRead
	}
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(a.rs.DeepCopy())
	return &unstructured.Unstructured{Object: raw}, err
}
func (a *fakeServing) ListEndpointSlices(context.Context, string) (*discoveryv1.EndpointSliceList, error) {
	return a.list.DeepCopy(), nil
}

type servingFixture struct {
	f          *fixture
	access     *fakeServing
	secrets    *fakePrivateSecrets
	deployment *appsv1.Deployment
	service    *corev1.Service
	activation *Activation
	options    ActivationOptions
	tls        CredentialOptions
	issuer     *x509.Certificate
	issuerKey  *ecdsa.PrivateKey
}

func fixtureOwner(version, kind, name string, uid types.UID) []metav1.OwnerReference {
	return []metav1.OwnerReference{{APIVersion: version, Kind: kind, Name: name, UID: uid, Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true)}}
}

func fixtureTokenVolume(name string) corev1.Volume {
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{DefaultMode: ptr.To[int32](0644), Sources: []corev1.VolumeProjection{
		{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: ptr.To[int64](3607)}},
		{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}, Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}}},
		{DownwardAPI: &corev1.DownwardAPIProjection{Items: []corev1.DownwardAPIVolumeFile{{Path: "namespace", FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"}}}}},
	}}}}
}

func newServingFixture(t *testing.T) *servingFixture {
	t.Helper()
	f := newFixture(t, false)
	now := time.Now().UTC()
	opts, issuer, issuerKey := fixtureTLSWithIssuer(t, f.plan.Namespace(), now)
	c, err := f.engine.PrepareCredentials(context.Background(), f.snapshot, opts)
	if err != nil {
		t.Fatal(err)
	}
	private := &fakePrivateSecrets{f: f, objects: map[string]*corev1.Secret{}}
	w, err := NewSecretWorkflow(f.engine, private)
	if err != nil {
		t.Fatal(err)
	}
	s := f.snapshot
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		s, err = w.Create(context.Background(), s, c, name, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	doc := s.Document()
	var deployment *appsv1.Deployment
	var service *corev1.Service
	for _, resource := range f.plan.Resources() {
		o := resource.Object
		if o.GetKind() == "Namespace" {
			continue
		}
		key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
		template, err := f.engine.contracts[f.plan.Digest()].Template(key, false)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := template.Candidate(strings.Repeat("b", 32))
		if err != nil {
			t.Fatal(err)
		}
		candidate.SetUID(types.UID("original-" + key.Kind + "-" + key.Name))
		candidate.SetResourceVersion("10")
		if key.Kind == "Deployment" && key.Name == "arcadectl-api" {
			deployment = &appsv1.Deployment{}
			if decodeServing(candidate, deployment) != nil {
				t.Fatal("deployment fixture")
			}
			podTemplate, err := template.PodTemplate()
			if err != nil {
				t.Fatal(err)
			}
			deployment.Spec.Template = *podTemplate
			deployment.Spec.RevisionHistoryLimit = ptr.To[int32](10)
			deployment.Spec.ProgressDeadlineSeconds = ptr.To[int32](600)
			deployment.Generation = 1
			deployment.Annotations["deployment.kubernetes.io/revision"] = "1"
			deployment.Status = appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
			candidate = servingObject(t, deployment)
		}
		if key.Kind == "Service" {
			service = &corev1.Service{}
			if decodeServing(candidate, service) != nil {
				t.Fatal("service fixture")
			}
			service.Spec.SessionAffinity = corev1.ServiceAffinityNone
			service.Spec.InternalTrafficPolicy = ptr.To(corev1.ServiceInternalTrafficPolicyCluster)
			service.Spec.IPFamilyPolicy = ptr.To(corev1.IPFamilyPolicySingleStack)
			service.Spec.ClusterIP = "10.96.0.10"
			service.Spec.ClusterIPs = []string{"10.96.0.10"}
			service.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv4Protocol}
			candidate = servingObject(t, service)
		}
		f.access.objects[key] = candidate
		doc.Resources = append(doc.Resources, installstate.Resource{Key: key, UID: candidate.GetUID(), TemplateSHA256: template.Hash(), Retained: resource.Retained, Phase: resource.Phase})
	}
	// Build an already-applied trusted fixture. This is not an effect/lifecycle
	// proof; actual engine Creates are covered separately against a real API.
	doc.Stage = installstate.Verifying
	doc.Revision++
	installstate.SortResources(doc.Resources)
	body, err := installstate.Encode(doc, f.plan)
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.access.client.CoreV1().Namespaces().Get(context.Background(), doc.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	n.Annotations[installstate.Annotation] = string(body)
	if _, err := f.access.client.CoreV1().Namespaces().Update(context.Background(), n, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.Load(context.Background(), s.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Resources) != 40 || deployment == nil || service == nil {
		t.Fatal("complete fixture missing")
	}
	hash := "bcdfg23456"
	rsName := deployment.Name + "-" + hash
	labels := map[string]string{}
	for key, value := range deployment.Spec.Template.Labels {
		labels[key] = value
	}
	labels[appsv1.DefaultDeploymentUniqueLabelKey] = hash
	template := deployment.Spec.Template.DeepCopy()
	template.Labels = labels
	selector := deployment.Spec.Selector.DeepCopy()
	selector.MatchLabels[appsv1.DefaultDeploymentUniqueLabelKey] = hash
	rs := &appsv1.ReplicaSet{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "ReplicaSet"}, ObjectMeta: metav1.ObjectMeta{Name: rsName, Namespace: doc.Namespace, UID: "original-rs", ResourceVersion: "10", Generation: 1, Labels: labels, Annotations: map[string]string{installstate.MutationAnnotation: strings.Repeat("b", 32), "deployment.kubernetes.io/revision": "1", "deployment.kubernetes.io/desired-replicas": "1", "deployment.kubernetes.io/max-replicas": "1"}, OwnerReferences: fixtureOwner("apps/v1", "Deployment", deployment.Name, deployment.UID)}, Spec: appsv1.ReplicaSetSpec{Replicas: ptr.To[int32](1), Selector: selector, Template: *template}, Status: appsv1.ReplicaSetStatus{ObservedGeneration: 1, Replicas: 1, FullyLabeledReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}}
	pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{Name: rsName + "-bcdfg", GenerateName: rsName + "-", Namespace: doc.Namespace, UID: "original-pod", ResourceVersion: "10", Labels: labels, OwnerReferences: fixtureOwner("apps/v1", "ReplicaSet", rs.Name, rs.UID)}, Spec: *template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.0.10", PodIPs: []corev1.PodIP{{IP: "10.244.0.10"}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "api", Ready: true, Started: ptr.To(true), State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}, {Type: corev1.ContainersReady, Status: corev1.ConditionTrue}, {Type: corev1.PodScheduled, Status: corev1.ConditionTrue}, {Type: corev1.PodInitialized, Status: corev1.ConditionTrue}}}}
	pod.Spec.NodeName = "node1"
	pod.Spec.EnableServiceLinks = ptr.To(true)
	pod.Spec.DeprecatedServiceAccount = pod.Spec.ServiceAccountName
	pod.Spec.Priority = ptr.To[int32](0)
	pod.Spec.PreemptionPolicy = ptr.To(corev1.PreemptLowerPriority)
	pod.Spec.Tolerations = []corev1.Toleration{{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: ptr.To[int64](300)}, {Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: ptr.To[int64](300)}}
	pod.Spec.Volumes = append(pod.Spec.Volumes, fixtureTokenVolume("kube-api-access-bcdfg"))
	pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "kube-api-access-bcdfg", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true})
	sliceLabels := map[string]string{}
	for k, v := range service.Labels {
		sliceLabels[k] = v
	}
	sliceLabels[discoveryv1.LabelServiceName] = service.Name
	sliceLabels[discoveryv1.LabelManagedBy] = "endpointslice-controller.k8s.io"
	list := &discoveryv1.EndpointSliceList{TypeMeta: metav1.TypeMeta{APIVersion: "discovery.k8s.io/v1", Kind: "EndpointSliceList"}, ListMeta: metav1.ListMeta{ResourceVersion: "100"}, Items: []discoveryv1.EndpointSlice{{ObjectMeta: metav1.ObjectMeta{Name: service.Name + "-bcdfg", GenerateName: service.Name + "-", Namespace: doc.Namespace, UID: "original-slice", ResourceVersion: "10", Labels: sliceLabels, OwnerReferences: fixtureOwner("v1", "Service", service.Name, service.UID)}, AddressType: discoveryv1.AddressTypeIPv4, Ports: []discoveryv1.EndpointPort{{Name: ptr.To("https"), Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To[int32](8443)}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{pod.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true), Serving: ptr.To(true), Terminating: ptr.To(false)}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: doc.Namespace, Name: pod.Name, UID: pod.UID}, NodeName: ptr.To("node1"), Zone: ptr.To("az-1")}}}}}
	access := &fakeServing{pod: pod, rs: rs, list: list}
	a, err := NewActivation(f.engine, access, private)
	if err != nil {
		t.Fatal(err)
	}
	clientFile := filepath.Join(filepath.Dir(opts.KeyFile), "client.json")
	if err := os.WriteFile(clientFile, c.admin.PrivateBytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return &servingFixture{f: f, access: access, secrets: private, deployment: deployment, service: service, activation: a, options: ActivationOptions{CredentialFile: clientFile, CAFile: opts.CAFile}, tls: opts, issuer: issuer, issuerKey: issuerKey}
}

func TestServingObservationPinsWholeOriginalRoute(t *testing.T) {
	x := newServingFixture(t)
	before, err := x.f.engine.ObserveServing(context.Background(), x.f.snapshot, x.access)
	if err != nil || before.podUID != x.access.pod.UID || before.address != x.access.pod.Status.PodIP {
		t.Fatal("serving route unproved", err)
	}
	after, err := x.f.engine.ObserveServing(context.Background(), x.f.snapshot, x.access)
	if err != nil || after.fingerprint != before.fingerprint {
		t.Fatal("stable route changed", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%q", "%d"} {
		if fmt.Sprintf(format, *before) != "installation serving evidence" {
			t.Fatal("serving diagnostics expose route")
		}
	}
}

func TestServingObservationRefusesIdentityReadinessAndUnsignedShape(t *testing.T) {
	cases := map[string]func(*servingFixture){
		"pod-generated-suffix": func(x *servingFixture) {
			x.access.pod.Name = x.access.pod.GenerateName + "12345"
			x.access.list.Items[0].Endpoints[0].TargetRef.Name = x.access.pod.Name
		},
		"token-generated-suffix": func(x *servingFixture) {
			p := x.access.pod
			p.Spec.Volumes[len(p.Spec.Volumes)-1].Name = "kube-api-access-12345"
			p.Spec.Containers[0].VolumeMounts[len(p.Spec.Containers[0].VolumeMounts)-1].Name = "kube-api-access-12345"
		},
		"service-uid": func(x *servingFixture) {
			x.service.UID = "foreign"
			x.f.access.objects[installstate.Key{APIVersion: "v1", Kind: "Service", Namespace: x.service.Namespace, Name: x.service.Name}] = servingObject(t, x.service)
		},
		"deployment-stale": func(x *servingFixture) {
			x.deployment.Status.ObservedGeneration = 0
			x.f.access.objects[installstate.Key{APIVersion: "apps/v1", Kind: "Deployment", Namespace: x.deployment.Namespace, Name: x.deployment.Name}] = servingObject(t, x.deployment)
		},
		"slice-owner":  func(x *servingFixture) { x.access.list.Items[0].OwnerReferences[0].UID = "foreign" },
		"slice-label":  func(x *servingFixture) { x.access.list.Items[0].Labels["foreign"] = "unsigned" },
		"slice-port":   func(x *servingFixture) { x.access.list.Items[0].Ports[0].Port = ptr.To[int32](443) },
		"slice-family": func(x *servingFixture) { x.access.list.Items[0].AddressType = discoveryv1.AddressTypeIPv6 },
		"slice-duplicate": func(x *servingFixture) {
			s := *x.access.list.Items[0].DeepCopy()
			s.Name += "-second"
			s.UID = "second-slice"
			x.access.list.Items = append(x.access.list.Items, s)
		},
		"slice-partial":          func(x *servingFixture) { x.access.list.Continue = "incomplete" },
		"endpoint-unready":       func(x *servingFixture) { x.access.list.Items[0].Endpoints[0].Conditions.Ready = ptr.To(false) },
		"endpoint-unknown-ready": func(x *servingFixture) { x.access.list.Items[0].Endpoints[0].Conditions.Ready = nil },
		"endpoint-terminating":   func(x *servingFixture) { x.access.list.Items[0].Endpoints[0].Conditions.Terminating = ptr.To(true) },
		"endpoint-node":          func(x *servingFixture) { x.access.list.Items[0].Endpoints[0].NodeName = ptr.To("foreign-node") },
		"endpoint-loopback": func(x *servingFixture) {
			x.access.list.Items[0].Endpoints[0].Addresses = []string{"127.0.0.1"}
			x.access.pod.Status.PodIP = "127.0.0.1"
		},
		"pod-uid":   func(x *servingFixture) { x.access.pod.UID = "foreign" },
		"pod-owner": func(x *servingFixture) { x.access.pod.OwnerReferences[0].UID = "foreign" },
		"pod-extra-owner": func(x *servingFixture) {
			x.access.pod.OwnerReferences = append(x.access.pod.OwnerReferences, x.access.pod.OwnerReferences[0])
		},
		"pod-not-ready": func(x *servingFixture) { x.access.pod.Status.Conditions[0].Status = corev1.ConditionFalse },
		"pod-sidecar": func(x *servingFixture) {
			x.access.pod.Spec.Containers = append(x.access.pod.Spec.Containers, corev1.Container{Name: "foreign"})
		},
		"pod-image": func(x *servingFixture) { x.access.pod.Spec.Containers[0].Image = "foreign:latest" },
		"pod-inline-env": func(x *servingFixture) {
			x.access.pod.Spec.Containers[0].Env = append(x.access.pod.Spec.Containers[0].Env, corev1.EnvVar{Name: "CANARY", Value: "PRIVATE-CANARY"})
		},
		"pod-sa-alias":   func(x *servingFixture) { x.access.pod.Spec.DeprecatedServiceAccount = "foreign" },
		"pod-automount":  func(x *servingFixture) { x.access.pod.Spec.AutomountServiceAccountToken = ptr.To(false) },
		"pod-annotation": func(x *servingFixture) { x.access.pod.Annotations = map[string]string{"foreign": "PRIVATE-CANARY"} },
		"token-audience": func(x *servingFixture) {
			x.access.pod.Spec.Volumes[2].Projected.Sources[0].ServiceAccountToken.Audience = "foreign"
		},
		"token-expiry": func(x *servingFixture) {
			x.access.pod.Spec.Volumes[2].Projected.Sources[0].ServiceAccountToken.ExpirationSeconds = ptr.To[int64](7200)
		},
		"token-ca":       func(x *servingFixture) { x.access.pod.Spec.Volumes[2].Projected.Sources[1].ConfigMap.Name = "foreign" },
		"token-mount":    func(x *servingFixture) { x.access.pod.Spec.Containers[0].VolumeMounts[2].ReadOnly = false },
		"token-subpath":  func(x *servingFixture) { x.access.pod.Spec.Containers[0].VolumeMounts[2].SubPath = "foreign" },
		"pod-toleration": func(x *servingFixture) { x.access.pod.Spec.Tolerations[0].TolerationSeconds = ptr.To[int64](301) },
		"rs-owner":       func(x *servingFixture) { x.access.rs.OwnerReferences[0].UID = "foreign" },
		"rs-image":       func(x *servingFixture) { x.access.rs.Spec.Template.Spec.Containers[0].Image = "foreign:latest" },
		"rs-revision":    func(x *servingFixture) { x.access.rs.Annotations["deployment.kubernetes.io/revision"] = "2" },
		"rs-incomplete":  func(x *servingFixture) { x.access.rs.Status.ReadyReplicas = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			x := newServingFixture(t)
			mutate(x)
			if _, err := x.f.engine.ObserveServing(context.Background(), x.f.snapshot, x.access); !errors.Is(err, ErrServing) || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("unsigned or unsafe serving evidence accepted", err)
			}
		})
	}
}
