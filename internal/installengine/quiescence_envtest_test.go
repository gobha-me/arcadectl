//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Native isolated API servers certify original zero-state Deployment/RS and
// empty placeholder EndpointSlice read shapes for both exact declared profiles.
// Status and the in-flight fixture inventory are seeded by the test admin: no
// controller-manager/kubelet, binary shutdown, CSI or full lifecycle is claimed.
func TestEnvtestQuiescenceDeclaredProfiles(t *testing.T) {
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			plan := fixturePlanProfile(t, "isolated-install", profile)
			environment := &envtest.Environment{UseExistingCluster: new(bool), DownloadBinaryAssets: true, DownloadBinaryAssetsVersion: plan.Profile().KubernetesVersion, DownloadBinaryAssetsIndexURL: "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml", BinaryAssetsDirectory: t.TempDir(), ControlPlaneStartTimeout: 90 * time.Second, ControlPlaneStopTimeout: 30 * time.Second}
			if profile == installrender.Profile135 {
				prerequisite135Assets(t, environment)
			}
			if environment.ControlPlane.APIServer == nil {
				environment.ControlPlane.APIServer = &envtest.APIServer{}
			}
			environment.ControlPlane.APIServer.Configure().Set("disable-admission-plugins", "")
			config, err := environment.Start()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := environment.Stop(); err != nil {
					t.Error(err)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			access, err := NewHTTPAccess(config)
			if err != nil {
				t.Fatal(err)
			}
			kube, err := kubernetes.NewForConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			base := t.TempDir()
			if err := os.Chmod(base, 0700); err != nil {
				t.Fatal(err)
			}
			files, err := privatefs.Open(base, false)
			if err != nil {
				t.Fatal(err)
			}
			defer files.Close()
			store, err := installstate.New(access.Namespaces(), plan)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewWithAccess(access, store, files, plan)
			if err != nil {
				t.Fatal(err)
			}
			p, err := NewClusterPrerequisites(engine, access)
			if err != nil {
				t.Fatal(err)
			}
			q, err := NewClusterQuiescence(p)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := installstate.PrepareBootstrap(files, "bootstrap.json", plan)
			if err != nil {
				t.Fatal(err)
			}
			s, err := receipt.EnsureNamespace(ctx, access.Namespaces())
			if err != nil {
				t.Fatal(err)
			}
			s, err = store.Load(ctx, s.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			d := s.Document()
			d.Stage = installstate.Applying
			d.Revision++
			s, err = store.Commit(ctx, s, d)
			if err != nil {
				t.Fatal(err)
			}
			for _, resource := range plan.Resources() {
				if resource.Object.GetKind() == "CustomResourceDefinition" {
					s, err = engine.Apply(ctx, s, resourceKey(resource), plan.Digest(), false)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			crdRequest := LifecycleCheck{Checkpoint: CRDsAvailable, Snapshot: s, Mode: installstate.Install, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
			if err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) { return p.VerifyCRDs(ctx, crdRequest) == nil, nil }); err != nil {
				t.Fatal("original native CRD discovery", err)
			}
			now := time.Now().UTC()
			candidate, err := engine.PrepareCredentials(ctx, s, fixtureTLS(t, plan.Namespace(), now))
			if err != nil {
				t.Fatal(err)
			}
			workflow, err := NewSecretWorkflow(engine, access.PrivateSecrets())
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"arcadectl-admin-credential", "arcadectl-api-tls"} {
				s, err = workflow.Create(ctx, s, candidate, name, now)
				if err != nil {
					t.Fatal("native original Secret create", err)
				}
			}
			d = s.Document()
			parents := []*appsv1.Deployment{}
			var service *corev1.Service
			for _, resource := range plan.Resources() {
				key := resourceKey(resource)
				if !(key.Kind == "Service" || key.Kind == "ServiceAccount" && key.Name != apiFamily || key.Kind == "Deployment" && key.Name != apiFamily) {
					continue
				}
				template, err := engine.contracts[plan.Digest()].Template(key, key.Kind == "Deployment")
				if err != nil {
					t.Fatal(err)
				}
				candidate, err := template.Candidate(strings.Repeat("b", 32))
				if err != nil {
					t.Fatal(err)
				}
				live, err := access.Create(ctx, key, candidate, false)
				if err != nil || template.MatchLive(live, live.GetUID()) != nil {
					t.Fatal("native original fixture create", key, err)
				}
				if key.Kind == "Deployment" {
					parent := &appsv1.Deployment{}
					if decodeServing(live, parent) != nil {
						t.Fatal("native controller decode")
					}
					parent.Status = appsv1.DeploymentStatus{ObservedGeneration: parent.Generation}
					parent, err = kube.AppsV1().Deployments(plan.Namespace()).UpdateStatus(ctx, parent, metav1.UpdateOptions{})
					if err != nil {
						t.Fatal(err)
					}
					parents = append(parents, parent)
				}
				if key.Kind == "Service" {
					service = &corev1.Service{}
					if decodeServing(live, service) != nil {
						t.Fatal("native Service decode")
					}
				}
				d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: live.GetUID(), TemplateSHA256: template.Hash(), Retained: template.Retained(), Phase: template.Phase()})
			}
			if len(parents) != 2 || service == nil {
				t.Fatal("native quiescence fixture incomplete")
			}
			var first *appsv1.ReplicaSet
			for _, parent := range parents {
				rs := inertFixture(parent, "bcdfg23456", 1)
				rs.UID, rs.ResourceVersion, rs.Generation = "", "", 0
				rs.Status = appsv1.ReplicaSetStatus{}
				rs, err = kube.AppsV1().ReplicaSets(plan.Namespace()).Create(ctx, rs, metav1.CreateOptions{})
				if err != nil {
					t.Fatal("native inert RS create", err)
				}
				rs.Status.ObservedGeneration = rs.Generation
				rs, err = kube.AppsV1().ReplicaSets(plan.Namespace()).UpdateStatus(ctx, rs, metav1.UpdateOptions{})
				if err != nil || !inertReplicaSet(rs, parent) {
					t.Fatal("native inert history read", err)
				}
				if first == nil {
					first = rs
				}
			}
			labels := map[string]string{}
			for k, v := range service.Labels {
				labels[k] = v
			}
			labels[discoveryv1.LabelServiceName] = apiFamily
			labels[discoveryv1.LabelManagedBy] = "endpointslice-controller.k8s.io"
			addressType := discoveryv1.AddressTypeIPv4
			if service.Spec.IPFamilies[0] == corev1.IPv6Protocol {
				addressType = discoveryv1.AddressTypeIPv6
			}
			slice, err := kube.DiscoveryV1().EndpointSlices(plan.Namespace()).Create(ctx, &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{GenerateName: apiFamily + "-", Namespace: plan.Namespace(), Labels: labels, OwnerReferences: fixtureOwner("v1", "Service", service.Name, service.UID)}, AddressType: addressType, Endpoints: []discoveryv1.Endpoint{}, Ports: []discoveryv1.EndpointPort{}}, metav1.CreateOptions{})
			if err != nil || !validStoppedSlice(slice, service) {
				t.Fatal("native portless placeholder", err)
			}
			// Explicit fixture seeding, not a claim that Lifecycle performed these
			// transitions. The verifier subsequently uses only sealed live reads.
			d.Mode, d.Stage, d.Installed, d.ActivePackage = installstate.Uninstall, installstate.Quiescing, true, plan.Digest()
			d.Revision++
			installstate.SortResources(d.Resources)
			body, err := installstate.Encode(d, plan)
			if err != nil {
				t.Fatal(err)
			}
			ns, err := kube.CoreV1().Namespaces().Get(ctx, plan.Namespace(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			ns.Annotations[installstate.Annotation] = string(body)
			if _, err := kube.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			s, err = store.Load(ctx, s.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			request := LifecycleCheck{Checkpoint: RuntimeStopped, Snapshot: s, Mode: installstate.Uninstall, Target: plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
			if err := q.Verify(ctx, request); err != nil {
				t.Fatal("bound native stopped proof", err)
			}
			request.Checkpoint = APIStopped
			if err := q.Verify(ctx, request); err != nil {
				t.Fatal("bound native API stopped proof", err)
			}
			parent := parents[0]
			currentSet := inertFixture(parent, "bcdfg34567", 2)
			currentSet.Spec.Template = *parent.Spec.Template.DeepCopy()
			currentSet.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = "bcdfg34567"
			currentSet.Labels = currentSet.Spec.Template.Labels
			currentSet.Spec.Replicas = ptr.To[int32](1)
			currentSet.UID, currentSet.ResourceVersion, currentSet.Generation = "", "", 0
			currentSet.Status = appsv1.ReplicaSetStatus{}
			currentSet, err = kube.AppsV1().ReplicaSets(plan.Namespace()).Create(ctx, currentSet, metav1.CreateOptions{})
			if err != nil {
				t.Fatal("native current controller RS", err)
			}
			pod, err := kube.CoreV1().Pods(plan.Namespace()).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{GenerateName: currentSet.Name + "-", Namespace: plan.Namespace(), Labels: currentSet.Spec.Template.Labels, Annotations: currentSet.Spec.Template.Annotations, OwnerReferences: fixtureOwner("apps/v1", "ReplicaSet", currentSet.Name, currentSet.UID)}, Spec: *currentSet.Spec.Template.Spec.DeepCopy()}, metav1.CreateOptions{})
			if err != nil || pod.Spec.NodeName != "" || !validOriginalPodTemplate(pod, currentSet, false) || validServingPodTemplate(pod, currentSet) {
				t.Fatal("native Pending controller defaults", err)
			}
			if err := q.Verify(ctx, request); err != nil {
				t.Fatal("native API stop rejected original Pending controller", err)
			}
			request.Checkpoint = RuntimeStopped
			if q.Verify(ctx, request) != ErrQuiescence {
				t.Fatal("native runtime stop ignored Pending controller")
			}
			if err := kube.CoreV1().Pods(plan.Namespace()).Delete(ctx, pod.Name, metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0), Preconditions: &metav1.Preconditions{UID: &pod.UID}}); err != nil {
				t.Fatal(err)
			}
			if err := kube.AppsV1().ReplicaSets(plan.Namespace()).Delete(ctx, currentSet.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &currentSet.UID}}); err != nil {
				t.Fatal(err)
			}
			if err := q.Verify(ctx, request); err != nil {
				t.Fatal("native owned Pending fixture cleanup", err)
			}
			first.Spec.Replicas = ptr.To[int32](1)
			if _, err := kube.AppsV1().ReplicaSets(plan.Namespace()).Update(ctx, first, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			request.Checkpoint = RuntimeStopped
			if q.Verify(ctx, request) != ErrQuiescence {
				t.Fatal("native executable unknown-history RS accepted")
			}
		})
	}
}
