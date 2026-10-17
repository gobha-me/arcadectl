// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package admincredential

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

const customNamespace = "isolated-install"

func customReadyCluster(secret *corev1.Secret) *fakeCluster {
	cluster := readyCluster(secret)
	cluster.deployment.Namespace = customNamespace
	cluster.slices.Items[0].Namespace = customNamespace
	cluster.slices.Items[0].Endpoints[0].TargetRef.Namespace = customNamespace
	return cluster
}

func TestExplicitNamespaceInitializeAndRotate(t *testing.T) {
	now := time.Now().UTC()
	cluster := &fakeCluster{}
	workflow, err := NewWithAccess(cluster, Config{Namespace: customNamespace})
	if err != nil || workflow.Namespace() != customNamespace {
		t.Fatal("custom workflow unavailable")
	}
	path := filepath.Join(privateTestDirectory(t), "initial.json")
	if err := workflow.Initialize(context.Background(), InitializeOptions{OutputPath: path, Now: now, Lifetime: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if cluster.secret.Namespace != customNamespace || !reflect.DeepEqual(cluster.secret.Labels, adminauth.ManagedSecretLabels()) {
		t.Fatal("credential scope or legacy-compatible labels changed")
	}
	oldToken := string(cluster.secret.Data[adminauth.TokenSecretKey])
	cluster = customReadyCluster(cluster.secret)
	workflow, err = NewWithAccess(cluster, Config{Namespace: customNamespace})
	if err != nil {
		t.Fatal(err)
	}
	if err := workflow.Rotate(boundedTestContext(t), &fakeProbe{wantOld: oldToken}, RotateOptions{OutputPath: filepath.Join(privateTestDirectory(t), "rotated.json"), Now: now, Lifetime: time.Hour, PollInterval: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if cluster.secret.Namespace != customNamespace || cluster.secret.UID != "secret-uid" || cluster.updateCalls != 1 || !reflect.DeepEqual(cluster.secret.Labels, adminauth.ManagedSecretLabels()) {
		t.Fatal("rotation did not retain namespace, UID, labels and single CAS")
	}
}

func TestClientGoAccessTargetsOnlyConfiguredNamespace(t *testing.T) {
	now := time.Now().UTC()
	client := fake.NewClientset()
	client.PrependReactor("*", "*", func(action clienttesting.Action) (bool, runtime.Object, error) {
		if action.GetNamespace() != customNamespace {
			t.Fatalf("typed client targeted namespace %q", action.GetNamespace())
		}
		switch action := action.(type) {
		case clienttesting.CreateAction:
			secret := action.GetObject().(*corev1.Secret)
			if secret.Namespace != customNamespace {
				t.Fatal("create body namespace differs")
			}
			secret.UID, secret.ResourceVersion = "typed-secret", "1"
		case clienttesting.UpdateAction:
			secret := action.GetObject().(*corev1.Secret)
			if secret.Namespace != customNamespace || secret.UID != "typed-secret" || secret.ResourceVersion != "1" {
				t.Fatal("update lacks exact namespace/UID/RV")
			}
			secret.ResourceVersion = "2"
		}
		return false, nil, nil
	})
	workflow, err := New(client, Config{Namespace: customNamespace})
	if err != nil {
		t.Fatal(err)
	}
	if err := workflow.Initialize(context.Background(), InitializeOptions{OutputPath: filepath.Join(privateTestDirectory(t), "initial.json"), Now: now, Lifetime: time.Hour}); err != nil {
		t.Fatal(err)
	}
	secret, err := client.CoreV1().Secrets(customNamespace).Get(context.Background(), adminauth.CredentialSecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	topology := customReadyCluster(secret)
	if err := client.Tracker().Add(topology.deployment); err != nil {
		t.Fatal(err)
	}
	if err := client.Tracker().Add(&topology.slices.Items[0]); err != nil {
		t.Fatal(err)
	}
	if err := workflow.Rotate(boundedTestContext(t), &fakeProbe{wantOld: string(secret.Data[adminauth.TokenSecretKey])}, RotateOptions{OutputPath: filepath.Join(privateTestDirectory(t), "rotated.json"), Now: now, Lifetime: time.Hour, PollInterval: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	var updates int
	for _, action := range client.Actions() {
		if action.GetNamespace() != customNamespace {
			t.Fatal("action escaped configured namespace")
		}
		if action.GetVerb() == "update" {
			updates++
		}
	}
	if updates != 1 {
		t.Fatal("rotation did not make exactly one update")
	}
}

func TestNamespaceAndMetadataMismatchRefusedBeforeRotationEffects(t *testing.T) {
	now := time.Now().UTC()
	old, _ := adminauth.GenerateCredential(now, time.Hour)
	secret, _ := secretForCredential(old, customNamespace)
	secret.UID, secret.ResourceVersion = "uid", "1"
	cases := []struct {
		name   string
		mutate func(*fakeCluster)
		want   error
	}{
		{"Secret namespace", func(c *fakeCluster) { c.secret.Namespace = "foreign" }, ErrInvalidManagedSecret},
		{"Deployment namespace", func(c *fakeCluster) { c.deployment.Namespace = "foreign" }, ErrTopologyUnavailable},
		{"Deployment name", func(c *fakeCluster) { c.deployment.Name = "foreign" }, ErrTopologyUnavailable},
		{"Deployment deleting", func(c *fakeCluster) { c.deployment.DeletionTimestamp = &metav1.Time{Time: now} }, ErrTopologyUnavailable},
		{"slice namespace", func(c *fakeCluster) { c.slices.Items[0].Namespace = "foreign" }, ErrTopologyUnavailable},
		{"slice service", func(c *fakeCluster) { c.slices.Items[0].Labels[discoveryv1.LabelServiceName] = "foreign" }, ErrTopologyUnavailable},
		{"slice deleting", func(c *fakeCluster) { c.slices.Items[0].DeletionTimestamp = &metav1.Time{Time: now} }, ErrTopologyUnavailable},
		{"target namespace", func(c *fakeCluster) { c.slices.Items[0].Endpoints[0].TargetRef.Namespace = "foreign" }, ErrTopologyUnavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cluster := customReadyCluster(secret)
			test.mutate(cluster)
			workflow, err := NewWithAccess(cluster, Config{Namespace: customNamespace})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(privateTestDirectory(t), "candidate.json")
			err = workflow.Rotate(boundedTestContext(t), &fakeProbe{wantOld: old.Token}, RotateOptions{OutputPath: path, Now: now, Lifetime: time.Hour, PollInterval: time.Millisecond})
			if !errors.Is(err, test.want) || cluster.updateCalls != 0 {
				t.Fatalf("rotation mismatch was not refused before mutation: %v", err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("output exists after refused metadata")
			}
		})
	}
}

func TestInvalidConfigurationAndProbeScopeHaveNoEffects(t *testing.T) {
	var typedNil *fakeCluster
	for _, namespace := range []string{"", "UPPER", "bad/name", "a.b", "-leading"} {
		if _, err := NewWithAccess(&fakeCluster{}, Config{Namespace: namespace}); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatal("invalid namespace accepted")
		}
		if _, err := NewHTTPSProbe(ProbeOptions{Namespace: namespace}); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatal("invalid probe namespace accepted")
		}
	}
	if _, err := NewWithAccess(typedNil, Config{Namespace: customNamespace}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("typed nil access accepted")
	}
	if _, err := New(nil, Config{Namespace: customNamespace}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("nil client accepted")
	}
	var nilClient *fake.Clientset
	if _, err := New(nilClient, Config{Namespace: customNamespace}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("typed nil client accepted")
	}
	var workflow Workflow
	if err := workflow.Initialize(context.Background(), InitializeOptions{}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("zero workflow accepted")
	}
	path := filepath.Join(privateTestDirectory(t), "candidate.json")
	configured, _ := NewWithAccess(&fakeCluster{}, Config{Namespace: customNamespace})
	var nilProbe *fakeProbe
	if err := configured.Rotate(context.Background(), nilProbe, RotateOptions{OutputPath: path, PollInterval: time.Millisecond}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("typed nil probe accepted")
	}
	if err := configured.Rotate(context.Background(), &HTTPSProbe{namespace: "foreign"}, RotateOptions{OutputPath: path, PollInterval: time.Millisecond}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("foreign scoped probe accepted")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid configuration created output")
	}
}

func TestCustomNamespaceAmbiguousWritesRetainExactCandidate(t *testing.T) {
	now := time.Now().UTC()
	for _, committed := range []bool{false, true} {
		for _, rotate := range []bool{false, true} {
			name := "initialize-unconfirmed"
			if rotate {
				name = "rotate-unconfirmed"
			}
			if committed {
				name += "-committed"
			}
			t.Run(name, func(t *testing.T) {
				cluster := &fakeCluster{createErr: errors.New("lost response"), commitOnCreateError: committed}
				var oldToken string
				if rotate {
					old, err := adminauth.GenerateCredential(now, time.Hour)
					if err != nil {
						t.Fatal(err)
					}
					secret, err := secretForCredential(old, customNamespace)
					if err != nil {
						t.Fatal(err)
					}
					secret.UID, secret.ResourceVersion = "secret-uid", "1"
					cluster = customReadyCluster(secret)
					cluster.updateErr, cluster.commitOnUpdateError = errors.New("lost response"), committed
					oldToken = old.Token
				}
				workflow, err := NewWithAccess(cluster, Config{Namespace: customNamespace})
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(privateTestDirectory(t), "candidate.json")
				if rotate {
					err = workflow.Rotate(boundedTestContext(t), &fakeProbe{wantOld: oldToken}, RotateOptions{OutputPath: path, Now: now, Lifetime: time.Hour, PollInterval: time.Millisecond})
				} else {
					err = workflow.Initialize(context.Background(), InitializeOptions{OutputPath: path, Now: now, Lifetime: time.Hour})
				}
				if committed && err != nil || !committed && !errors.Is(err, ErrMutationUnconfirmed) {
					t.Fatalf("ambiguous mutation outcome: committed=%t error=%v", committed, err)
				}
				body, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatal("ambiguous mutation lost private candidate")
				}
				candidate, parseErr := adminauth.ParseClientCredential(body)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				if rotate && cluster.updateCalls != 1 {
					t.Fatal("ambiguous update retried")
				}
				if committed && (cluster.secret.Namespace != customNamespace || cluster.secret.UID != "secret-uid" || string(cluster.secret.Data[adminauth.TokenSecretKey]) != candidate.Token) {
					t.Fatal("readback failed to correlate exact candidate in configured namespace")
				}
			})
		}
	}
}

// Compile-time checks ensure the seam stays concrete enough for integration
// callers to retain typed object metadata rather than unstructured payloads.
var _ ClusterAccess = (*fakeCluster)(nil)
