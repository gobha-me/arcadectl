// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package admincredential

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
)

type fakeCluster struct {
	mu                  sync.Mutex
	secret              *corev1.Secret
	deployment          *appsv1.Deployment
	slices              *discoveryv1.EndpointSliceList
	createErr           error
	updateErr           error
	getErr              error
	updateCalls         int
	commitOnCreateError bool
	commitOnUpdateError bool
}

func (cluster *fakeCluster) GetSecret(context.Context) (*corev1.Secret, error) {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	if cluster.getErr != nil {
		return nil, cluster.getErr
	}
	if cluster.secret == nil {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, adminauth.CredentialSecretName)
	}
	return cluster.secret.DeepCopy(), nil
}

func (cluster *fakeCluster) CreateSecret(_ context.Context, secret *corev1.Secret) (*corev1.Secret, error) {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	if cluster.secret != nil {
		return nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, adminauth.CredentialSecretName)
	}
	created := secret.DeepCopy()
	created.UID = "secret-uid"
	created.ResourceVersion = "1"
	if cluster.createErr != nil {
		if cluster.commitOnCreateError {
			cluster.secret = created
		}
		return nil, cluster.createErr
	}
	cluster.secret = created
	return created.DeepCopy(), nil
}

func (cluster *fakeCluster) UpdateSecret(_ context.Context, secret *corev1.Secret) (*corev1.Secret, error) {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	cluster.updateCalls++
	if cluster.secret == nil || secret.UID != cluster.secret.UID || secret.ResourceVersion != cluster.secret.ResourceVersion {
		return nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, adminauth.CredentialSecretName, errors.New("revision changed"))
	}
	updated := secret.DeepCopy()
	updated.ResourceVersion = "2"
	if cluster.updateErr != nil {
		if cluster.commitOnUpdateError {
			cluster.secret = updated
		}
		return nil, cluster.updateErr
	}
	cluster.secret = updated
	return updated.DeepCopy(), nil
}

type concurrentCluster struct {
	*fakeCluster
	firstGets atomic.Int32
	release   chan struct{}
}

func (cluster *concurrentCluster) GetSecret(ctx context.Context) (*corev1.Secret, error) {
	call := cluster.firstGets.Add(1)
	if call <= 2 {
		secret, err := cluster.fakeCluster.GetSecret(ctx)
		if call == 2 {
			close(cluster.release)
		}
		select {
		case <-cluster.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return secret, err
	}
	return cluster.fakeCluster.GetSecret(ctx)
}

func (cluster *fakeCluster) GetDeployment(context.Context) (*appsv1.Deployment, error) {
	if cluster.deployment == nil {
		return nil, errors.New("unavailable")
	}
	return cluster.deployment.DeepCopy(), nil
}

func (cluster *fakeCluster) ListEndpointSlices(context.Context) (*discoveryv1.EndpointSliceList, error) {
	if cluster.slices == nil {
		return nil, errors.New("unavailable")
	}
	return cluster.slices.DeepCopy(), nil
}

type fakeProbe struct {
	wantOld  string
	called   int
	failures int
	err      error
	after    func()
}

func (probe *fakeProbe) Verify(_ context.Context, credential adminauth.ClientCredential, oldToken string) error {
	probe.called++
	if oldToken != probe.wantOld || credential.Token == "" || credential.Token == oldToken {
		return ErrActivationIncomplete
	}
	if probe.called <= probe.failures {
		return ErrActivationIncomplete
	}
	if probe.after != nil {
		probe.after()
	}
	return probe.err
}

func TestPrivateFileExclusiveAndTrustedParent(t *testing.T) {
	directory := privateTestDirectory(t)
	path := filepath.Join(directory, "credential.json")
	if err := writePrivateFile(path, []byte("private")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private file mode = %v, %v", info.Mode(), err)
	}
	if err := writePrivateFile(path, []byte("replacement")); !errors.Is(err, ErrPrivateOutput) {
		t.Fatalf("replacement error = %v", err)
	}
	contents, _ := os.ReadFile(path)
	if string(contents) != "private" {
		t.Fatal("O_EXCL output was overwritten")
	}
	unsafeParent := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(unsafeParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(filepath.Join(unsafeParent, "credential"), []byte("private")); !errors.Is(err, ErrPrivateOutput) {
		t.Fatalf("unsafe parent error = %v", err)
	}
}

func TestInitializeCredentialConfirmsAmbiguousCommitAndRetainsUnknown(t *testing.T) {
	now := time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)
	committed := &fakeCluster{createErr: errors.New("transport failed"), commitOnCreateError: true}
	path := filepath.Join(privateTestDirectory(t), "credential.json")
	if err := testInitializeCredential(context.Background(), committed, path, now, time.Hour); err != nil {
		t.Fatalf("confirmed ambiguous create = %v", err)
	}
	privateContents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	private, err := adminauth.ParseClientCredential(privateContents)
	if err != nil || private.Token == "" || private.PriorSecretUID != "" {
		t.Fatalf("private credential = %#v, %v", private, err)
	}

	unknown := &fakeCluster{createErr: errors.New("transport failed")}
	unknownPath := filepath.Join(privateTestDirectory(t), "credential.json")
	if err := testInitializeCredential(context.Background(), unknown, unknownPath, now, time.Hour); !errors.Is(err, ErrMutationUnconfirmed) {
		t.Fatalf("unknown create = %v", err)
	}
	if _, err := os.Stat(unknownPath); err != nil {
		t.Fatalf("ambiguous output removed: %v", err)
	}

	conflict := &fakeCluster{createErr: apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, adminauth.CredentialSecretName)}
	conflictPath := filepath.Join(privateTestDirectory(t), "credential.json")
	if err := testInitializeCredential(context.Background(), conflict, conflictPath, now, time.Hour); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("create conflict = %v", err)
	}
	if _, err := os.Stat(conflictPath); err != nil {
		t.Fatalf("definite-failure output was removed: %v", err)
	}
}

func TestConcurrentInitializationCreatesOnlyOneSecret(t *testing.T) {
	now := time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)
	cluster := &fakeCluster{}
	type result struct {
		err  error
		path string
	}
	results := make(chan result, 2)
	for range 2 {
		path := filepath.Join(privateTestDirectory(t), "credential.json")
		go func() {
			results <- result{err: testInitializeCredential(context.Background(), cluster, path, now, time.Hour), path: path}
		}()
	}
	var successes, conflicts int
	for range 2 {
		outcome := <-results
		switch {
		case outcome.err == nil:
			successes++
		case errors.Is(outcome.err, ErrCredentialConflict):
			conflicts++
			if _, err := os.Stat(outcome.path); err != nil {
				t.Fatalf("loser output was removed: %v", err)
			}
		default:
			t.Fatalf("unexpected init result: %v", outcome.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestRotateCredentialCASAllowsExpiredCurrentAndProbes(t *testing.T) {
	now := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	old, _ := adminauth.GenerateCredential(now.Add(-2*time.Hour), time.Hour)
	secret, _ := testSecretForCredential(old)
	secret.UID = "secret-uid"
	secret.ResourceVersion = "1"
	cluster := readyCluster(secret)
	probe := &fakeProbe{wantOld: old.Token}
	path := filepath.Join(privateTestDirectory(t), "credential.json")
	if err := testRotateCredential(boundedTestContext(t), cluster, probe, path, now, time.Hour, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if cluster.updateCalls != 1 || probe.called != 1 {
		t.Fatalf("updates=%d probes=%d", cluster.updateCalls, probe.called)
	}
	contents, _ := os.ReadFile(path)
	private, err := adminauth.ParseClientCredential(contents)
	if err != nil || private.Serial != 2 || private.PriorSecretUID != "secret-uid" || private.PriorResourceVersion != "1" {
		t.Fatalf("rotation file = %#v, %v", private, err)
	}
	bundle, token, err := testValidateManagedSecret(cluster.secret)
	if err != nil || bundle.Serial != 2 || token != private.Token || token == old.Token {
		t.Fatalf("rotated Secret = %#v token-match=%v err=%v", bundle, token == private.Token, err)
	}
}

func TestRotateCredentialNeverRetriesConflictOrDeletesAmbiguity(t *testing.T) {
	now := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	old, _ := adminauth.GenerateCredential(now, time.Hour)
	secret, _ := testSecretForCredential(old)
	secret.UID, secret.ResourceVersion = "secret-uid", "1"
	cluster := readyCluster(secret)
	cluster.updateErr = apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, adminauth.CredentialSecretName, errors.New("canary-secret-value"))
	path := filepath.Join(privateTestDirectory(t), "credential.json")
	if err := testRotateCredential(boundedTestContext(t), cluster, &fakeProbe{}, path, now, time.Hour, time.Millisecond); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("rotation conflict = %v", err)
	}
	if cluster.updateCalls != 1 {
		t.Fatalf("conflict update calls = %d", cluster.updateCalls)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("definite conflict file was removed: %v", err)
	}

	cluster = readyCluster(secret)
	cluster.updateErr = errors.New("canary-token-transport")
	path = filepath.Join(privateTestDirectory(t), "credential.json")
	if err := testRotateCredential(boundedTestContext(t), cluster, &fakeProbe{}, path, now, time.Hour, time.Millisecond); !errors.Is(err, ErrMutationUnconfirmed) {
		t.Fatalf("ambiguous rotation = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("ambiguous file removed: %v", err)
	}
}

func TestConcurrentRotationsUseOneCASWithoutLoserRetry(t *testing.T) {
	now := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	old, _ := adminauth.GenerateCredential(now, time.Hour)
	secret, _ := testSecretForCredential(old)
	secret.UID, secret.ResourceVersion = "secret-uid", "1"
	base := readyCluster(secret)
	cluster := &concurrentCluster{fakeCluster: base, release: make(chan struct{})}
	type result struct {
		err  error
		path string
	}
	results := make(chan result, 2)
	ctx := boundedTestContext(t)
	for range 2 {
		path := filepath.Join(privateTestDirectory(t), "credential.json")
		go func() {
			results <- result{err: testRotateCredential(ctx, cluster, &fakeProbe{wantOld: old.Token}, path, now, time.Hour, time.Millisecond), path: path}
		}()
	}
	var successes, conflicts int
	for range 2 {
		outcome := <-results
		switch {
		case outcome.err == nil:
			successes++
			if _, err := os.Stat(outcome.path); err != nil {
				t.Fatalf("winner credential missing: %v", err)
			}
		case errors.Is(outcome.err, ErrCredentialConflict):
			conflicts++
			if _, err := os.Stat(outcome.path); err != nil {
				t.Fatalf("loser credential was removed: %v", err)
			}
		default:
			t.Fatalf("unexpected concurrent outcome: %v", outcome.err)
		}
	}
	if successes != 1 || conflicts != 1 || base.updateCalls != 2 {
		t.Fatalf("successes=%d conflicts=%d updateCalls=%d", successes, conflicts, base.updateCalls)
	}
}

func TestRotationRequiresExactSingleServingEndpointBeforeOutput(t *testing.T) {
	now := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	old, _ := adminauth.GenerateCredential(now, time.Hour)
	secret, _ := testSecretForCredential(old)
	secret.UID, secret.ResourceVersion = "secret-uid", "1"
	cluster := readyCluster(secret)
	cluster.slices.Items[0].Endpoints = append(cluster.slices.Items[0].Endpoints,
		discoveryv1.Endpoint{Addresses: []string{"10.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)}})
	path := filepath.Join(privateTestDirectory(t), "credential.json")
	if err := testRotateCredential(boundedTestContext(t), cluster, &fakeProbe{}, path, now, time.Hour, time.Millisecond); !errors.Is(err, ErrTopologyUnavailable) {
		t.Fatalf("topology error = %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file created before topology preflight: %v", err)
	}
}

func TestActivationPollingWaitsForProjectionAndHonorsContext(t *testing.T) {
	now := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	old, _ := adminauth.GenerateCredential(now, time.Hour)
	secret, _ := testSecretForCredential(old)
	secret.UID, secret.ResourceVersion = "secret-uid", "1"
	cluster := readyCluster(secret)
	current, _ := adminauth.GenerateCredential(now, 2*time.Hour)
	current.Bundle.Serial = 2
	candidateSecret, _ := testSecretForCredential(current)
	candidateSecret.UID, candidateSecret.ResourceVersion = "secret-uid", "2"
	cluster.secret = candidateSecret
	private := adminauth.ClientCredential{
		Version: adminauth.ClientCredentialVersion, CredentialID: current.Bundle.CredentialID,
		Serial: 2, ExpiresAt: current.Bundle.ExpiresAt, Token: current.Token, PriorSecretUID: "secret-uid", PriorResourceVersion: "1",
	}
	probe := &fakeProbe{wantOld: old.Token, failures: 2}
	identity, err := testRequirePreMutationTopology(context.Background(), cluster)
	if err != nil {
		t.Fatal(err)
	}
	if err := testWaitForActivation(context.Background(), cluster, probe, private, current, old.Token, identity, time.Microsecond); err != nil || probe.called != 3 {
		t.Fatalf("poll result=%v calls=%d", err, probe.called)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	probe = &fakeProbe{wantOld: old.Token, err: ErrActivationIncomplete}
	if err := testWaitForActivation(ctx, cluster, probe, private, current, old.Token, identity, time.Millisecond); !errors.Is(err, ErrActivationIncomplete) {
		t.Fatalf("timeout result=%v", err)
	}
	if probe.called == 0 {
		t.Fatal("activation polling did not probe before waiting")
	}
}

func TestActivationRejectsCandidateOrEndpointSupersededDuringProbe(t *testing.T) {
	now := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		mutate func(*fakeCluster)
	}{
		{
			name: "next Secret candidate",
			mutate: func(cluster *fakeCluster) {
				next, _ := adminauth.GenerateCredential(now, 2*time.Hour)
				next.Bundle.Serial = 3
				nextSecret, _ := testSecretForCredential(next)
				nextSecret.UID, nextSecret.ResourceVersion = "secret-uid", "3"
				cluster.mu.Lock()
				cluster.secret = nextSecret
				cluster.mu.Unlock()
			},
		},
		{
			name: "replacement serving Pod",
			mutate: func(cluster *fakeCluster) {
				cluster.slices.Items[0].Endpoints[0].TargetRef.UID = "replacement-pod-uid"
			},
		},
		{
			name: "replacement endpoint address",
			mutate: func(cluster *fakeCluster) {
				cluster.slices.Items[0].Endpoints[0].Addresses[0] = "10.0.0.99"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			old, _ := adminauth.GenerateCredential(now, time.Hour)
			secret, _ := testSecretForCredential(old)
			secret.UID, secret.ResourceVersion = "secret-uid", "1"
			cluster := readyCluster(secret)
			var once sync.Once
			probe := &fakeProbe{wantOld: old.Token, after: func() { once.Do(func() { test.mutate(cluster) }) }}
			path := filepath.Join(privateTestDirectory(t), "credential.json")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			err := testRotateCredential(ctx, cluster, probe, path, now, time.Hour, time.Millisecond)
			if !errors.Is(err, ErrActivationIncomplete) || cluster.updateCalls != 1 || probe.called == 0 {
				t.Fatalf("rotation result=%v updates=%d probes=%d", err, cluster.updateCalls, probe.called)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("superseded candidate output was removed: %v", err)
			}
		})
	}
}

func TestExpiredCredentialTopologyAllowsRecoveryButNotActivation(t *testing.T) {
	credential, _ := adminauth.GenerateCredential(time.Now().UTC().Add(-2*time.Hour), time.Hour)
	secret, _ := testSecretForCredential(credential)
	secret.UID, secret.ResourceVersion = "secret-uid", "1"
	cluster := readyCluster(secret)
	cluster.deployment.Status.ReadyReplicas = 0
	cluster.deployment.Status.AvailableReplicas = 0
	cluster.deployment.Status.UnavailableReplicas = 1
	ready := false
	serving := false
	cluster.slices.Items[0].Endpoints[0].Conditions.Ready = &ready
	cluster.slices.Items[0].Endpoints[0].Conditions.Serving = &serving
	identity, err := testRequirePreMutationTopology(context.Background(), cluster)
	if err != nil || identity.uid != "api-pod-uid" || identity.address != "10.0.0.1" {
		t.Fatalf("expired pre-mutation topology = %#v, %v", identity, err)
	}
	if err := requireActivatedTopology(context.Background(), cluster, identity, adminauth.CredentialNamespace); !errors.Is(err, ErrTopologyUnavailable) {
		t.Fatalf("unready topology activated = %v", err)
	}
	cluster.deployment.Status.ReadyReplicas = 1
	cluster.deployment.Status.AvailableReplicas = 1
	cluster.deployment.Status.UnavailableReplicas = 0
	ready, serving = true, true
	if err := requireActivatedTopology(context.Background(), cluster, identity, adminauth.CredentialNamespace); err != nil {
		t.Fatalf("recovered topology = %v", err)
	}
	cluster.slices.Items[0].Endpoints[0].TargetRef.UID = "replacement-pod-uid"
	if err := requireActivatedTopology(context.Background(), cluster, identity, adminauth.CredentialNamespace); !errors.Is(err, ErrTopologyUnavailable) {
		t.Fatalf("replacement Pod activated = %v", err)
	}
}

func TestManagedSecretValidationIsExact(t *testing.T) {
	credential, _ := adminauth.GenerateCredential(time.Now().UTC(), time.Hour)
	secret, _ := testSecretForCredential(credential)
	secret.UID, secret.ResourceVersion = "uid", "1"
	if _, _, err := testValidateManagedSecret(secret); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*corev1.Secret){
		"type":  func(item *corev1.Secret) { item.Type = corev1.SecretTypeOpaque },
		"label": func(item *corev1.Secret) { item.Labels["extra"] = "value" },
		"key":   func(item *corev1.Secret) { item.Data["extra"] = []byte("value") },
		"token": func(item *corev1.Secret) { item.Data[adminauth.TokenSecretKey] = []byte("credential-canary") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := secret.DeepCopy()
			mutate(changed)
			if _, _, err := testValidateManagedSecret(changed); !errors.Is(err, ErrInvalidManagedSecret) {
				t.Fatalf("invalid Secret error = %v", err)
			}
		})
	}
}

func readyCluster(secret *corev1.Secret) *fakeCluster {
	ready := true
	return &fakeCluster{
		secret: secret.DeepCopy(),
		deployment: &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: apiDeploymentName, Namespace: adminauth.CredentialNamespace, Generation: 2},
			Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](1), Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}},
			Status:     appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1},
		},
		slices: &discoveryv1.EndpointSliceList{Items: []discoveryv1.EndpointSlice{{
			ObjectMeta: metav1.ObjectMeta{Name: "arcadectl-api-endpoints", Namespace: adminauth.CredentialNamespace, Labels: map[string]string{discoveryv1.LabelServiceName: apiServiceName}},
			Endpoints: []discoveryv1.Endpoint{{
				Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready},
				TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: adminauth.CredentialNamespace, Name: "arcadectl-api-pod", UID: "api-pod-uid"},
			}},
		}}},
	}
}

func TestSecretCandidateComparisonRequiresExactRevision(t *testing.T) {
	credential, _ := adminauth.GenerateCredential(time.Now().UTC(), time.Hour)
	secret, _ := testSecretForCredential(credential)
	secret.UID, secret.ResourceVersion = "uid", "2"
	if !testSecretMatchesCandidate(secret, credential, "uid", "2") || testSecretMatchesCandidate(secret, credential, "other", "2") ||
		testSecretMatchesCandidate(secret, credential, "uid", "3") {
		t.Fatal("candidate identity comparison is not exact")
	}
	if !reflect.DeepEqual(secret.Labels, adminauth.ManagedSecretLabels()) {
		t.Fatal("candidate labels changed")
	}
	for _, missing := range []string{"UID", "RV"} {
		changed := secret.DeepCopy()
		if missing == "UID" {
			changed.UID = ""
		} else {
			changed.ResourceVersion = ""
		}
		if testSecretMatchesCandidate(changed, credential, "", "") {
			t.Fatal("incomplete readback identity accepted")
		}
	}
}

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func boundedTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}
