// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Fixed mock-cluster reads plus stock native SPDY and a real HTTPS boundary.
// This exercises the closed provider, not actual kubelet or binary lifecycle.
func closedTargetFixture(t *testing.T, x *servingFixture, mode string, onUpgrade func(), onRead func(*corev1.Namespace)) (*ClusterTargetAuthenticated, LifecycleCheck, *atomic.Int32) {
	t.Helper()
	ns, err := x.f.access.client.CoreV1().Namespaces().Get(context.Background(), x.f.plan.Namespace(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	read := func(w http.ResponseWriter, r *http.Request) bool {
		mu.Lock()
		defer mu.Unlock()
		if onRead != nil {
			onRead(ns)
		}
		var object any
		if r.URL.Path == "/api/v1/namespaces/"+ns.Name {
			object = ns
		}
		if r.URL.Path == "/apis/discovery.k8s.io/v1/namespaces/"+ns.Name+"/endpointslices" {
			object = x.access.list
		}
		if r.URL.Path == "/api/v1/namespaces/"+ns.Name+"/pods/"+x.access.pod.Name {
			pod := x.access.pod.DeepCopy()
			if mode == "foreign-pod" {
				pod.UID = "foreign"
			}
			object = pod
		}
		if r.URL.Path == "/apis/apps/v1/namespaces/"+ns.Name+"/replicasets/"+x.access.rs.Name {
			object = x.access.rs
		}
		for key, value := range x.f.access.objects {
			path, pathErr := resourcePath(key, false)
			if pathErr == nil && r.URL.Path == path {
				object = value.Object
			}
		}
		for name, secret := range x.secrets.objects {
			path, _ := privateSecretPath(secretKey(ns.Name, name), false)
			if r.URL.Path == path {
				// The in-process private fixture omits wire TypeMeta; an API
				// response must carry the exact resource identity.
				wire := secret.DeepCopy()
				wire.APIVersion, wire.Kind = "v1", "Secret"
				object = wire
			}
		}
		if object == nil {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(object)
		return true
	}
	access, posts := nativeForwardFixture(t, x, mode, onUpgrade, read)
	plans := []*installrender.Plan{x.f.plan}
	for digest, plan := range x.f.engine.plans {
		if digest != x.f.plan.Digest() {
			plans = append(plans, plan)
		}
	}
	store, err := installstate.New(access.Namespaces(), plans...)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewWithAccess(access, store, x.f.engine.files, plans...)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Load(context.Background(), x.f.snapshot.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewClusterPrerequisites(engine, access)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClusterTargetAuthenticated(p)
	if err != nil {
		t.Fatal(err)
	}
	return c, LifecycleCheck{Checkpoint: TargetAuthenticated, Snapshot: s, Mode: s.Document().Mode, Target: x.f.plan, Options: LifecycleOptions{Now: time.Now().UTC(), Activation: x.options}}, posts
}

// Explicitly construct public fixture state, not a lifecycle effect proof.
func setTargetFixtureJournal(t *testing.T, x *servingFixture, d installstate.Document) {
	t.Helper()
	plans := []*installrender.Plan{x.f.plan}
	for digest, plan := range x.f.engine.plans {
		if digest != x.f.plan.Digest() {
			plans = append(plans, plan)
		}
	}
	body, err := installstate.Encode(d, plans...)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := x.f.access.client.CoreV1().Namespaces().Get(context.Background(), d.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ns.Annotations[installstate.Annotation] = string(body)
	if _, err := x.f.access.client.CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	x.f.snapshot, err = x.f.store.Load(context.Background(), x.f.snapshot.Anchor())
	if err != nil {
		t.Fatal(err)
	}
}

func TestTargetAuthenticatedSupportedChangedPackageTransitions(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	for _, mode := range []installstate.Mode{installstate.Upgrade, installstate.Rollback} {
		t.Run(string(mode), func(t *testing.T) {
			current, other := target, previous
			if mode == installstate.Rollback {
				current, other = previous, target
			}
			x := newServingFixtureWithPlan(t, current, other)
			d := x.f.snapshot.Document()
			d.Mode, d.ActivePackage, d.Installed = mode, other.Digest(), true
			if mode == installstate.Rollback {
				d.PreviousPackage = current.Digest()
			}
			setTargetFixtureJournal(t, x, d)
			// Keep the protected bootstrap candidate tied to its predecessor.
			// Reloading it for current activation must fail, not regenerate it.
			name := credentialName(x.f.snapshot.Anchor())
			raw, id, err := x.f.engine.files.Read(name, canonicaljson.MaxBytes)
			if err != nil {
				t.Fatal(err)
			}
			var candidate credentialDocument
			if json.Unmarshal(raw, &candidate) != nil {
				t.Fatal("private fixture candidate decoding failed")
			}
			candidate.PackageSHA256 = other.Digest()
			body, err := encodeCredentials(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := x.f.engine.files.AtomicWrite(name, body, &id); err != nil {
				t.Fatal(err)
			}
			if _, err := x.f.engine.LoadCredentials(context.Background(), x.f.snapshot, time.Now()); err != ErrCredentials {
				t.Fatal("stale bootstrap candidate accepted")
			}
			requests := activationServer(t, x, current.Namespace(), nil)
			c, r, posts := closedTargetFixture(t, x, "success", nil, nil)
			if err := c.Verify(context.Background(), r); err != nil || posts.Load() != 1 || requests.Load() != 1 {
				t.Fatal("current target identity authentication failed", err)
			}
		})
	}
}

func TestTargetAuthenticatedOriginalSecretUIDRotation(t *testing.T) {
	for _, fault := range []string{"valid", "old-client", "replaced-secret"} {
		t.Run(fault, func(t *testing.T) {
			x := newServingFixture(t)
			secret := x.secrets.objects[adminauth.CredentialSecretName]
			before := secret.DeepCopy()
			old, err := adminauth.ParseVerifierBundle(secret.Data[adminauth.VerifierSecretKey])
			if err != nil {
				t.Fatal("private fixture verifier unavailable")
			}
			generated, err := adminauth.GenerateCredential(time.Now().UTC(), 2*time.Hour)
			if err != nil {
				t.Fatal("private fixture rotation failed")
			}
			generated.Bundle.Serial = old.Serial + 1
			bundle, err := adminauth.MarshalVerifierBundle(generated.Bundle)
			if err != nil {
				t.Fatal("private fixture verifier encoding failed")
			}
			secret.Data = map[string][]byte{adminauth.VerifierSecretKey: bundle, adminauth.TokenSecretKey: []byte(generated.Token)}
			secret.ResourceVersion = "501"
			if fault == "replaced-secret" {
				secret.UID = "foreign-secret"
			}
			client, err := adminauth.MarshalClientCredential(adminauth.ClientCredential{Version: adminauth.ClientCredentialVersion,
				CredentialID: generated.Bundle.CredentialID, Serial: generated.Bundle.Serial, ExpiresAt: generated.Bundle.ExpiresAt, Token: generated.Token,
				PriorSecretUID: string(before.UID), PriorResourceVersion: before.ResourceVersion})
			if err != nil {
				t.Fatal("private client encoding failed")
			}
			if fault != "old-client" {
				x.options.CredentialFile = filepath.Join(filepath.Dir(x.tls.KeyFile), "rotated-client.json")
				if os.WriteFile(x.options.CredentialFile, client, 0600) != nil {
					t.Fatal("private client fixture unavailable")
				}
			}
			requests := activationServer(t, x, x.f.plan.Namespace(), nil)
			c, r, posts := closedTargetFixture(t, x, "success", nil, nil)
			err = c.Verify(context.Background(), r)
			if fault == "valid" {
				if err != nil || posts.Load() != 1 || requests.Load() != 1 {
					t.Fatal("valid original-UID rotation refused", err)
				}
			} else if err != ErrActivation || posts.Load() != 0 || requests.Load() != 0 {
				t.Fatal("stale or foreign credential reached native authentication")
			}
			if x.secrets.writes != 2 {
				t.Fatal("activation performed rotation writes")
			}
		})
	}
}

func TestTargetAuthenticatedRejectsUnsettledJournal(t *testing.T) {
	for _, fault := range []string{"applying", "pending"} {
		t.Run(fault, func(t *testing.T) {
			x := newServingFixture(t)
			d := x.f.snapshot.Document()
			if fault == "applying" {
				d.Stage = installstate.Applying
			} else {
				for _, resource := range d.Resources {
					if resource.Key.Kind == "ServiceAccount" {
						d.Pending = &installstate.Pending{Action: installstate.Update, Key: resource.Key, CreateNonce: strings.Repeat("d", 32),
							BeforeUID: resource.UID, BeforeResourceVersion: "10", BeforeSHA256: resource.TemplateSHA256, AfterSHA256: resource.TemplateSHA256}
						break
					}
				}
			}
			setTargetFixtureJournal(t, x, d)
			requests := activationServer(t, x, x.f.plan.Namespace(), nil)
			c, r, posts := closedTargetFixture(t, x, "success", nil, nil)
			if err := c.Verify(context.Background(), r); err != ErrInvalid || posts.Load() != 0 || requests.Load() != 0 {
				t.Fatal("unsettled journal reached authentication", err)
			}
		})
	}
}

func TestTargetAuthenticatedClosedNativeAccessAndRealHTTPS(t *testing.T) {
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			x := newServingFixtureWithPlan(t, fixturePlanProfile(t, "isolated-install", profile))
			requests := activationServer(t, x, x.f.plan.Namespace(), nil)
			c, r, posts := closedTargetFixture(t, x, "success", nil, nil)
			before := r.Snapshot.Bytes()
			if err := c.Verify(context.Background(), r); err != nil {
				_, servingErr := c.prerequisites.engine.ObserveServing(context.Background(), r.Snapshot, c.prerequisites.access.Serving())
				_, bindingErr := c.activation.binding(context.Background(), r.Snapshot, r.Options.Activation)
				t.Fatalf("target=%v original=%v serving=%v binding=%v", err, c.prerequisites.original(context.Background(), r.Snapshot), servingErr, bindingErr)
			}
			if posts.Load() != 1 || requests.Load() != 1 || x.secrets.writes != 2 {
				t.Fatal("auth skipped, replayed or wrote Secrets")
			}
			after, err := c.prerequisites.engine.journal.Load(context.Background(), r.Snapshot.Anchor())
			if err != nil || string(after.Bytes()) != string(before) {
				t.Fatal("authentication changed journal")
			}
		})
	}
}

func TestTargetAuthenticatedRejectsCheckpointAndAuthoritySubstitution(t *testing.T) {
	x := newServingFixture(t)
	requests := activationServer(t, x, x.f.plan.Namespace(), nil)
	c, r, posts := closedTargetFixture(t, x, "success", nil, nil)
	for _, change := range []func(*LifecycleCheck){
		func(r *LifecycleCheck) { r.Checkpoint = ControllersAvailable },
		func(r *LifecycleCheck) { r.Snapshot = nil },
		func(r *LifecycleCheck) { r.Target = nil },
		func(r *LifecycleCheck) { r.Target = fixturePlanProfile(t, "foreign", installrender.Profile135) },
		func(r *LifecycleCheck) { r.Mode = installstate.Uninstall },
		func(r *LifecycleCheck) { r.Options.Now = time.Time{} },
	} {
		bad := r
		change(&bad)
		if err := c.Verify(context.Background(), bad); err != ErrInvalid {
			t.Fatal("foreign request accepted", err)
		}
	}
	if err := c.Verify(nil, r); err != ErrInvalid {
		t.Fatal("nil context accepted")
	}
	if _, err := NewClusterTargetAuthenticated(nil); err != ErrInvalid {
		t.Fatal("nil provider accepted")
	}
	foreign := *c.prerequisites
	foreign.access = &HTTPAccess{}
	if _, err := NewClusterTargetAuthenticated(&foreign); err != ErrInvalid {
		t.Fatal("foreign frozen access accepted")
	}
	if posts.Load() != 0 || requests.Load() != 0 {
		t.Fatal("invalid request reached credentials")
	}
}

func TestTargetAuthenticatedNoFallbackAndRepeatedOriginalBarriers(t *testing.T) {
	for _, fault := range []string{"foreign-pod", "redirect", "rejection", "during-upgrade", "after-auth", "namespace-after-auth", "secret-after-auth", "foreign-api-namespace"} {
		t.Run(fault, func(t *testing.T) {
			x := newServingFixture(t)
			var changed atomic.Bool
			namespace := x.f.plan.Namespace()
			if fault == "foreign-api-namespace" {
				namespace = "foreign"
			}
			requests := activationServer(t, x, namespace, func() {
				if fault == "after-auth" || fault == "namespace-after-auth" || fault == "secret-after-auth" {
					changed.Store(true)
				}
			})
			var upgrade func()
			if fault == "during-upgrade" {
				upgrade = func() { changed.Store(true) }
			}
			mode := "success"
			if fault == "foreign-pod" || fault == "redirect" || fault == "rejection" {
				mode = fault
			}
			read := func(ns *corev1.Namespace) {
				if !changed.Load() {
					return
				}
				switch fault {
				case "during-upgrade", "after-auth":
					x.access.pod.ResourceVersion = "11"
				case "namespace-after-auth":
					ns.ResourceVersion = "11"
				case "secret-after-auth":
					x.secrets.objects[adminauth.CredentialSecretName].ResourceVersion = "11"
				}
			}
			c, r, posts := closedTargetFixture(t, x, mode, upgrade, read)
			if err := c.Verify(context.Background(), r); err != ErrActivation {
				t.Fatal("substitution counted as auth", err)
			}
			if fault == "during-upgrade" && requests.Load() != 0 {
				t.Fatal("drift reached bearer transmission")
			}
			want := int32(1)
			if fault == "foreign-pod" {
				want = 0
			}
			if posts.Load() != want {
				t.Fatal("native route replayed or fallback used")
			}
		})
	}
}
