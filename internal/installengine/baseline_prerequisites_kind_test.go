//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// Actual controller-manager typechecking plus the closed production bootstrap
// CREATE/receipt/recovery proof, with fresh ownership through actual lifecycle
// Steps and restart. The separate larger pre-controller component continues
// from this same genuine setup; neither replaces signed-binary lifecycle proof.
// The existing owned Kind helper caps the node at 3 GiB and cleans its exact
// cluster/registry/images. No external kubeconfig, workload or world is used.
func TestKindBaselinePrerequisiteCreateNative(t *testing.T) {
	testKindBaselineNative(t, false)
}

// Actual 37-entry pre-controller inventory, including original Secret effects,
// complete empty executor observation and retained/full runtime proofs. This
// does not execute the full-admission retirement archive or start a controller.
func TestKindBaselinePrecontrollerRuntimeNative(t *testing.T) {
	testKindBaselineNative(t, true)
}

func testKindBaselineNative(t *testing.T, precontroller bool) {
	t.Helper()
	for _, profile := range []struct{ id, node string }{{installrender.Profile135, targetKind135}, {installrender.Profile137, targetKind137}} {
		t.Run(profile.id, func(t *testing.T) {
			fixture := targetKindFixture
			if precontroller {
				fixture = targetKindPrecontrollerFixture
			}
			ctx, config, _ := fixture(t, profile.node)
			plan := fixturePlanProfile(t, "baseline-native-create", profile.id)
			baseline := baselineFixturePlan(t, plan.Namespace(), profile.id, 'd')
			access, err := NewDirectHTTPAccess(config)
			if err != nil {
				t.Fatal("owned native administration transport unavailable")
			}
			path := t.TempDir()
			if os.Chmod(path, 0700) != nil {
				t.Fatal("protected bootstrap directory unavailable")
			}
			files, err := privatefs.Open(path, false)
			if err != nil {
				t.Fatal("protected bootstrap evidence unavailable")
			}
			t.Cleanup(func() { _ = files.Close() })
			store, err := installstate.NewWithBaseline(access.Namespaces(), baseline, plan)
			if err != nil {
				t.Fatal("original baseline-aware journal unavailable")
			}
			engine, err := NewWithBaselineAccess(access, store, files, baseline, plan)
			if err != nil {
				t.Fatal("original baseline-aware engine unavailable")
			}
			lifecycle, err := NewClusterLifecycle(engine, access)
			if err != nil {
				t.Fatal("closed native lifecycle composition refused")
			}
			now := time.Now().UTC()
			tls := fixtureTLS(t, plan.Namespace(), now)
			opts := LifecycleOptions{Now: now, Credentials: tls, Activation: ActivationOptions{CAFile: tls.CAFile}}
			proof, err := NewClusterPrerequisites(engine, access)
			if err != nil || proof.VerifyBootstrap(ctx, plan, opts) != nil {
				t.Fatal("real fresh bootstrap prerequisites refused")
			}
			receipt, err := installstate.PrepareBootstrapWithBaseline(files, "bootstrap.json", plan, baseline)
			if err != nil {
				t.Fatal("signed baseline bootstrap pin refused")
			}
			snapshot, err := receipt.EnsureNamespace(ctx, access.Namespaces())
			if err != nil {
				t.Fatal("owned original Namespace bootstrap refused")
			}
			for step := 0; step < installbaseline.ResourceCount+2; step++ {
				before := snapshot.Document()
				snapshot, err = lifecycle.Step(ctx, snapshot, opts)
				if err != nil {
					t.Fatal("native original baseline ownership refused")
				}
				after := snapshot.Document()
				before.SecurityBaseline, after.SecurityBaseline = nil, nil
				after.Revision = before.Revision
				if !reflect.DeepEqual(before, after) {
					t.Fatal("native enrollment changed runtime fields")
				}
				store, err = installstate.NewWithBaseline(access.Namespaces(), baseline, plan)
				if err != nil {
					t.Fatal("original journal restart refused")
				}
				engine, err = NewWithBaselineAccess(access, store, files, baseline, plan)
				if err != nil {
					t.Fatal("original engine restart refused")
				}
				lifecycle, err = NewClusterLifecycle(engine, access)
				if err != nil {
					t.Fatal("closed native lifecycle restart refused")
				}
				snapshot, err = store.Load(ctx, snapshot.Anchor())
				if err != nil {
					t.Fatal("original journal restart reload refused")
				}
			}
			observer, err := NewClusterSecurityBaseline(engine, access)
			if err != nil || wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
				return observer.VerifyConfigured(ctx, snapshot) == nil, nil
			}) != nil {
				t.Fatal("actual native generation-current baseline typechecking did not converge")
			}
			// Advance through the same fresh prerequisites/stage dispatch, not
			// a fabricated runtime stage. Subsequent effects remain component
			// CRD/ServiceAccount proof, not a complete signed CLI lifecycle.
			beforeStage := snapshot.Document()
			snapshot, err = lifecycle.Step(ctx, snapshot, opts)
			if err != nil {
				t.Fatal("original prerequisite stage CAS refused")
			}
			afterStage := snapshot.Document()
			if afterStage.Stage != installstate.Applying || afterStage.Pending != nil || afterStage.SecurityBaseline.Stage != installstate.BaselineVerified || afterStage.SecurityBaseline.Pending != nil || len(afterStage.SecurityBaseline.Resources) != installbaseline.ResourceCount || len(afterStage.Resources) != 1 || afterStage.Resources[0].Key != namespaceKey(plan.Namespace()) {
				t.Fatal("native stage transition changed baseline or runtime inventory")
			}
			afterStage.Stage, afterStage.Revision = beforeStage.Stage, beforeStage.Revision
			if !reflect.DeepEqual(beforeStage, afterStage) {
				t.Fatal("native stage transition changed fields beyond stage/revision")
			}
			var keys []installstate.Key
			for _, kind := range []string{"CustomResourceDefinition", "ServiceAccount"} {
				for _, resource := range plan.ResourceMetadata() {
					if resource.Kind == kind {
						keys = append(keys, installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name})
						break
					}
				}
			}
			if len(keys) != 2 {
				t.Fatal("native prerequisite addresses unavailable")
			}
			client, err := kubernetes.NewForConfig(config)
			if err != nil {
				t.Fatal("owned native negative fixture client unavailable")
			}
			foreign, err := client.CoreV1().ConfigMaps(plan.Namespace()).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foreign-bootstrap"}}, metav1.CreateOptions{})
			if err != nil {
				t.Fatal("owned inert negative prerequisite fixture unavailable")
			}
			if _, err := engine.applyPrerequisite(ctx, snapshot, keys[0], plan.Digest()); !errors.Is(err, ErrSecurityBaseline) {
				t.Fatal("foreign native namespace inventory acquired CREATE authority")
			}
			unchanged, err := store.Load(ctx, snapshot.Anchor())
			if err != nil || unchanged.ResourceVersion() != snapshot.ResourceVersion() || unchanged.Document().Pending != nil {
				t.Fatal("refused native prerequisite altered its original intent")
			}
			if _, err := access.Get(ctx, keys[0]); !apierrors.IsNotFound(err) {
				t.Fatal("refused native prerequisite created a target")
			}
			uid, rv := foreign.UID, foreign.ResourceVersion
			if client.CoreV1().ConfigMaps(plan.Namespace()).Delete(ctx, foreign.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}) != nil {
				t.Fatal("exact owned inert negative fixture cleanup refused")
			}
			if _, err := client.CoreV1().ConfigMaps(plan.Namespace()).Get(ctx, foreign.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
				t.Fatal("exact owned inert negative fixture absence unproved")
			}
			for _, key := range keys {
				next, applyErr := engine.applyPrerequisite(ctx, snapshot, key, plan.Digest())
				if applyErr != nil && !errors.Is(applyErr, ErrOutcomeUnknown) {
					t.Fatal("healthy closed native prerequisite CREATE refused")
				}
				if next == nil {
					t.Fatal("native prerequisite returned no original snapshot")
				}
				snapshot = next
				if applyErr != nil {
					// CRD establishment may change RV after ACK. Only observation
					// converges; never resend preview/CREATE or adopt an unknown UID.
					if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 90*time.Second, true, func(ctx context.Context) (bool, error) {
						fresh, err := store.Load(ctx, snapshot.Anchor())
						if err != nil {
							return false, nil
						}
						observed, err := engine.Recover(ctx, fresh)
						if err == nil {
							snapshot = observed
						}
						return err == nil, nil
					}) != nil {
						t.Fatal("acknowledged native prerequisite did not settle observation-only")
					}
				}
				// Restart every completed effect from durable original receipts.
				engine, err = NewWithBaselineAccess(access, store, files, baseline, plan)
				if err != nil {
					t.Fatal("native prerequisite restart refused")
				}
				if _, err := NewClusterLifecycle(engine, access); err != nil {
					t.Fatal("native restarted closed composition refused")
				}
				snapshot, err = store.Load(ctx, snapshot.Anchor())
				if err != nil {
					t.Fatal("native restarted original journal unavailable")
				}
				entry, template := engine.inventory(snapshot.Document(), key)
				live, readErr := access.Get(ctx, key)
				if entry == nil || template == nil || readErr != nil || template.MatchLive(live, entry.UID) != nil || snapshot.Document().Pending != nil {
					t.Fatal("native prerequisite original identity or settlement unproved")
				}
				if _, err := engine.applyPrerequisite(ctx, snapshot, key, plan.Digest()); !errors.Is(err, ErrSecurityBaseline) {
					t.Fatal("settled native prerequisite acquired UPDATE/replay authority")
				}
			}
			if len(snapshot.Document().Resources) != 3 || len(snapshot.Document().SecurityBaseline.Resources) != installbaseline.ResourceCount {
				t.Fatal("native prerequisite mixed baseline/runtime inventories")
			}
			if _, err := engine.current(ctx, snapshot); !errors.Is(err, ErrSecurityBaseline) {
				t.Fatal("native bootstrap component invented full runtime enforcement")
			}
			t.Log("actual baseline typechecking, original CRD/SA CREATE, restart, foreign-inventory refusal and runtime fence proved")
			if !precontroller {
				return // preserve the original small component and its time bounds
			}

			// Build the actual fresh pre-controller state using only production
			// original CREATE/ACK/receipt/journal paths. Never fabricate inventory,
			// health, actor authority, executor observations or retained Secrets.
			// Keep the earlier incomplete-inventory refusal as an independent
			// control. This smaller component deliberately has no fixture archive;
			// its success cannot explain the exact signed CLI's archive-era failure.
			prerequisites, services := 0, 0
			for index, key := range lifecycle.ordered(snapshot.Document()) {
				if key.Kind == "Deployment" {
					continue // no controller or API process is allowed to start
				}
				prerequisite := baselinePrerequisiteKey(key, plan.Namespace())
				if prerequisite {
					prerequisites++
				} else if key.APIVersion == "v1" && key.Kind == "Service" && key.Name == "arcadectl-api" {
					services++
				} else {
					t.Fatal("native pre-controller component encountered an unreviewed effect")
				}
				if entry, _ := engine.inventory(snapshot.Document(), key); entry != nil {
					continue // the two earlier actual acknowledged effects
				}
				attempt, diagnostic := WithLifecycleDiagnostic(ctx)
				var next *installstate.Snapshot
				var applyErr error
				if prerequisite {
					next, applyErr = engine.applyPrerequisite(attempt, snapshot, key, plan.Digest())
				} else {
					// The Service uses ordinary Apply's complete runtime guard,
					// never the private nonexecuting bootstrap CREATE protocol.
					next, applyErr = engine.Apply(attempt, snapshot, key, plan.Digest(), false)
				}
				if applyErr != nil && !errors.Is(applyErr, ErrOutcomeUnknown) {
					t.Fatalf("native pre-controller original effect %d refused: fixture-deadline=%t %s", index, errors.Is(ctx.Err(), context.DeadlineExceeded), diagnostic.BoundarySnapshot())
				}
				if next == nil {
					t.Fatal("native pre-controller effect returned no original snapshot")
				}
				snapshot = next
				if applyErr != nil && wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 90*time.Second, true, func(ctx context.Context) (bool, error) {
					fresh, err := store.Load(ctx, snapshot.Anchor())
					if err != nil {
						return false, nil
					}
					observed, err := engine.Recover(ctx, fresh)
					if err == nil {
						snapshot = observed
					}
					return err == nil, nil
				}) != nil {
					t.Fatal("native pre-controller acknowledged effect did not settle observation-only")
				}
				// Restart the production composition after EVERY completed effect.
				engine, err = NewWithBaselineAccess(access, store, files, baseline, plan)
				if err != nil {
					t.Fatal("native pre-controller engine restart refused")
				}
				lifecycle, err = NewClusterLifecycle(engine, access)
				if err != nil {
					t.Fatal("native pre-controller closed lifecycle restart refused")
				}
				snapshot, err = store.Load(ctx, snapshot.Anchor())
				if err != nil {
					t.Fatal("native pre-controller original journal reload refused")
				}
				entry, template := engine.inventory(snapshot.Document(), key)
				live, readErr := access.Get(ctx, key)
				if entry == nil || template == nil || readErr != nil || template.MatchLive(live, entry.UID) != nil || snapshot.Document().Pending != nil {
					t.Fatal("native pre-controller original identity or settlement unproved")
				}
			}
			if prerequisites != 33 || services != 1 || len(snapshot.Document().Resources) != 35 {
				t.Fatal("native pre-controller public inventory coverage changed")
			}
			for index := 0; index < 2; index++ {
				attempt, diagnostic := WithLifecycleDiagnostic(ctx)
				next, done, err := lifecycle.ensureSecrets(attempt, snapshot, opts)
				if err != nil || done || next == nil || next.ResourceVersion() == snapshot.ResourceVersion() {
					t.Fatalf("native pre-controller original Secret effect %d refused: fixture-deadline=%t %s", index, errors.Is(ctx.Err(), context.DeadlineExceeded), diagnostic.BoundarySnapshot())
				}
				snapshot = next
				// Independently bind each live Secret to the recorded original
				// UID and its durable CREATE ACK, without logging private data or
				// relying on the workflow's later retained validation to assert it.
				name := []string{"arcadectl-admin-credential", "arcadectl-api-tls"}[index]
				key := secretKey(plan.Namespace(), name)
				var original *installstate.Resource
				for _, resource := range snapshot.Document().Resources {
					if resource.Key == key {
						if original != nil {
							t.Fatal("native pre-controller Secret original is duplicated")
						}
						original = &resource
					}
				}
				live, readErr := access.PrivateSecrets().Get(ctx, key.Namespace, key.Name)
				if original == nil || !original.Retained || original.TemplateSHA256 != "" || original.Phase != installrender.API || readErr != nil || live == nil || original.UID == "" || live.UID != original.UID || live.ResourceVersion == "" || live.DeletionTimestamp != nil || len(live.Annotations) != 1 {
					t.Fatal("native pre-controller Secret original metadata or public hash invariant unproved")
				}
				nonce := live.Annotations[installstate.MutationAnnotation]
				if !nonceID.MatchString(nonce) {
					t.Fatal("native pre-controller Secret original nonce unproved")
				}
				receiptName := "create-" + nonce + ".json"
				body, identity, readErr := files.Read(receiptName, 4096)
				var receipt createReceipt
				if readErr != nil || files.ConfirmDurable(receiptName, identity) != nil || json.Unmarshal(body, &receipt) != nil || receipt.Version != "v1" || receipt.Anchor != snapshot.Anchor() || receipt.TargetPackage != plan.Digest() || receipt.OriginalUID != original.UID || receipt.Pending != (installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: nonce}) {
					t.Fatal("native pre-controller Secret protected original ACK unproved")
				}
			}
			document := snapshot.Document()
			if document.Stage != installstate.Applying || document.Revision != 100 || document.Pending != nil || document.Installed || len(document.Resources) != 37 || document.SecurityBaseline.Stage != installstate.BaselineVerified || document.SecurityBaseline.Pending != nil || len(document.SecurityBaseline.Resources) != 12 {
				t.Fatal("native pre-controller original journal did not reach the exact 37-entry Applying boundary")
			}
			observer, err = NewClusterSecurityBaseline(engine, access)
			if err != nil {
				t.Fatal("native pre-controller full runtime provider unavailable")
			}
			executables, err := observer.collectExecutables(ctx, snapshot)
			if err != nil || executables == nil || len(executables.whole) != 0 || len(executables.guarded) != 0 {
				t.Fatal("native pre-controller complete executable inventory is not empty")
			}
			collections := executables.observation.Collections()
			if collections == nil || collections.Pods == nil || collections.Jobs == nil || collections.Deployments == nil || collections.ReplicaSets == nil || collections.StatefulSets == nil || collections.DaemonSets == nil || collections.ReplicationControllers == nil || collections.CronJobs == nil || len(collections.Pods.Items)+len(collections.Jobs.Items)+len(collections.Deployments.Items)+len(collections.ReplicaSets.Items)+len(collections.StatefulSets.Items)+len(collections.DaemonSets.Items)+len(collections.ReplicationControllers.Items)+len(collections.CronJobs.Items) != 0 {
				t.Fatal("native pre-controller eight-family empty observation is incomplete")
			}
			for _, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller", "arcadectl-api"} {
				key := installstate.Key{APIVersion: "apps/v1", Kind: "Deployment", Namespace: plan.Namespace(), Name: name}
				if _, err := access.Get(ctx, key); !apierrors.IsNotFound(err) {
					t.Fatal("native pre-controller original Deployment absence unproved")
				}
			}
			attempt, diagnostic := WithLifecycleDiagnostic(ctx)
			beforeRetained := snapshot.ResourceVersion()
			beforeBytes := snapshot.Bytes()
			next, done, err := lifecycle.ensureSecrets(attempt, snapshot, opts)
			if err != nil || !done || next == nil || next.ResourceVersion() != beforeRetained || !reflect.DeepEqual(next.Bytes(), beforeBytes) {
				t.Fatalf("native pre-controller retained Secret/full runtime proof refused: fixture-deadline=%t %s", errors.Is(ctx.Err(), context.DeadlineExceeded), diagnostic.BoundarySnapshot())
			}
			unchanged, err = store.Load(ctx, snapshot.Anchor())
			if err != nil || unchanged.ResourceVersion() != beforeRetained || !reflect.DeepEqual(unchanged.Bytes(), beforeBytes) {
				t.Fatal("native pre-controller read-only proof changed the original journal")
			}
			t.Log("genuine native Applying revision 100, original 37/12 inventories, empty eight executor families, absent three parents, and retained Secret/full runtime proof passed; no full-admission archive or signed lifecycle claimed")
		})
	}
}
