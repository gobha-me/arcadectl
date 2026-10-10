//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Native ownership/bootstrap/receipt evidence, not native typechecking health
// (envtest has no controller-manager). No workload or world is created. A real
// closed production guard is still required before runtime installation.
func TestEnvtestBaselineOriginalOwnershipAndRestart(t *testing.T) {
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		t.Run(profile, func(t *testing.T) {
			runtimePlan := fixturePlanProfile(t, "baseline-owned", profile)
			baseline := baselineFixturePlan(t, runtimePlan.Namespace(), profile, 'd')
			environment := &envtest.Environment{
				UseExistingCluster: new(bool), DownloadBinaryAssets: true,
				DownloadBinaryAssetsVersion:  runtimePlan.Profile().KubernetesVersion,
				DownloadBinaryAssetsIndexURL: "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml",
				BinaryAssetsDirectory:        t.TempDir(), ControlPlaneStartTimeout: 90 * time.Second, ControlPlaneStopTimeout: 30 * time.Second,
			}
			if profile == installrender.Profile135 {
				prerequisite135Assets(t, environment)
			} else {
				environment.ControlPlane.APIServer = &envtest.APIServer{}
			}
			environment.ControlPlane.APIServer.Configure().Set("disable-admission-plugins", "")
			config, err := environment.Start()
			if err != nil {
				t.Fatal("owned API server unavailable")
			}
			t.Cleanup(func() {
				if environment.Stop() != nil {
					t.Error("owned API server cleanup failed")
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
			defer cancel()
			access, err := NewDirectHTTPAccess(config)
			if err != nil {
				t.Fatal("owned original administration transport unavailable")
			}
			path := t.TempDir()
			if os.Chmod(path, 0700) != nil {
				t.Fatal("protected bootstrap directory unavailable")
			}
			files, err := privatefs.Open(path, false)
			if err != nil {
				t.Fatal("protected bootstrap storage unavailable")
			}
			t.Cleanup(func() { _ = files.Close() })
			store, err := installstate.NewWithBaseline(access.Namespaces(), baseline, runtimePlan)
			if err != nil {
				t.Fatal("baseline-aware original journal refused")
			}
			engine, err := NewWithBaselineAccess(access, store, files, baseline, runtimePlan)
			if err != nil {
				t.Fatal("baseline ownership engine refused")
			}
			lifecycle, err := NewClusterLifecycle(engine, access)
			if err != nil {
				t.Fatal("closed native lifecycle refused")
			}
			now := time.Now().UTC()
			tls := fixtureTLS(t, runtimePlan.Namespace(), now)
			opts := LifecycleOptions{Now: now, Credentials: tls, Activation: ActivationOptions{CAFile: tls.CAFile}}
			proof, err := NewClusterPrerequisites(engine, access)
			if err != nil || proof.VerifyBootstrap(ctx, runtimePlan, opts) != nil {
				t.Fatal("native baseline-aware bootstrap prerequisites refused")
			}
			// A signed shape is not ownership: either occupied native resource
			// kind must refuse before namespace or bootstrap-receipt creation.
			for _, kind := range []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
				var key installstate.Key
				for _, resource := range baseline.Resources() {
					object := resource.Object
					if object.GetKind() == kind {
						key = installstate.Key{APIVersion: object.GetAPIVersion(), Kind: kind, Name: object.GetName()}
						break
					}
				}
				template, templateErr := engine.baseline.contract.Template(key, false)
				nonce, nonceErr := installstate.NewID()
				if templateErr != nil || nonceErr != nil {
					t.Fatal("owned occupied-address fixture template refused")
				}
				candidate, candidateErr := template.Candidate(nonce)
				if candidateErr != nil {
					t.Fatal("owned occupied-address fixture candidate refused")
				}
				occupied, createErr := access.Create(ctx, key, candidate, false)
				if createErr != nil || occupied.GetUID() == "" || occupied.GetResourceVersion() == "" {
					t.Fatal("owned occupied-address fixture creation refused")
				}
				if proof.VerifyBootstrap(ctx, runtimePlan, opts) != ErrPrerequisites {
					t.Fatal("native bootstrap adopted occupied baseline address", kind)
				}
				if _, err := access.Get(ctx, namespaceKey(runtimePlan.Namespace())); !apierrors.IsNotFound(err) {
					t.Fatal("occupied baseline preflight changed namespace")
				}
				if entries, err := os.ReadDir(path); err != nil || len(entries) != 0 {
					t.Fatal("occupied baseline preflight wrote bootstrap evidence")
				}
				uid, rv := occupied.GetUID(), occupied.GetResourceVersion()
				if access.Delete(ctx, key, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}) != nil {
					t.Fatal("original occupied-address fixture cleanup refused")
				}
				if _, err := access.Get(ctx, key); !apierrors.IsNotFound(err) {
					t.Fatal("original occupied-address fixture cleanup incomplete")
				}
			}
			if proof.VerifyBootstrap(ctx, runtimePlan, opts) != nil {
				t.Fatal("native fresh bootstrap failed after exact occupied-address cleanup")
			}
			receipt, err := installstate.PrepareBootstrapWithBaseline(files, "baseline-bootstrap.json", runtimePlan, baseline)
			if err != nil {
				t.Fatal("signed baseline was not pinned before bootstrap")
			}
			snapshot, err := receipt.EnsureNamespace(ctx, access.Namespaces())
			if err != nil {
				t.Fatal("original namespace bootstrap refused")
			}
			invalid := opts
			invalid.Activation.CAFile = tls.CAFile + ".missing"
			if _, err := lifecycle.Step(ctx, snapshot, invalid); err != ErrLifecycle {
				t.Fatal("native lifecycle skipped initial TLS prerequisites")
			}
			unchanged, err := store.Load(ctx, snapshot.Anchor())
			if err != nil || unchanged.ResourceVersion() != snapshot.ResourceVersion() || !reflect.DeepEqual(unchanged.Document(), snapshot.Document()) {
				t.Fatal("denied native prerequisites changed original journal")
			}
			for _, resource := range baseline.Resources() {
				object := resource.Object
				key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Name: object.GetName()}
				if _, err := access.Get(ctx, key); !apierrors.IsNotFound(err) {
					t.Fatal("denied native prerequisites created a baseline resource")
				}
			}
			for step := 0; step < installbaseline.ResourceCount+2; step++ {
				before := len(snapshot.Document().SecurityBaseline.Resources)
				snapshot, err = lifecycle.Step(ctx, snapshot, opts)
				if err != nil || len(snapshot.Document().SecurityBaseline.Resources)-before > 1 {
					t.Fatal("native original baseline effect or checked settlement failed")
				}
				// Every step reconstructs from authenticated plans and protected
				// files, without an in-memory acknowledgement capability.
				store, err = installstate.NewWithBaseline(access.Namespaces(), baseline, runtimePlan)
				if err != nil {
					t.Fatal("native restart journal refused")
				}
				engine, err = NewWithBaselineAccess(access, store, files, baseline, runtimePlan)
				if err != nil {
					t.Fatal("native restart engine refused")
				}
				lifecycle, err = NewClusterLifecycle(engine, access)
				if err != nil {
					t.Fatal("closed native restart lifecycle refused")
				}
				snapshot, err = store.Load(ctx, snapshot.Anchor())
				if err != nil {
					t.Fatal("native original journal reload refused")
				}
			}
			document := snapshot.Document()
			if document.SecurityBaseline.Stage != installstate.BaselineVerified || len(document.SecurityBaseline.Resources) != installbaseline.ResourceCount || document.SecurityBaseline.Pending != nil || len(document.Resources) != 1 || document.Resources[0].Key.Kind != "Namespace" {
				t.Fatal("native baseline contaminated runtime inventory or lacks original identities")
			}
			for _, resource := range document.SecurityBaseline.Resources {
				template, err := engine.baseline.contract.Template(resource.Key, false)
				live, readErr := access.Get(ctx, resource.Key)
				if err != nil || readErr != nil || template.MatchLive(live, resource.UID) != nil {
					t.Fatal("native baseline identity or whole template drifted")
				}
			}
			if next, err := engine.EstablishBaselineOwnership(ctx, snapshot); err != nil || !reflect.DeepEqual(next.Document(), document) || next.ResourceVersion() != snapshot.ResourceVersion() {
				t.Fatal("native original ownership was replayed")
			}
			if _, err := engine.current(ctx, snapshot); err != ErrSecurityBaseline {
				t.Fatal("native ownership was misrepresented as runtime security proof")
			}
			configuration, err := NewClusterSecurityBaseline(engine, access)
			if err != nil {
				t.Fatal("closed native baseline configuration observer refused")
			}
			if configuration.VerifyConfigured(ctx, snapshot) != ErrSecurityBaseline {
				t.Fatal("API-server-only ownership was misrepresented as native typechecking health")
			}
			t.Run("prerequisite-absence", func(t *testing.T) {
				// Native production collection/SSAR/original-CAS proof only.
				// This API server has no typechecking controller; bypassing
				// configured() in this component test does NOT authorize effects.
				document := snapshot.Document()
				document.Stage = installstate.Applying
				document.Revision++
				var err error
				snapshot, err = store.Commit(ctx, snapshot, document)
				if err != nil {
					t.Fatal("native original prerequisite stage fixture refused")
				}
				var key installstate.Key
				for _, resource := range runtimePlan.ResourceMetadata() {
					if resource.Kind == "CustomResourceDefinition" {
						key = installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Name: resource.Name}
						break
					}
				}
				operation, err := engine.prerequisiteOperation(snapshot, key, runtimePlan.Digest())
				if err != nil {
					t.Fatal("native signed prerequisite descriptor refused")
				}
				if _, err := configuration.prerequisiteEmptyNamespace(ctx, snapshot, operation); err != nil {
					t.Fatal("native complete original prerequisite absence proof refused")
				}
				client, err := kubernetes.NewForConfig(config)
				if err != nil {
					t.Fatal("owned inert namespace fixture client unavailable")
				}
				foreign, err := client.CoreV1().ConfigMaps(runtimePlan.Namespace()).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foreign-prerequisite", Namespace: runtimePlan.Namespace()}}, metav1.CreateOptions{})
				if err != nil {
					t.Fatal("owned inert negative prerequisite fixture refused")
				}
				if _, err := configuration.prerequisiteEmptyNamespace(ctx, snapshot, operation); err != ErrSecurityBaseline {
					t.Fatal("native foreign namespace inventory was omitted")
				}
				uid, rv := foreign.UID, foreign.ResourceVersion
				if client.CoreV1().ConfigMaps(runtimePlan.Namespace()).Delete(ctx, foreign.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}) != nil {
					t.Fatal("exact owned inert prerequisite fixture cleanup failed")
				}
				if _, err := client.CoreV1().ConfigMaps(runtimePlan.Namespace()).Get(ctx, foreign.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
					t.Fatal("owned inert prerequisite fixture cleanup was not complete")
				}
				if _, err := configuration.prerequisiteEmptyNamespace(ctx, snapshot, operation); err != nil {
					t.Fatal("native prerequisite absence did not recover after exact owned cleanup")
				}
				if configuration.VerifyConfigured(ctx, snapshot) != ErrSecurityBaseline {
					t.Fatal("component absence proof invented native typechecking or enforcement")
				}
				if _, err := engine.current(ctx, snapshot); err != ErrSecurityBaseline {
					t.Fatal("component absence proof authorized ordinary runtime")
				}
			})
			t.Run("event-alias-snapshot", func(t *testing.T) {
				testNativeEventAliasSnapshot(t, ctx, config, snapshot.Anchor(), store, runtimePlan)
			})
		})
	}
}

// Native feasibility proof of ONE exact Event-alias snapshot, including
// continuation, followed by actual GCReader integration with an intervening
// native update. This does not certify the installer lifecycle or Kind suite.
func testNativeEventAliasSnapshot(t *testing.T, ctx context.Context, config *rest.Config, anchor installstate.Anchor, journal *installstate.Store, plan *installrender.Plan) {
	t.Helper()
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal("owned Event fixture client unavailable")
	}
	meta, err := metadata.NewForConfig(config)
	if err != nil {
		t.Fatal("owned transformed metadata client unavailable")
	}
	reference, err := client.CoreV1().ConfigMaps(anchor.Namespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "event-reference", Namespace: anchor.Namespace}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal("owned non-executable Event reference fixture refused")
	}
	var first *corev1.Event
	for _, name := range []string{"snapshot-event-a", "snapshot-event-b"} {
		event, err := client.CoreV1().Events(anchor.Namespace).Create(ctx, &corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Name: name, Namespace: anchor.Namespace, Labels: map[string]string{"snapshot": "original"}},
			InvolvedObject: corev1.ObjectReference{APIVersion: "v1", Kind: "ConfigMap", Namespace: anchor.Namespace, Name: reference.Name, UID: reference.UID},
			Type:           "Normal", Reason: "InertFixture", Message: "test-owned non-executable snapshot metadata", Source: corev1.EventSource{Component: "arcadectl-test"}, Count: 1,
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal("owned non-executable Event creation refused")
		}
		if first == nil {
			first = event
		}
	}
	collect := func(source schema.GroupVersionResource, exact string) ([]metav1.PartialObjectMetadata, string) {
		t.Helper()
		rows := []metav1.PartialObjectMetadata{}
		rv, token := "", ""
		for page := 0; page < 3; page++ {
			options := metav1.ListOptions{Limit: 1, Continue: token}
			if page == 0 && exact != "" {
				options.ResourceVersion, options.ResourceVersionMatch = exact, metav1.ResourceVersionMatchExact
			}
			list, err := meta.Resource(source).Namespace(anchor.Namespace).List(ctx, options)
			if err != nil || list.ResourceVersion == "" || rv != "" && rv != list.ResourceVersion || exact != "" && list.ResourceVersion != exact {
				t.Fatal("native exact Event snapshot or continuation refused; no fallback allowed")
			}
			rv = list.ResourceVersion
			rows = append(rows, list.Items...)
			token = list.Continue
			if token == "" {
				if len(rows) != 2 || page != 1 {
					t.Fatal("native Event snapshot omitted complete pagination")
				}
				return rows, rv
			}
		}
		t.Fatal("native Event snapshot exceeded bounded pagination")
		return nil, ""
	}
	coreSource := schema.GroupVersionResource{Version: "v1", Resource: "events"}
	aliasSource := schema.GroupVersionResource{Group: "events.k8s.io", Version: "v1", Resource: "events"}
	original, pin := collect(coreSource, "")
	changed := first.DeepCopy()
	changed.Count, changed.Labels["snapshot"] = 2, "updated"
	changed, err = client.CoreV1().Events(anchor.Namespace).Update(ctx, changed, metav1.UpdateOptions{})
	if err != nil || changed.UID != first.UID || changed.ResourceVersion == first.ResourceVersion {
		t.Fatal("owned Event update failed to establish a real intervening revision")
	}
	historical, _ := collect(aliasSource, pin)
	for index, old := range original {
		if !reflect.DeepEqual(fixtureGCMetadata(&old), fixtureGCMetadata(&historical[index])) || historical[index].Labels["snapshot"] != "original" {
			t.Fatal("exact Event alias snapshot changed membership or original metadata")
		}
	}
	fresh, _ := collect(aliasSource, "")
	seen := false
	for _, event := range fresh {
		if event.UID == first.UID {
			seen = true
			if event.ResourceVersion != changed.ResourceVersion || event.Labels["snapshot"] != "updated" {
				t.Fatal("fresh Event alias concealed the real update")
			}
		}
	}
	if !seen {
		t.Fatal("fresh Event alias omitted updated original")
	}
	var intervened atomic.Bool
	observing := rest.CopyConfig(config)
	observing.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return nativeEventSnapshotTransport{next: next, afterCoreEvents: func() {
			if intervened.Swap(true) {
				t.Error("native Event collection was unexpectedly replayed")
				return
			}
			update := changed.DeepCopy()
			update.Count, update.Labels["snapshot"] = 3, "gc-reader-update"
			if _, err := client.CoreV1().Events(anchor.Namespace).Update(ctx, update, metav1.UpdateOptions{}); err != nil {
				t.Error("GCReader intervening native Event update refused")
			}
		}}
	}
	reader, err := installobserve.NewGCReader(observing, journal, plan)
	if err != nil {
		t.Fatal("original production GCReader unavailable")
	}
	discovery, err := reader.Discover(ctx, anchor)
	if err != nil {
		t.Fatal("native production GC discovery refused")
	}
	observation, err := reader.Collect(ctx, discovery)
	if err != nil || observation == nil || !intervened.Load() {
		t.Fatal("production GCReader did not preserve one native exact Event snapshot", reader.DiagnosticStage())
	}
	aliases := map[string]int{}
	for _, row := range observation.Objects() {
		if row.Metadata.UID == changed.UID {
			if row.Source.Kind != "Event" || row.Source.GVR.Resource != "events" || row.Metadata.ResourceVersion != changed.ResourceVersion {
				t.Fatal("production GCReader normalized or changed original native Event metadata")
			}
			aliases[row.Source.GVR.Group]++
		}
	}
	if aliases[""] != 1 || aliases["events.k8s.io"] != 1 || len(aliases) != 2 {
		t.Fatal("production GCReader omitted an original native Event alias")
	}
}

type nativeEventSnapshotTransport struct {
	next            http.RoundTripper
	afterCoreEvents func()
}

func (transport nativeEventSnapshotTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.next.RoundTrip(request)
	if err == nil && response != nil && response.StatusCode == http.StatusOK && strings.HasPrefix(request.URL.Path, "/api/v1/namespaces/") && strings.HasSuffix(request.URL.Path, "/events") {
		transport.afterCoreEvents()
	}
	return response, err
}
