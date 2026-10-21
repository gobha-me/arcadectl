// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

type recoveryFixture struct {
	privateDir     string
	reporter       *RecoveryReporter
	receipt        *installstate.BootstrapReceipt
	ns             *corev1.Namespace
	lists          int
	namespaceReads int
	claims         []corev1.PersistentVolumeClaim
	beforeRead     func(*recoveryFixture, *http.Request)
}

// Mock HTTP cluster plus the actual private bootstrap workflow. Bootstrap is
// setup only; report collection permits GETs for the original Namespace/PVCs
// and no other request. This is not a complete installer lifecycle proof.
func newRecoveryFixture(t *testing.T) *recoveryFixture {
	return newRecoveryFixtureRouting(t, false)
}

func newRecoveryFixtureRouting(t *testing.T, direct bool) *recoveryFixture {
	t.Helper()
	plan := fixturePlan(t)
	privateDir := t.TempDir()
	if err := os.Chmod(privateDir, 0700); err != nil {
		t.Fatal(err)
	}
	files, err := privatefs.Open(privateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = files.Close() })
	receipt, err := installstate.PrepareBootstrap(files, "recovery-bootstrap.json", plan)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientset()
	client.PrependReactor("create", "namespaces", func(a clienttesting.Action) (bool, runtime.Object, error) {
		ns := a.(clienttesting.CreateAction).GetObject().(*corev1.Namespace).DeepCopy()
		ns.UID, ns.ResourceVersion = "original-recovery-namespace", "1"
		ns.Labels["kubernetes.io/metadata.name"] = ns.Name
		ns.Spec.Finalizers = []corev1.FinalizerName{corev1.FinalizerKubernetes}
		if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, ""); err != nil {
			return true, nil, err
		}
		return true, ns, nil
	})
	client.PrependReactor("update", "namespaces", func(a clienttesting.Action) (bool, runtime.Object, error) {
		ns := a.(clienttesting.UpdateAction).GetObject().(*corev1.Namespace).DeepCopy()
		ns.ResourceVersion += "1"
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, ""); err != nil {
			return true, nil, err
		}
		return true, ns, nil
	})
	s, err := receipt.EnsureNamespace(context.Background(), client.CoreV1().Namespaces())
	if err != nil {
		t.Fatal("original test bootstrap failed", err)
	}
	ns, err := client.CoreV1().Namespaces().Get(context.Background(), s.Anchor().Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ns.APIVersion, ns.Kind = "v1", "Namespace"
	x := &recoveryFixture{privateDir: privateDir, receipt: receipt, ns: ns, claims: []corev1.PersistentVolumeClaim{{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"},
		ObjectMeta: metav1.ObjectMeta{Name: "unlabeled-world", Namespace: ns.Name, UID: "world-uid", ResourceVersion: "11",
			Annotations: map[string]string{"private.example/note": "PRIVATE-CANARY"}, Labels: map[string]string{"private.example/label": "PRIVATE-CANARY"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "missing-owner", UID: "PRIVATE-CANARY"}}},
		Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "retained-pv"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}}}
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodGet {
			t.Error("recovery report attempted a mutation")
			w.WriteHeader(500)
			return
		}
		if x.beforeRead != nil {
			x.beforeRead(x, r)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/namespaces/" + ns.Name:
			x.namespaceReads++
			_ = json.NewEncoder(w).Encode(x.ns)
		case "/api/v1/namespaces/" + ns.Name + "/persistentvolumeclaims":
			q := r.URL.Query()
			if q.Get("limit") != "128" || q.Get("labelSelector") != "" || q.Get("fieldSelector") != "" || q.Get("resourceVersion") != "" {
				t.Error("filtered/unbounded claims request")
			}
			x.lists++
			_ = json.NewEncoder(w).Encode(&corev1.PersistentVolumeClaimList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaimList"},
				ListMeta: metav1.ListMeta{ResourceVersion: strconv.Itoa(100 + x.lists)}, Items: x.claims})
		default:
			t.Error("recovery tried unrelated resource, Secret, discovery or owner lookup", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(server.Close)
	constructor := NewHTTPAccess
	if direct {
		constructor = NewDirectHTTPAccess
	}
	access, err := constructor(serverConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	store, err := installstate.New(access.Namespaces(), plan)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewWithAccess(access, store, files, plan)
	if err != nil {
		t.Fatal(err)
	}
	x.reporter, err = NewRecoveryReporter(engine, access)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestRecoveryReportAllowsListRevisionChurnAndRedactsPrivateMetadata(t *testing.T) {
	x := newRecoveryFixture(t)
	before, id, err := x.reporter.engine.files.Read("recovery-bootstrap.json", installstate.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(x.privateDir)
	if err != nil {
		t.Fatal(err)
	}
	report, err := x.reporter.Collect(context.Background(), x.receipt)
	if err != nil || report == nil {
		t.Fatal("current recovery report failed", err)
	}
	if x.lists != 2 || bytes.Contains(report.Bytes(), []byte("PRIVATE-CANARY")) {
		t.Fatal("incomplete enumeration or private metadata exposure")
	}
	var public recoveryDocument
	if json.Unmarshal(report.Bytes(), &public) != nil || len(public.Claims) != 1 || public.Claims[0].UID != "world-uid" || public.ClaimsResourceVersion != "102" || public.NamespaceUID != x.ns.UID || len(public.Guidance) < 3 {
		t.Fatal("recovery report lost original identities/guidance")
	}
	copy := report.Bytes()
	copy[0] = 'x'
	if report.Bytes()[0] != '{' {
		t.Fatal("mutable report accessor")
	}
	var absent *RecoveryReport
	if absent.Bytes() != nil {
		t.Fatal("nil report produced output")
	}
	after, afterID, err := x.reporter.engine.files.Read("recovery-bootstrap.json", installstate.MaxBytes)
	if err != nil || id != afterID || !bytes.Equal(before, after) {
		t.Fatal("recovery modified protected receipt")
	}
	afterEntries, err := os.ReadDir(x.privateDir)
	if err != nil || len(afterEntries) != len(entries) {
		t.Fatal("recovery created private state")
	}
}

func TestRecoveryReportShowsSeparateBaselinePendingWithoutPrivateEvidence(t *testing.T) {
	x := newRecoveryFixtureRouting(t, true)
	engine, access := x.reporter.engine, x.reporter.access
	var plan *installrender.Plan
	for _, registered := range engine.plans {
		plan = registered
	}
	baseline := baselineFixturePlan(t, plan.Namespace(), plan.Profile().ID, 'd')
	document, err := installstate.Decode([]byte(x.ns.Annotations[installstate.Annotation]), plan)
	if err != nil {
		t.Fatal("original recovery fixture journal unavailable")
	}
	document.SecurityBaseline, err = installstate.PinnedSecurityBaseline(baseline)
	if err != nil {
		t.Fatal("baseline recovery pin unavailable")
	}
	resource := baseline.Resources()[0]
	document.SecurityBaseline.Stage = installstate.BaselineApplying
	document.SecurityBaseline.Pending = &installstate.Pending{Action: installstate.Create, Key: installstate.Key{APIVersion: resource.Object.GetAPIVersion(), Kind: resource.Object.GetKind(), Name: resource.Object.GetName()}, CreateNonce: strings.Repeat("b", 32), AfterSHA256: resource.TemplateSHA256}
	body, err := installstate.EncodeWithBaseline(document, baseline, plan)
	if err != nil {
		t.Fatal("baseline recovery encoding failed")
	}
	x.ns.Annotations[installstate.Annotation] = string(body)
	store, err := installstate.NewWithBaseline(access.Namespaces(), baseline, plan)
	if err != nil {
		t.Fatal("baseline recovery store unavailable")
	}
	engine, err = NewWithBaselineAccess(access, store, engine.files, baseline, plan)
	if err != nil {
		t.Fatal("baseline recovery engine unavailable")
	}
	x.reporter, err = NewRecoveryReporter(engine, access)
	if err != nil {
		t.Fatal("baseline recovery reporter unavailable")
	}
	// Original historical receipt remains byte-exact, loaded with explicit
	// baseline context only to READ its pinned identity; it cannot bootstrap.
	x.receipt, err = installstate.LoadBootstrapWithBaseline(engine.files, "recovery-bootstrap.json", plan, baseline)
	if err != nil {
		t.Fatal("original legacy receipt unavailable for read-only recovery")
	}
	report, err := x.reporter.Collect(t.Context(), x.receipt)
	if err != nil {
		t.Fatal("baseline recovery report refused")
	}
	var public recoveryDocument
	if json.Unmarshal(report.Bytes(), &public) != nil || public.Pending != nil || public.SecurityBaseline == nil || public.SecurityBaseline.Pending == nil || public.SecurityBaseline.OwnershipStage != installstate.BaselineApplying || public.SecurityBaseline.ArtifactDigest != baseline.Digest() || public.SecurityBaseline.OriginalResourceCount != 0 || public.SecurityBaseline.Pending.Key != document.SecurityBaseline.Pending.Key {
		t.Fatal("separate pending baseline evidence was omitted or mislabeled")
	}
	for _, private := range []string{"PRIVATE-CANARY", document.SecurityBaseline.Pending.CreateNonce, document.SecurityBaseline.Pending.AfterSHA256, x.privateDir} {
		if bytes.Contains(report.Bytes(), []byte(private)) {
			t.Fatal("baseline recovery output leaked non-allowlisted evidence")
		}
	}
	if !bytes.Equal([]byte(x.ns.Annotations[installstate.Annotation]), body) {
		t.Fatal("read-only baseline recovery mutated journal")
	}
}

func TestRecoveryReportRefusesDriftAndIncompleteReads(t *testing.T) {
	for _, fault := range []string{"claim-uid", "claim-rv", "claim-shape", "claim-membership", "namespace-uid", "namespace-shape", "journal-rv", "receipt-missing", "receipt-late", "unknown-phase", "cancelled", "nil-context"} {
		t.Run(fault, func(t *testing.T) {
			x := newRecoveryFixture(t)
			ctx := context.Background()
			if fault == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if fault == "nil-context" {
				ctx = nil
			}
			if fault == "receipt-missing" {
				if err := os.Remove(x.privateDir + "/recovery-bootstrap.json"); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "unknown-phase" {
				x.claims[0].Status.Phase = "PRIVATE-CANARY"
			}
			x.beforeRead = func(x *recoveryFixture, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/persistentvolumeclaims") && x.lists == 1 {
					switch fault {
					case "claim-uid":
						x.claims[0].UID = "replacement"
					case "claim-rv":
						x.claims[0].ResourceVersion = "12"
					case "claim-shape":
						x.claims[0].Annotations["new"] = "PRIVATE-CANARY"
					case "claim-membership":
						x.claims = nil
					case "receipt-late":
						if err := os.Remove(x.privateDir + "/recovery-bootstrap.json"); err != nil {
							t.Error(err)
						}
					}
				}
				if x.lists == 1 && r.URL.Path == "/api/v1/namespaces/"+x.ns.Name {
					switch fault {
					case "namespace-uid":
						x.ns.UID = "replacement"
					case "namespace-shape":
						x.ns.Labels["pod-security.kubernetes.io/enforce"] = "privileged"
					case "journal-rv":
						x.ns.ResourceVersion = "2"
					}
				}
			}
			report, err := x.reporter.Collect(ctx, x.receipt)
			if err == nil || report != nil || strings.Contains(err.Error(), "PRIVATE-CANARY") {
				t.Fatal("unproved recovery became public output")
			}
		})
	}
}

// Construct completed public state only, with no resource effects or claimed
// uninstall certification. Neither removed workloads nor surviving identities
// are consulted by reporting, and mutation compatibility remains unchanged.
func TestRecoveryReportCompletedUninstallAndPendingIntent(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "completed-uninstall"}[completed], func(t *testing.T) {
			x := newRecoveryFixture(t)
			anchor, err := x.receipt.PinnedAnchor(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			s, err := x.reporter.engine.journal.Load(context.Background(), anchor)
			if err != nil {
				t.Fatal(err)
			}
			d := s.Document()
			plan := x.reporter.engine.plans[d.TargetPackage]
			if completed {
				d.Mode, d.Stage, d.Installed, d.ActivePackage = installstate.Uninstall, installstate.Complete, false, d.TargetPackage
				d.Resources = nil
				for _, resource := range plan.Resources() {
					if !resource.Retained {
						continue
					}
					o := resource.Object
					key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
					template, err := x.reporter.engine.contracts[d.TargetPackage].Template(key, false)
					if err != nil {
						t.Fatal(err)
					}
					uid := types.UID("retained-" + o.GetKind() + "-" + o.GetName())
					if o.GetKind() == "Namespace" {
						uid = anchor.UID
					}
					d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: uid, TemplateSHA256: template.Hash(), Retained: true, Phase: resource.Phase})
				}
				for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
					d.Resources = append(d.Resources, installstate.Resource{Key: secretKey(d.Namespace, name), UID: types.UID("retained-" + name), Retained: true, Phase: installrender.API})
				}
				installstate.SortResources(d.Resources)
				if x.reporter.engine.compatible(d) {
					t.Fatal("completed uninstall unexpectedly became mutation-compatible")
				}
			} else {
				d.Stage = installstate.RecoveryRequired
				key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: d.Namespace, Name: "arcadectl-controller"}
				template, err := x.reporter.engine.contracts[d.TargetPackage].Template(key, false)
				if err != nil {
					t.Fatal(err)
				}
				d.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("b", 32), AfterSHA256: template.Hash()}
			}
			body, err := installstate.Encode(d, plan)
			if err != nil {
				t.Fatal(err)
			}
			x.ns.Annotations[installstate.Annotation] = string(body)
			report, err := x.reporter.Collect(context.Background(), x.receipt)
			if err != nil {
				t.Fatal(err)
			}
			var public recoveryDocument
			if json.Unmarshal(report.Bytes(), &public) != nil || public.Mode != d.Mode || public.Stage != d.Stage || len(public.Claims) != 1 {
				t.Fatal("retained recovery lost current identities")
			}
			if !completed && (public.Pending == nil || public.Pending.Action != installstate.Create || public.Pending.Key != d.Pending.Key || bytes.Contains(report.Bytes(), []byte(d.Pending.CreateNonce))) {
				t.Fatal("pending intent was lost or candidate nonce exposed")
			}
		})
	}
}

func TestRecoveryReportOriginalBootstrapMayPredateRegisteredPackages(t *testing.T) {
	x := newRecoveryFixture(t)
	anchor, err := x.receipt.PinnedAnchor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s, err := x.reporter.engine.journal.Load(context.Background(), anchor)
	if err != nil {
		t.Fatal(err)
	}
	d := s.Document()
	plans := []*installrender.Plan{}
	for _, digit := range []string{"d", "e", "f"} {
		plans = append(plans, fixturePlanImages(t, d.Namespace, d.ProfileID, installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("a", 64), API: "registry.example/api@sha256:" + strings.Repeat(digit, 64)}))
	}
	d.TargetPackage = plans[0].Digest()
	body, err := installstate.Encode(d, plans...)
	if err != nil {
		t.Fatal(err)
	}
	x.ns.Annotations[installstate.Annotation] = string(body)
	store, err := installstate.New(x.reporter.access.Namespaces(), plans...)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewWithAccess(x.reporter.access, store, x.reporter.engine.files, plans...)
	if err != nil {
		t.Fatal(err)
	}
	x.reporter, err = NewRecoveryReporter(engine, x.reporter.access)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installstate.LoadBootstrap(engine.files, "recovery-bootstrap.json", plans[0]); err == nil {
		t.Fatal("original bootstrap retied to current package")
	}
	report, err := x.reporter.Collect(context.Background(), x.receipt)
	if err != nil || report == nil {
		t.Fatal("original bootstrap could not report current package", err)
	}
}

func TestRecoveryReporterRejectsForeignAccessAndNilInputs(t *testing.T) {
	x := newRecoveryFixture(t)
	for _, access := range []*HTTPAccess{nil, {frozen: x.reporter.access.frozen}} {
		if reporter, err := NewRecoveryReporter(x.reporter.engine, access); err == nil || reporter != nil {
			t.Fatal("foreign access became a closed reporter")
		}
	}
	if reporter, err := NewRecoveryReporter(nil, x.reporter.access); err == nil || reporter != nil {
		t.Fatal("nil engine became reporter")
	}
	if report, err := x.reporter.Collect(context.Background(), nil); err == nil || report != nil {
		t.Fatal("nil receipt became report")
	}
	var nilReporter *RecoveryReporter
	if report, err := nilReporter.Collect(context.Background(), x.receipt); err == nil || report != nil {
		t.Fatal("nil reporter became report")
	}
}
