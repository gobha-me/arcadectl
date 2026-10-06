// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	clienttest "k8s.io/client-go/testing"
)

func fixturePlan(t *testing.T) *installrender.Plan {
	return fixturePlanProfile(t, "isolated-install", installrender.Profile135)
}

func fixturePlanProfile(t *testing.T, namespace, profile string) *installrender.Plan {
	t.Helper()
	images := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("a", 64), API: "registry.example/api@sha256:" + strings.Repeat("b", 64)}
	return fixturePlanImages(t, namespace, profile, images)
}

func fixturePlanImages(t *testing.T, namespace, profile string, images installpackage.Images) *installrender.Plan {
	t.Helper()
	payloads, crds, err := installrender.RenderPayloads(images, false)
	if err != nil {
		t.Fatal(err)
	}
	body, err := installpackage.Build(installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: strings.Repeat("c", 40), SourceEpoch: 1, Images: images, Profiles: installrender.SupportedProfiles(false), Prerequisites: installrender.RequiredPrerequisites(), CRDs: crds}, payloads)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)) // fake fixture key ONLY
	sig, err := installpackage.Sign(body, key)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := installpackage.Verify(body, sig, payloads, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := installrender.Compile(pkg, namespace, profile)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

type fixtureAccess struct {
	t               *testing.T
	namespace       string
	client          *fake.Clientset
	objects         map[installstate.Key]*unstructured.Unstructured
	writes, dryRuns int
	write           func(installstate.Action, installstate.Key, *unstructured.Unstructured) (*unstructured.Unstructured, error)
	get             func(installstate.Key) error
	dry             func(*unstructured.Unstructured) *unstructured.Unstructured
	deleteOptions   metav1.DeleteOptions
}

func (a *fixtureAccess) Get(ctx context.Context, key installstate.Key) (*unstructured.Unstructured, error) {
	if key.Kind == "Namespace" {
		n, err := a.client.CoreV1().Namespaces().Get(ctx, key.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		o, err := runtime.DefaultUnstructuredConverter.ToUnstructured(n)
		o["apiVersion"], o["kind"] = "v1", "Namespace"
		return &unstructured.Unstructured{Object: o}, err
	}
	if a.get != nil {
		if err := a.get(key); err != nil {
			return nil, err
		}
	}
	if o := a.objects[key]; o != nil {
		return o.DeepCopy(), nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Resource: key.Kind}, key.Name)
}
func (a *fixtureAccess) mutation(ctx context.Context, action installstate.Action, key installstate.Key, o *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	if dry {
		a.dryRuns++
		if a.dry != nil {
			return a.dry(o.DeepCopy()), nil
		}
		return o.DeepCopy(), nil
	}
	a.writes++
	n, err := a.client.CoreV1().Namespaces().Get(ctx, a.namespace, metav1.GetOptions{})
	if err != nil {
		a.t.Fatal(err)
	}
	var doc installstate.Document
	// The fixture can inspect public intent; no private body enters the journal.
	if err := json.Unmarshal([]byte(n.Annotations[installstate.Annotation]), &doc); err != nil {
		a.t.Fatal(err)
	}
	p := doc.Pending
	if p == nil || p.Action != action || p.Key != key {
		a.t.Fatal("effect sent without durable exact intent")
	}
	if o != nil && (p.CreateNonce != o.GetAnnotations()[installstate.MutationAnnotation] || action == installstate.Update && (p.BeforeUID != o.GetUID() || p.BeforeResourceVersion != o.GetResourceVersion())) {
		a.t.Fatal("effect differs from saved intent")
	}
	if a.write != nil {
		return a.write(action, key, o)
	}
	if action == installstate.Delete {
		delete(a.objects, key)
		return nil, nil
	}
	result := o.DeepCopy()
	if action == installstate.Create {
		result.SetUID(types.UID("original-" + key.Name))
	} else if a.objects[key].GetUID() != o.GetUID() || a.objects[key].GetResourceVersion() != o.GetResourceVersion() {
		return nil, apierrors.NewConflict(schema.GroupResource{Resource: key.Kind}, key.Name, ErrConcurrent)
	}
	result.SetResourceVersion(strconv.Itoa(a.writes + 100))
	a.objects[key] = result.DeepCopy()
	return result, nil
}
func (a *fixtureAccess) Create(ctx context.Context, k installstate.Key, o *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	return a.mutation(ctx, installstate.Create, k, o, dry)
}
func (a *fixtureAccess) Update(ctx context.Context, k installstate.Key, o *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	return a.mutation(ctx, installstate.Update, k, o, dry)
}
func (a *fixtureAccess) Delete(ctx context.Context, k installstate.Key, opts metav1.DeleteOptions) error {
	a.deleteOptions = opts
	_, err := a.mutation(ctx, installstate.Delete, k, nil, false)
	return err
}

type fixture struct {
	plan      *installrender.Plan
	engine    *Engine
	access    *fixtureAccess
	store     *installstate.Store
	snapshot  *installstate.Snapshot
	key       installstate.Key
	nsUpdates int
	nsUpdate  func(*corev1.Namespace) error
}

func newFixture(t *testing.T, installed bool) *fixture {
	return newFixtureWithPlans(t, installed, fixturePlan(t))
}

func newFixtureWithPlans(t *testing.T, installed bool, plans ...*installrender.Plan) *fixture {
	t.Helper()
	f := &fixture{plan: plans[0]}
	c, err := installcontract.New(f.plan)
	if err != nil {
		t.Fatal(err)
	}
	nsKey := namespaceKey(f.plan.Namespace())
	nsTemplate, _ := c.Template(nsKey, false)
	var nsObject *unstructured.Unstructured
	for _, r := range f.plan.Resources() {
		if r.Object.GetKind() == "Namespace" {
			nsObject = r.Object.DeepCopy()
		}
		if r.Object.GetKind() == "ServiceAccount" && f.key.Name == "" {
			f.key = installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: r.Object.GetNamespace(), Name: r.Object.GetName()}
		}
	}
	ns := &corev1.Namespace{}
	if runtime.DefaultUnstructuredConverter.FromUnstructured(nsObject.Object, ns) != nil {
		t.Fatal("namespace")
	}
	ns.UID, ns.ResourceVersion = "original-namespace", "1"
	ns.Labels["kubernetes.io/metadata.name"] = ns.Name
	ns.Spec.Finalizers = []corev1.FinalizerName{corev1.FinalizerKubernetes}
	doc := installstate.Document{Version: installstate.Version, InstallationID: strings.Repeat("a", 32), Namespace: ns.Name, NamespaceUID: ns.UID, ProfileID: f.plan.Profile().ID, Revision: 1, Mode: installstate.Install, Stage: installstate.Applying, TargetPackage: f.plan.Digest(), Resources: []installstate.Resource{{Key: nsKey, UID: ns.UID, TemplateSHA256: nsTemplate.Hash(), Retained: true, Phase: installrender.Anchors}}}
	objects := map[installstate.Key]*unstructured.Unstructured{}
	if installed {
		template, _ := c.Template(f.key, false)
		o, _ := template.Candidate(strings.Repeat("b", 32))
		o.SetUID("original-service-account")
		o.SetResourceVersion("42")
		objects[f.key] = o
		doc.Mode, doc.Installed, doc.ActivePackage = installstate.Uninstall, true, f.plan.Digest()
		doc.Resources = append(doc.Resources, installstate.Resource{Key: f.key, UID: o.GetUID(), TemplateSHA256: template.Hash(), Retained: false, Phase: template.Phase()})
	}
	installstate.SortResources(doc.Resources)
	body, err := installstate.Encode(doc, f.plan)
	if err != nil {
		t.Fatal(err)
	}
	if ns.Annotations == nil {
		ns.Annotations = map[string]string{}
	}
	ns.Annotations[installstate.Annotation], ns.Annotations[installstate.BootstrapAnnotation] = string(body), doc.InstallationID
	// This namespace-only journal seam uses GET/UPDATE, not SSA. Defaults,
	// original UID/RV conflicts, increments and defensive copies are supplied
	// explicitly below. The managed-field fake rebuilds the entire Kubernetes
	// REST mapper on every update; native fieldsets are tested with real HTTP/
	// API servers separately, never inferred from this object tracker.
	client := fake.NewSimpleClientset(ns)
	client.PrependReactor("update", "namespaces", func(action clienttest.Action) (bool, runtime.Object, error) {
		candidate := action.(clienttest.UpdateAction).GetObject().(*corev1.Namespace).DeepCopy()
		f.nsUpdates++
		if f.nsUpdate != nil {
			if err := f.nsUpdate(candidate); err != nil {
				return true, nil, err
			}
		}
		old, err := client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("namespaces"), "", candidate.Name)
		if err != nil {
			return true, nil, err
		}
		before := old.(*corev1.Namespace)
		if candidate.UID != before.UID || candidate.ResourceVersion != before.ResourceVersion {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "namespaces"}, candidate.Name, ErrConcurrent)
		}
		rv, _ := strconv.Atoi(before.ResourceVersion)
		candidate.ResourceVersion = strconv.Itoa(rv + 1)
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), candidate, ""); err != nil {
			return true, nil, err
		}
		return true, candidate.DeepCopy(), nil
	})
	f.access = &fixtureAccess{t: t, namespace: f.plan.Namespace(), client: client, objects: objects}
	f.store, err = installstate.New(client.CoreV1().Namespaces(), plans...)
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
	t.Cleanup(func() { _ = files.Close() })
	f.engine, err = NewWithAccess(f.access, f.store, files, plans...)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.Load(context.Background(), installstate.Anchor{Namespace: ns.Name, UID: ns.UID, InstallationID: doc.InstallationID})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCreateUpdateAndDeleteJournalBeforeEffects(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, false)
	s, err := f.engine.Apply(ctx, f.snapshot, f.key, f.plan.Digest(), false)
	if err != nil {
		t.Fatal(err)
	}
	if f.access.writes != 1 || f.access.dryRuns != 1 || f.nsUpdates != 2 || s.Document().Pending != nil || len(s.Document().Resources) != 2 {
		t.Fatal("unproved create settlement")
	}
	s, err = f.engine.Apply(ctx, s, f.key, f.plan.Digest(), false)
	if err != nil {
		t.Fatal(err)
	}
	if f.access.writes != 2 || s.Document().Resources[1].UID == "" {
		t.Fatal("update")
	}
	f = newFixture(t, true)
	s, err = f.engine.Delete(ctx, f.snapshot, f.key)
	if err != nil {
		t.Fatal(err)
	}
	opts := f.access.deleteOptions
	if opts.Preconditions == nil || *opts.Preconditions.UID != "original-service-account" || *opts.Preconditions.ResourceVersion != "42" || opts.PropagationPolicy == nil || *opts.PropagationPolicy != metav1.DeletePropagationForeground || len(s.Document().Resources) != 1 {
		t.Fatal("missing original UID/RV delete guards")
	}
}

func TestLostCreateResponseIsCorrelatedButNeverReplayed(t *testing.T) {
	for _, effect := range []bool{false, true} {
		t.Run(fmt.Sprint(effect), func(t *testing.T) {
			f := newFixture(t, false)
			f.access.write = func(_ installstate.Action, k installstate.Key, o *unstructured.Unstructured) (*unstructured.Unstructured, error) {
				if effect {
					live := o.DeepCopy()
					live.SetUID("original-lost-create")
					live.SetResourceVersion("111")
					f.access.objects[k] = live
				}
				return nil, errors.New("PRIVATE-ERROR-CANARY")
			}
			s, err := f.engine.Apply(context.Background(), f.snapshot, f.key, f.plan.Digest(), false)
			if effect {
				if err != nil || s.Document().Pending != nil {
					t.Fatal("lost success not correlated")
				}
			} else {
				if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil || strings.Contains(err.Error(), "CANARY") {
					t.Fatal("uncertain absence not retained")
				}
				for i := 0; i < 3; i++ {
					if _, err := f.engine.Recover(context.Background(), s); !errors.Is(err, ErrOutcomeUnknown) {
						t.Fatal("absence must not replay")
					}
				}
				if _, err := f.engine.Apply(context.Background(), s, f.key, f.plan.Digest(), false); !errors.Is(err, ErrInvalid) {
					t.Fatal("pending overwritten")
				}
			}
			if f.access.writes != 1 || f.access.dryRuns != 1 {
				t.Fatal("effect or dry-run replayed")
			}
		})
	}
}

func definitiveCreateErrors() []error {
	gr := schema.GroupResource{Resource: "reviewed"}
	return []error{
		apierrors.NewAlreadyExists(gr, "reviewed"),
		apierrors.NewConflict(gr, "reviewed", ErrConcurrent),
		apierrors.NewForbidden(gr, "reviewed", ErrOwnership),
		apierrors.NewUnauthorized("fixed rejection"),
		apierrors.NewInvalid(schema.GroupKind{Kind: "ServiceAccount"}, "reviewed", nil),
		apierrors.NewBadRequest("fixed rejection"),
		apierrors.NewNotFound(gr, "reviewed"),
		apierrors.NewTooManyRequests("fixed rejection", 0),
		apierrors.NewMethodNotSupported(gr, "create"),
		apierrors.NewRequestEntityTooLargeError("fixed rejection"),
		&apierrors.StatusError{ErrStatus: metav1.Status{Status: metav1.StatusFailure, Code: 415, Reason: metav1.StatusReasonUnsupportedMediaType, Message: "fixed rejection"}},
		ErrOwnership, ErrInvalid, ErrConcurrent,
	}
}

func TestDefiniteCreateRejectionNeverAdoptsRacedCopiedNonce(t *testing.T) {
	for _, rejection := range definitiveCreateErrors() {
		t.Run(rejection.Error(), func(t *testing.T) {
			f := newFixture(t, false)
			f.access.write = func(_ installstate.Action, k installstate.Key, o *unstructured.Unstructured) (*unstructured.Unstructured, error) {
				foreign := o.DeepCopy()
				foreign.SetUID("foreign-copied-nonce")
				foreign.SetResourceVersion("100")
				f.access.objects[k] = foreign
				return nil, rejection
			}
			s, err := f.engine.Apply(context.Background(), f.snapshot, f.key, f.plan.Digest(), false)
			if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil || len(s.Document().Resources) != 1 {
				t.Fatal("definitely rejected Create adopted a raced object")
			}
			if _, err := f.engine.Recover(context.Background(), s); !errors.Is(err, ErrOutcomeUnknown) || f.access.writes != 1 || f.access.dryRuns != 1 {
				t.Fatal("restart adopted or replayed rejected Create")
			}
		})
	}
}

func TestReadbackMustMatchOriginalNonceUIDAndSignedShape(t *testing.T) {
	for _, scenario := range []string{"nonce", "shape", "ack-uid", "read-failure", "namespace-race"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, false)
			f.access.write = func(_ installstate.Action, k installstate.Key, o *unstructured.Unstructured) (*unstructured.Unstructured, error) {
				live := o.DeepCopy()
				live.SetUID("original-created")
				live.SetResourceVersion("111")
				ack := live.DeepCopy()
				switch scenario {
				case "nonce":
					a := live.GetAnnotations()
					a[installstate.MutationAnnotation] = strings.Repeat("d", 32)
					live.SetAnnotations(a)
				case "shape":
					live.Object["automountServiceAccountToken"] = false
				case "ack-uid":
					ack.SetUID("foreign-ack")
				case "read-failure":
					f.access.get = func(installstate.Key) error { return errors.New("PRIVATE-CANARY") }
				case "namespace-race":
					n, _ := f.access.client.CoreV1().Namespaces().Get(context.Background(), f.plan.Namespace(), metav1.GetOptions{})
					n.ResourceVersion = "999"
					_ = f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), n, "")
				}
				f.access.objects[k] = live
				return ack, nil
			}
			s, err := f.engine.Apply(context.Background(), f.snapshot, f.key, f.plan.Digest(), false)
			if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil || f.access.writes != 1 {
				t.Fatal("invalid readback settled")
			}
			if _, err := f.engine.Recover(context.Background(), s); !errors.Is(err, ErrOutcomeUnknown) || f.access.writes != 1 {
				t.Fatal("resume adopted drift/replacement")
			}
		})
	}
}

func TestCreateUIDReceiptSurvivesRestartAndRefusesCopiedNonceReplacement(t *testing.T) {
	f := newFixture(t, false)
	f.nsUpdate = func(*corev1.Namespace) error {
		if f.nsUpdates == 2 {
			return errors.New("PRIVATE-CANARY")
		}
		return nil
	}
	s, err := f.engine.Apply(context.Background(), f.snapshot, f.key, f.plan.Digest(), false)
	if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil {
		t.Fatal("fixture did not retain pending")
	}
	uid, err := f.engine.loadCreateUID(s.Document())
	if err != nil || uid != f.access.objects[f.key].GetUID() {
		t.Fatal("original UID was not durably pinned")
	}
	// Reconstruct the engine and explicitly reload the original Namespace.
	restarted, err := NewWithAccess(f.access, f.store, f.engine.files, f.plan)
	if err != nil {
		t.Fatal(err)
	}
	s, err = f.store.Load(context.Background(), s.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	f.access.objects[f.key].SetUID("foreign-copied-nonce-replacement")
	if _, err := restarted.Recover(context.Background(), s); !errors.Is(err, ErrOutcomeUnknown) || f.access.writes != 1 {
		t.Fatal("restart adopted copied nonce replacement")
	}
	f.access.objects[f.key].SetUID(uid)
	s, err = restarted.Recover(context.Background(), s)
	if err != nil || s.Document().Pending != nil || f.access.writes != 1 {
		t.Fatal("restart did not observe-settle original UID")
	}
}

func TestMissingCreateUIDEvidenceAndUnavailablePrivateStorageFailClosed(t *testing.T) {
	t.Run("lost response and delayed create", func(t *testing.T) {
		f := newFixture(t, false)
		var delayed *unstructured.Unstructured
		f.access.write = func(_ installstate.Action, _ installstate.Key, o *unstructured.Unstructured) (*unstructured.Unstructured, error) {
			delayed = o.DeepCopy()
			delayed.SetUID("delayed-original")
			delayed.SetResourceVersion("101")
			return nil, ErrRead
		}
		s, err := f.engine.Apply(context.Background(), f.snapshot, f.key, f.plan.Digest(), false)
		if !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatal(err)
		}
		f.access.objects[f.key] = delayed
		if _, err := f.engine.Recover(context.Background(), s); !errors.Is(err, ErrOutcomeUnknown) || f.access.writes != 1 {
			t.Fatal("missing UID receipt inferred by nonce")
		}
	})
	t.Run("private store closed before effect", func(t *testing.T) {
		f := newFixture(t, false)
		_ = f.engine.files.Close()
		s, err := f.engine.Apply(context.Background(), f.snapshot, f.key, f.plan.Digest(), false)
		// The fixture fence now needs safe private storage before even journal
		// intent. Unreadability must refuse earlier, not create a pending effect.
		if err != ErrFixtures || s != nil || f.access.writes != 0 || f.nsUpdates != 0 {
			t.Fatal("unavailable private storage permitted an effect or journal intent")
		}
		fresh, err := f.store.Load(context.Background(), f.snapshot.Anchor())
		if err != nil || fresh.ResourceVersion() != f.snapshot.ResourceVersion() || !bytes.Equal(fresh.Bytes(), f.snapshot.Bytes()) {
			t.Fatal("private-storage refusal changed the original journal")
		}
	})
}

func TestRecoverRejectsSchemaValidButUnauthorizedIntent(t *testing.T) {
	for _, scenario := range []string{"wrong-hash", "wrong-stage", "uninstall-create"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, scenario == "uninstall-create")
			if scenario == "wrong-stage" {
				d := f.snapshot.Document()
				d.Revision++
				d.Stage = installstate.Verifying
				var err error
				f.snapshot, err = f.store.Commit(context.Background(), f.snapshot, d)
				if err != nil {
					t.Fatal(err)
				}
			}
			d := f.snapshot.Document()
			key := f.key
			if scenario == "uninstall-create" {
				for k := range f.engine.templates {
					if k.Kind == "Role" {
						key = k
						break
					}
				}
			}
			target, _ := f.engine.contracts[f.plan.Digest()].Template(key, false)
			after := target.Hash()
			if scenario == "wrong-hash" {
				after = strings.Repeat("f", 64)
			}
			d.Revision++
			d.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("d", 32), AfterSHA256: after}
			s, err := f.store.Commit(context.Background(), f.snapshot, d)
			if err != nil {
				t.Fatal("fixture journal must be schema-valid: ", err)
			}
			if _, err := f.engine.Recover(context.Background(), s); !errors.Is(err, ErrInvalid) || f.access.writes != 0 || f.access.dryRuns != 0 {
				t.Fatal("schema-valid intent authorized wrong contract")
			}
		})
	}
}

func TestLostUpdateResponseNeverReplaysAndGuardsBeforeUIDRV(t *testing.T) {
	for _, scenario := range []string{"committed", "unchanged", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, false)
			s, err := f.engine.Apply(context.Background(), f.snapshot, f.key, f.plan.Digest(), false)
			if err != nil {
				t.Fatal(err)
			}
			f.access.write = func(_ installstate.Action, k installstate.Key, o *unstructured.Unstructured) (*unstructured.Unstructured, error) {
				if scenario != "unchanged" {
					live := o.DeepCopy()
					live.SetResourceVersion("999")
					if scenario == "replacement" {
						live.SetUID("foreign-replacement")
					}
					f.access.objects[k] = live
				}
				return nil, ErrRead
			}
			s, err = f.engine.Apply(context.Background(), s, f.key, f.plan.Digest(), false)
			if scenario == "committed" {
				if err != nil || s.Document().Pending != nil {
					t.Fatal("committed lost update not correlated")
				}
			} else {
				if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil {
					t.Fatal("unknown update was settled")
				}
				if _, err := f.engine.Recover(context.Background(), s); !errors.Is(err, ErrOutcomeUnknown) {
					t.Fatal("unknown update replayed/adopted")
				}
			}
			if f.access.writes != 2 {
				t.Fatal("update replayed")
			}
		})
	}
}

func TestIntentFailureSendsNoTargetWrite(t *testing.T) {
	for _, kind := range []string{"conflict", "lost"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, false)
			f.nsUpdate = func(*corev1.Namespace) error {
				if kind == "conflict" {
					return apierrors.NewConflict(schema.GroupResource{Resource: "namespaces"}, f.plan.Namespace(), ErrConcurrent)
				}
				return errors.New("PRIVATE-CANARY")
			}
			if _, err := f.engine.Apply(context.Background(), f.snapshot, f.key, f.plan.Digest(), false); err == nil {
				t.Fatal("unconfirmed journal accepted")
			}
			if f.access.writes != 0 || f.nsUpdates != 1 {
				t.Fatal("effect without proved journal")
			}
		})
	}
}

func TestLostSettlementResumesByObservationOnly(t *testing.T) {
	f := newFixture(t, false)
	f.nsUpdate = func(*corev1.Namespace) error {
		if f.nsUpdates == 2 {
			return errors.New("PRIVATE-CANARY")
		}
		return nil
	}
	s, err := f.engine.Apply(context.Background(), f.snapshot, f.key, f.plan.Digest(), false)
	if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil {
		t.Fatal("lost settlement")
	}
	s, err = f.engine.Recover(context.Background(), s)
	if err != nil || s.Document().Pending != nil || f.access.writes != 1 || f.access.dryRuns != 1 {
		t.Fatal("resume replayed effect")
	}
}

func TestDeleteAcceptanceWaitsForAbsenceAndRefusesReplacement(t *testing.T) {
	for _, scenario := range []string{"deleting", "replacement", "lost-no-effect"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, true)
			f.access.write = func(_ installstate.Action, k installstate.Key, _ *unstructured.Unstructured) (*unstructured.Unstructured, error) {
				switch scenario {
				case "deleting":
					now := metav1.Now()
					f.access.objects[k].SetDeletionTimestamp(&now)
				case "replacement":
					f.access.objects[k].SetUID("foreign-replacement")
				case "lost-no-effect":
					return nil, errors.New("PRIVATE-CANARY")
				}
				return nil, nil
			}
			s, err := f.engine.Delete(context.Background(), f.snapshot, f.key)
			if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil {
				t.Fatal("delete accepted as absence")
			}
			if _, err := f.engine.Recover(context.Background(), s); !errors.Is(err, ErrOutcomeUnknown) || f.access.writes != 1 {
				t.Fatal("delete replayed/adopted replacement")
			}
			delete(f.access.objects, f.key)
			s, err = f.engine.Recover(context.Background(), s)
			if err != nil || len(s.Document().Resources) != 1 || f.access.writes != 1 {
				t.Fatal("absence not settled by observation")
			}
		})
	}
}

func TestForeignDriftRetainedAndWrongStageRefusedBeforeIntent(t *testing.T) {
	for _, scenario := range []string{"foreign", "dry-drift", "dry-nonce", "namespace-drift", "retained-delete", "wrong-stage", "namespace-effect", "secret-effect"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, false)
			key := f.key
			deleteRequest := false
			switch scenario {
			case "foreign":
				o := &unstructured.Unstructured{}
				o.SetUID("foreign")
				f.access.objects[key] = o
			case "dry-drift":
				f.access.dry = func(o *unstructured.Unstructured) *unstructured.Unstructured {
					o.Object["automountServiceAccountToken"] = false
					return o
				}
			case "dry-nonce":
				f.access.dry = func(o *unstructured.Unstructured) *unstructured.Unstructured {
					o.SetAnnotations(map[string]string{installstate.MutationAnnotation: strings.Repeat("d", 32)})
					return o
				}
			case "namespace-drift":
				n, _ := f.access.client.CoreV1().Namespaces().Get(context.Background(), f.plan.Namespace(), metav1.GetOptions{})
				n.Labels["unsigned"] = "true"
				_ = f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), n, "")
			case "retained-delete":
				key = namespaceKey(f.plan.Namespace())
				deleteRequest = true
			case "wrong-stage":
				d := f.snapshot.Document()
				d.Stage = installstate.Verifying
				d.Revision++
				var err error
				f.snapshot, err = f.store.Commit(context.Background(), f.snapshot, d)
				if err != nil {
					t.Fatal(err)
				}
				f.nsUpdates = 0
			case "namespace-effect":
				key = namespaceKey(f.plan.Namespace())
			case "secret-effect":
				key = installstate.Key{APIVersion: "v1", Kind: "Secret", Namespace: f.plan.Namespace(), Name: "arcadectl-api-tls"}
			}
			var err error
			if deleteRequest {
				_, err = f.engine.Delete(context.Background(), f.snapshot, key)
			} else {
				_, err = f.engine.Apply(context.Background(), f.snapshot, key, f.plan.Digest(), false)
			}
			if err == nil || f.access.writes != 0 || f.nsUpdates != 0 {
				t.Fatal("unsafe request reached intent/effect")
			}
		})
	}
}
