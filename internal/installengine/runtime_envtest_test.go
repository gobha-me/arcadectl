//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type lostResponseAccess struct {
	*HTTPAccess
	key            installstate.Key
	writes         int
	failRead       bool
	responseKey    installstate.Key
	responseWrites int
}

func (a *lostResponseAccess) Get(ctx context.Context, k installstate.Key) (*unstructured.Unstructured, error) {
	if a.failRead && k == a.key {
		a.failRead = false
		return nil, ErrRead
	}
	return a.HTTPAccess.Get(ctx, k)
}
func (a *lostResponseAccess) Create(ctx context.Context, k installstate.Key, o *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	result, err := a.HTTPAccess.Create(ctx, k, o, dry)
	if k == a.responseKey && !dry && err == nil {
		a.responseWrites++
		return nil, ErrRead
	}
	if k == a.key && !dry {
		a.writes++
		if err == nil {
			a.failRead = true
			return result, nil
		}
	}
	return result, err
}

// This proves actual journal CAS, real public writes, signed default checks and
// lost-response and unavailable-readback recovery against a fresh isolated API
// server. It runs no Pods, credential activation, actual predecessor binaries
// or lifecycle uninstall.
func TestEnvtestJournaledResourceEffects(t *testing.T) {
	environment := &envtest.Environment{DownloadBinaryAssets: true, DownloadBinaryAssetsVersion: "1.37.0", DownloadBinaryAssetsIndexURL: "https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/1031496fc98a4f51010c3bdfdeb57b5d67bea7bd/envtest-releases.yaml", BinaryAssetsDirectory: t.TempDir(), ControlPlaneStartTimeout: 90 * time.Second, ControlPlaneStopTimeout: 30 * time.Second}
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
	plan := fixturePlanProfile(t, installrender.DefaultNamespace, installrender.Profile137)
	access, err := NewHTTPAccess(config)
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
	receipt, err := installstate.PrepareBootstrap(files, "bootstrap.json", plan)
	if err != nil {
		t.Fatal(err)
	}
	s, err := receipt.EnsureNamespace(ctx, access.Namespaces())
	if err != nil {
		t.Fatal("single-attempt namespace bootstrap: ", err)
	}
	store, err := installstate.New(access.Namespaces(), plan)
	if err != nil {
		t.Fatal(err)
	}
	s, err = store.Load(ctx, s.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	d := s.Document()
	d.Revision++
	d.Stage = installstate.Applying
	s, err = store.Commit(ctx, s, d)
	if err != nil {
		t.Fatal("single-attempt journal stage CAS: ", err)
	}
	lost := &lostResponseAccess{HTTPAccess: access}
	for _, r := range plan.Resources() {
		if r.Object.GetKind() == "ServiceAccount" {
			lost.key = installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: r.Object.GetNamespace(), Name: r.Object.GetName()}
			break
		}
	}
	for _, r := range plan.Resources() {
		if r.Object.GetKind() == "Role" {
			lost.responseKey = installstate.Key{APIVersion: r.Object.GetAPIVersion(), Kind: "Role", Namespace: r.Object.GetNamespace(), Name: r.Object.GetName()}
			break
		}
	}
	engine, err := NewWithAccess(lost, store, files, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range plan.Resources() {
		o := r.Object
		if o.GetKind() == "Namespace" {
			continue
		}
		key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
		s, err = engine.Apply(ctx, s, key, plan.Digest(), false)
		if key == lost.key {
			if !errors.Is(err, ErrOutcomeUnknown) || s == nil || s.Document().Pending == nil || lost.writes != 1 {
				t.Fatal("unavailable real readback not retained")
			}
			s, err = engine.Recover(ctx, s)
			if err != nil || s.Document().Pending != nil || lost.writes != 1 {
				t.Fatal("real recovery replayed create: ", err)
			}
		}
		if err != nil {
			t.Fatalf("real journaled apply %s: %v", key.String(), err)
		}
	}
	if lost.responseWrites != 1 {
		t.Fatal("lost real Create response path not exercised exactly once")
	}
	if len(s.Document().Resources) != 38 || s.Document().Pending != nil {
		t.Fatal("public inventory incomplete")
	}
	uid := lost.key
	before, err := access.Get(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	s, err = engine.Apply(ctx, s, uid, plan.Digest(), false)
	if err != nil {
		t.Fatal("real original-UID/RV update: ", err)
	}
	after, err := access.Get(ctx, uid)
	if err != nil || after.GetUID() != before.GetUID() || after.GetResourceVersion() == before.GetResourceVersion() {
		t.Fatal("original CAS update not proved")
	}
	if _, err := engine.Delete(ctx, s, namespaceKey(plan.Namespace())); !errors.Is(err, ErrInvalid) {
		t.Fatal("retained Namespace delete accepted")
	}
}
