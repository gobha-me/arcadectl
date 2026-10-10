// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installfiles"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	configv1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

// Actual signed on-disk package/private receipts and TLS HTTP reads through
// the command entrypoint. Public cluster state is a mock; this does not claim
// an actual-binary/kubelet or complete install/upgrade/uninstall proof.
func TestInspectionCommandSignedInputsTLSRecoveryAndOutputFailure(t *testing.T) {
	for _, mode := range []string{"historical", "historical-explicit-baseline", "baseline-bootstrap", "baseline-with-historical-anchor"} {
		t.Run(mode, func(t *testing.T) { testInspectionCommandSignedInputsTLSRecoveryAndOutputFailure(t, mode) })
	}
}

func testInspectionCommandSignedInputsTLSRecoveryAndOutputFailure(t *testing.T, mode string) {
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	trust := key.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(trust)
	if err != nil {
		t.Fatal(err)
	}
	trustPath := filepath.Join(base, "trust.pem")
	if err := os.WriteFile(trustPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	images := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("a", 64), API: "registry.example/api@sha256:" + strings.Repeat("b", 64)}
	payloads, crds, err := installrender.RenderPayloads(images, false)
	if err != nil {
		t.Fatal(err)
	}
	body, err := installpackage.Build(installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion,
		PackageVersion: "0.1.0-rc.1", SourceSHA: strings.Repeat("c", 40), SourceEpoch: 1, Images: images, CRDs: crds,
		Profiles: installrender.SupportedProfiles(false), Prerequisites: installrender.RequiredPrerequisites()}, payloads)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := installpackage.Sign(body, key)
	if err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(base, "package")
	if err := installfiles.Write(packagePath, body, sig, payloads, trust); err != nil {
		t.Fatal(err)
	}
	pkg, err := installfiles.Load(packagePath, trust)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := installrender.Compile(pkg, "isolated-inspect", installrender.Profile135)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(base, "state")
	if err := os.Mkdir(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	files, err := privatefs.Open(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = files.Close() })
	var baseline *installbaseline.Plan
	baselinePath := filepath.Join(base, "security-baseline")
	if mode != "historical" {
		manifest, payload, err := installbaseline.Build(strings.Repeat("c", 40), 1)
		if err != nil {
			t.Fatal("signed baseline inspection fixture unavailable")
		}
		signature, err := installbaseline.Sign(manifest, key)
		if err != nil || installfiles.WriteBaseline(baselinePath, manifest, signature, payload, trust) != nil {
			t.Fatal("separate signed baseline inspection fixture refused")
		}
		artifact, err := installfiles.LoadBaseline(baselinePath, trust)
		if err != nil {
			t.Fatal("baseline inspection trust fixture unavailable")
		}
		baseline, err = installbaseline.Compile(artifact, plan.Namespace(), plan.Profile().ID)
		if err != nil {
			t.Fatal("baseline inspection scope fixture refused")
		}
	}
	var receipt *installstate.BootstrapReceipt
	if mode == "baseline-bootstrap" {
		receipt, err = installstate.PrepareBootstrapWithBaseline(files, "bootstrap.json", plan, baseline)
	} else {
		receipt, err = installstate.PrepareBootstrap(files, "bootstrap.json", plan)
	}
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientset()
	client.PrependReactor("create", "namespaces", func(a clienttesting.Action) (bool, runtime.Object, error) {
		ns := a.(clienttesting.CreateAction).GetObject().(*corev1.Namespace).DeepCopy()
		ns.UID, ns.ResourceVersion = "original-inspect-namespace", "1"
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
		t.Fatal(err)
	}
	if mode == "baseline-with-historical-anchor" {
		// Synthetic explicit-enrollment journal state for READ-only CLI
		// coverage, not a native enrollment or mutation-workflow proof.
		store, err := installstate.NewWithBaseline(client.CoreV1().Namespaces(), baseline, plan)
		if err != nil {
			t.Fatal("baseline-aware inspection store unavailable")
		}
		s, err = store.Load(t.Context(), s.Anchor())
		if err != nil {
			t.Fatal("historical inspection anchor unavailable")
		}
		document := s.Document()
		document.SecurityBaseline, err = installstate.PinnedSecurityBaseline(baseline)
		if err != nil {
			t.Fatal("explicit inspection baseline fixture pin unavailable")
		}
		document.Revision++
		s, err = store.Commit(t.Context(), s, document)
		if err != nil {
			t.Fatal("baseline-aware inspection journal fixture refused")
		}
	}
	ns, err := client.CoreV1().Namespaces().Get(context.Background(), plan.Namespace(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ns.APIVersion, ns.Kind = "v1", "Namespace"
	originalJournal := ns.Annotations[installstate.Annotation]
	originalReceipt, id, err := files.Read("bootstrap.json", installstate.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	claims := []corev1.PersistentVolumeClaim{{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"},
		ObjectMeta: metav1.ObjectMeta{Name: "world", Namespace: ns.Name, UID: "original-world", ResourceVersion: "11", Annotations: map[string]string{"private.example/note": "PRIVATE-CANARY"}},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "retained-pv"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}}
	var mu sync.Mutex
	requests, lists := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer PRIVATE-CANARY" {
			t.Error("inspection mutation or lost static auth")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/namespaces/" + ns.Name:
			_ = json.NewEncoder(w).Encode(ns)
		case "/api/v1/namespaces/" + ns.Name + "/persistentvolumeclaims":
			lists++
			_ = json.NewEncoder(w).Encode(&corev1.PersistentVolumeClaimList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaimList"}, ListMeta: metav1.ListMeta{ResourceVersion: strconv.Itoa(100 + lists)}, Items: claims})
		default:
			t.Error("inspection contacted unrelated resource")
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	o := options{namespace: ns.Name, kubeContext: "explicit", kubeconfig: filepath.Join(base, "kubeconfig.json")}
	writeStatic(t, o, configv1.Config{Kind: "Config", APIVersion: "v1", Contexts: []configv1.NamedContext{{Name: "explicit", Context: configv1.Context{Cluster: "cluster", AuthInfo: "admin"}}},
		Clusters:  []configv1.NamedCluster{{Name: "cluster", Cluster: configv1.Cluster{Server: server.URL, CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}},
		AuthInfos: []configv1.NamedAuthInfo{{Name: "admin", AuthInfo: configv1.AuthInfo{Token: "PRIVATE-CANARY"}}}})
	args := []string{"inspect", "--namespace", ns.Name, "--profile", plan.Profile().ID, "--bootstrap-package", packagePath, "--package", packagePath, "--trust-key", trustPath,
		"--state-dir", stateDir, "--bootstrap-receipt", "bootstrap.json", "--kubeconfig", o.kubeconfig, "--context", o.kubeContext}
	if baseline != nil {
		args = append(args, "--security-baseline", baselinePath)
	}
	var out, diagnostics bytes.Buffer
	counts := func() (int, int) { mu.Lock(); defer mu.Unlock(); return requests, lists }
	// Historical read-only inspection remains available without a baseline,
	// but every mutation must refuse its absence before touching the cluster.
	for _, command := range []string{"install", "upgrade", "rollback", "uninstall", "resume"} {
		mutation := make([]string, 0, len(args))
		for i := 0; i < len(args); i++ {
			if args[i] == "--security-baseline" {
				i++
				continue
			}
			mutation = append(mutation, args[i])
		}
		mutation[0] = command
		mutation = append(mutation, "--api-ca", trustPath)
		if command == "install" || command == "upgrade" || command == "rollback" {
			mutation = append(mutation, "--target-package", packagePath)
		}
		if command == "install" {
			mutation = append(mutation, "--api-certificate", trustPath, "--api-key", trustPath)
		}
		out.Reset()
		diagnostics.Reset()
		before, _ := counts()
		if code := run(t.Context(), mutation, &out, &diagnostics); code != 2 || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE-CANARY") {
			t.Fatal("mutation ignored missing mandatory baseline input")
		}
		after, _ := counts()
		if before != after {
			t.Fatal("mutation without baseline contacted the cluster")
		}
	}
	out.Reset()
	diagnostics.Reset()
	if code := run(context.Background(), args, &out, &diagnostics); code != 0 || diagnostics.Len() != 0 || bytes.Contains(out.Bytes(), []byte("PRIVATE-CANARY")) {
		t.Fatal("signed inspection failed or leaked private data", code, diagnostics.String())
	}
	var public struct {
		NamespaceUID     string `json:"namespaceUid"`
		Stage            string `json:"stage"`
		SecurityBaseline *struct {
			Version               string `json:"version"`
			ArtifactDigest        string `json:"artifactDigest"`
			OwnershipStage        string `json:"ownershipStage"`
			OriginalResourceCount int    `json:"originalResourceCount"`
		} `json:"securityBaseline"`
		Claims []struct {
			UID string `json:"uid"`
		} `json:"claims"`
	}
	_, listCount := counts()
	if json.Unmarshal(out.Bytes(), &public) != nil || public.NamespaceUID != string(s.Anchor().UID) || public.Stage != "preparing" || len(public.Claims) != 1 || public.Claims[0].UID != "original-world" || listCount != 2 {
		t.Fatal("inspection lost public recovery identity")
	}
	baselineRecorded := mode == "baseline-bootstrap" || mode == "baseline-with-historical-anchor"
	if !baselineRecorded && public.SecurityBaseline != nil || baselineRecorded && (public.SecurityBaseline == nil || public.SecurityBaseline.Version != installbaseline.Version || public.SecurityBaseline.ArtifactDigest != baseline.Digest() || public.SecurityBaseline.OwnershipStage != "preparing" || public.SecurityBaseline.OriginalResourceCount != 0) {
		t.Fatal("inspection lost original baseline ownership progress or invented enforcement health")
	}
	if baseline != nil {
		withoutBaseline := args[:len(args)-2]
		out.Reset()
		diagnostics.Reset()
		code := run(t.Context(), withoutBaseline, &out, &diagnostics)
		if baselineRecorded {
			if (code != 3 && code != 4) || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE-CANARY") {
				t.Fatal("baseline-aware inspection silently adopted omitted trust context")
			}
		} else if code != 0 || diagnostics.Len() != 0 || bytes.Contains(out.Bytes(), []byte("securityBaseline")) || bytes.Contains(out.Bytes(), []byte("PRIVATE-CANARY")) {
			t.Fatal("optional inspection context invented historical baseline enrollment")
		}
		badArgs := append([]string{}, args...)
		badArgs[len(badArgs)-1] = "PRIVATE-CANARY"
		beforeInvalid, _ := counts()
		out.Reset()
		diagnostics.Reset()
		if code := run(t.Context(), badArgs, &out, &diagnostics); code != 2 || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE-CANARY") {
			t.Fatal("unsafe inspection baseline path was accepted or exposed")
		}
		afterInvalid, _ := counts()
		if beforeInvalid != afterInvalid {
			t.Fatal("invalid baseline path contacted the cluster")
		}
		badArgs = append([]string{}, args...)
		badArgs[len(badArgs)-1] = packagePath
		out.Reset()
		diagnostics.Reset()
		if code := run(t.Context(), badArgs, &out, &diagnostics); code != 3 || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE-CANARY") {
			t.Fatal("inspection treated runtime package as baseline")
		}
		afterCrossover, _ := counts()
		if afterCrossover != afterInvalid {
			t.Fatal("artifact crossover contacted the cluster")
		}
		if baselineRecorded {
			manifest, payload, err := installbaseline.Build(strings.Repeat("d", 40), 1)
			if err != nil {
				t.Fatal("foreign signed baseline fixture unavailable")
			}
			signature, err := installbaseline.Sign(manifest, key)
			foreignPath := filepath.Join(base, "foreign-baseline")
			if err != nil || installfiles.WriteBaseline(foreignPath, manifest, signature, payload, trust) != nil {
				t.Fatal("foreign signed baseline fixture publication refused")
			}
			badArgs = append([]string{}, args...)
			badArgs[len(badArgs)-1] = foreignPath
			out.Reset()
			diagnostics.Reset()
			if code := run(t.Context(), badArgs, &out, &diagnostics); (code != 3 && code != 4) || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE-CANARY") {
				t.Fatal("inspection adopted a different signed baseline identity")
			}
		}
	}
	for _, writer := range []io.Writer{shortWriter{}, brokenWriter{}} {
		diagnostics.Reset()
		if code := run(context.Background(), args, writer, &diagnostics); code != 1 || strings.Contains(diagnostics.String(), "PRIVATE-CANARY") {
			t.Fatal("inspection output failure hidden or reflected")
		}
	}
	beforeCancel, _ := counts()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out.Reset()
	diagnostics.Reset()
	code := run(ctx, args, &out, &diagnostics)
	afterCancel, _ := counts()
	if code != 4 || out.Len() != 0 || afterCancel != beforeCancel {
		t.Fatal("cancelled invocation contacted cluster")
	}
	after, afterID, err := files.Read("bootstrap.json", installstate.MaxBytes)
	if err != nil || afterID != id || !bytes.Equal(originalReceipt, after) || ns.Annotations[installstate.Annotation] != originalJournal {
		t.Fatal("inspection mutated original evidence")
	}
	afterEntries, err := os.ReadDir(stateDir)
	if err != nil || !reflect.DeepEqual(entries, afterEntries) {
		t.Fatal("inspection created private state")
	}
}
