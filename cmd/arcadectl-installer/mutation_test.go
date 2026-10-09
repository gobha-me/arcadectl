// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installengine"
	"github.com/gobha-me/arcadectl/internal/installfiles"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	configv1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

func mutationArguments(command string) []string {
	args := []string{command, "--namespace", "isolated-install", "--profile", "kubernetes-1.35.8", "--bootstrap-package", "/private/bootstrap", "--package", "/private/current", "--trust-key", "/private/trust", "--state-dir", "/private/state", "--bootstrap-receipt", "bootstrap.json", "--kubeconfig", "/private/kubeconfig", "--context", "explicit", "--api-ca", "/private/ca", "--security-baseline", "/private/baseline"}
	if command == "install" || command == "upgrade" || command == "rollback" {
		args = append(args, "--target-package", "/private/current")
	}
	if command == "install" {
		args = append(args, "--api-certificate", "/private/cert", "--api-key", "/private/key")
	}
	return args
}

func writeMutationBaseline(t *testing.T, path string, key ed25519.PrivateKey, epoch int64) {
	t.Helper()
	manifest, payload, err := installbaseline.Build(strings.Repeat("c", 40), epoch)
	if err != nil {
		t.Fatal("test-only baseline build unavailable")
	}
	signature, err := installbaseline.Sign(manifest, key)
	if err != nil || installfiles.WriteBaseline(path, manifest, signature, payload, key.Public().(ed25519.PublicKey)) != nil {
		t.Fatal("separate signed baseline fixture unavailable")
	}
}

// Real signed-package loader and frozen HTTPS boundary; responses deliberately
// reject prerequisites. This proves zero effects and preflight routing, NOT a
// successful lifecycle or native policy behavior.
func TestMutationBootstrapResumeUsesRegisteredPlanAndRejectsFreshClientBeforeHTTP(t *testing.T) {
	base := t.TempDir()
	if os.Chmod(base, 0700) != nil {
		t.Fatal("private fixture directory unavailable")
	}
	write := func(name string, body []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(base, name)
		if os.WriteFile(path, body, mode) != nil {
			t.Fatal("private fixture output unavailable")
		}
		return path
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32)) // test-only signing key
	images := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("a", 64), API: "registry.example/api@sha256:" + strings.Repeat("b", 64)}
	payloads, crds, err := installrender.RenderPayloads(images, false)
	if err != nil {
		t.Fatal(err)
	}
	body, err := installpackage.Build(installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: strings.Repeat("c", 40), SourceEpoch: 1, Images: images, Profiles: installrender.SupportedProfiles(false), Prerequisites: installrender.RequiredPrerequisites(), CRDs: crds}, payloads)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := installpackage.Sign(body, key)
	if err != nil || installfiles.Write(filepath.Join(base, "package"), body, signature, payloads, key.Public().(ed25519.PublicKey)) != nil {
		t.Fatal("signed package fixture unavailable")
	}
	trust, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	trustPath := write("trust.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: trust}), 0600)
	baselinePath := filepath.Join(base, "baseline")
	writeMutationBaseline(t, baselinePath, key, 1)
	var reads, writes atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews") {
			reads.Add(1)
		} else {
			writes.Add(1)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), DNSNames: []string{"arcadectl-api.isolated-install.svc"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certDER, err := x509.CreateCertificate(rand.Reader, cert, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	o := options{command: "resume", namespace: "isolated-install", profile: installrender.Profile135, bootstrapPackage: filepath.Join(base, "package"), packages: packagePaths{filepath.Join(base, "package")}, trustKey: trustPath, stateDir: base, receipt: "bootstrap.json", kubeContext: "explicit", kubeconfig: filepath.Join(base, "kubeconfig.json"), timeout: time.Minute, securityBaseline: baselinePath,
		apiCA:          write("api-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600),
		apiCertificate: write("api-cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0600),
		apiKey:         write("api-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)}
	raw := configv1.Config{Kind: "Config", APIVersion: "v1", Contexts: []configv1.NamedContext{{Name: "explicit", Context: configv1.Context{Cluster: "cluster", AuthInfo: "admin", Namespace: o.namespace}}},
		Clusters:  []configv1.NamedCluster{{Name: "cluster", Cluster: configv1.Cluster{Server: server.URL, CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}},
		AuthInfos: []configv1.NamedAuthInfo{{Name: "admin", AuthInfo: configv1.AuthInfo{Token: "TEST-ONLY-CLUSTER-CREDENTIAL"}}}}
	writeStatic(t, o, raw)
	foreignPath := filepath.Join(base, "foreign-baseline")
	writeMutationBaseline(t, foreignPath, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{18}, 32)), 1)
	tamperedPath := filepath.Join(base, "tampered-baseline")
	writeMutationBaseline(t, tamperedPath, key, 1)
	if os.WriteFile(filepath.Join(tamperedPath, installfiles.ManifestName), []byte("PRIVATE-CANARY"), 0600) != nil {
		t.Fatal("tampered artifact fixture unavailable")
	}
	sentinelBytes := []byte("original-protected-state-must-not-change")
	sentinelPath := write("original-state-sentinel", sentinelBytes, 0600)
	sentinel, err := os.Open(sentinelPath)
	if err != nil {
		t.Fatal("original protected sentinel unavailable")
	}
	defer sentinel.Close() // Retain the original inode, preventing identity recycling.
	sentinelInfo, err := sentinel.Stat()
	if err != nil {
		t.Fatal("original protected sentinel identity unavailable")
	}
	for _, command := range []string{"install", "upgrade", "rollback", "uninstall", "resume"} {
		for _, path := range []string{"", "relative", filepath.Join(base, "missing-baseline"), o.bootstrapPackage, foreignPath, tamperedPath} {
			bad := o
			bad.command, bad.securityBaseline = command, path
			before, err := os.ReadDir(base)
			if err != nil {
				t.Fatal("protected state census unavailable")
			}
			loaded, err := loadMutationInstallation(bad)
			if loaded != nil {
				_ = loaded.files.Close()
			}
			after, readErr := os.ReadDir(base)
			contents, contentsErr := os.ReadFile(sentinelPath)
			identity, identityErr := os.Stat(sentinelPath)
			if err != errInputs || loaded != nil || readErr != nil || !reflect.DeepEqual(before, after) || contentsErr != nil || identityErr != nil || !os.SameFile(sentinelInfo, identity) || !bytes.Equal(contents, sentinelBytes) || reads.Load() != 0 || writes.Load() != 0 {
				t.Fatal("invalid baseline contacted network, changed protected state census/sentinel or returned unprotected engine")
			}
		}
	}
	x, err := loadMutationInstallation(o)
	if err != nil {
		t.Fatal("real closed signed loader refused fixture")
	}
	defer x.files.Close()
	if !x.bootstrapRegistered || x.registeredBootstrap == nil || x.registeredBootstrap == x.original || x.registeredBootstrap.Digest() != x.original.Digest() {
		t.Fatal("bootstrap preflight lost actual registered plan identity")
	}
	artifact, err := installfiles.LoadBaseline(baselinePath, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal("independent signed baseline reader unavailable")
	}
	baseline, err := installbaseline.Compile(artifact, o.namespace, o.profile)
	if err != nil || x.journal.BaselineDigest() != baseline.Digest() {
		t.Fatal("real mutation loader did not bind separate baseline")
	}
	if _, err := installstate.PrepareBootstrapWithBaseline(x.files, o.receipt, x.original, baseline); err != nil {
		t.Fatal(err)
	}
	originalReceipt, err := os.ReadFile(filepath.Join(base, o.receipt))
	if err != nil {
		t.Fatal("original bootstrap evidence unavailable")
	}
	swapped := o
	swapped.securityBaseline = filepath.Join(base, "other-signed-baseline")
	writeMutationBaseline(t, swapped.securityBaseline, key, 2)
	other, err := loadMutationInstallation(swapped)
	if err != nil {
		t.Fatal("independently signed replacement fixture unavailable")
	}
	defer other.files.Close()
	if s, err := other.start(t.Context(), swapped); err == nil || s != nil || reads.Load() != 0 || writes.Load() != 0 {
		t.Fatal("different signed baseline retied original bootstrap authority")
	}
	unchanged, err := os.ReadFile(filepath.Join(base, o.receipt))
	if err != nil || !bytes.Equal(originalReceipt, unchanged) {
		t.Fatal("refused artifact rewrote original bootstrap evidence")
	}
	o.clientCredential = filepath.Join(base, "rotated-client.json")
	if s, err := x.start(context.Background(), o); err == nil || s != nil || reads.Load() != 0 || writes.Load() != 0 {
		t.Fatal("initial bootstrap resume accepted selected client or contacted cluster")
	}
	o.clientCredential = ""
	if s, err := x.start(context.Background(), o); err == nil || s != nil || reads.Load() == 0 || writes.Load() != 0 {
		t.Fatal("unpinned original resume skipped registered-plan preflight or created namespace")
	}
}

func TestMutationArgumentsClosedCommandsAndNoRetargeting(t *testing.T) {
	for _, command := range []string{"install", "upgrade", "rollback", "uninstall", "resume"} {
		t.Run(command, func(t *testing.T) {
			o, err := parseOptions(mutationArguments(command))
			if err != nil || o.command != command || o.timeout != 2*time.Hour {
				t.Fatal("explicit mutation inputs refused", err)
			}
			for _, extra := range [][]string{{"--token", "PRIVATE-CANARY"}, {"--timeout", "25h"}, {"--api-ca", "relative"}, {"--client-credential", "relative"}, {"--target-package", "/private/foreign"}} {
				if _, err := parseOptions(append(mutationArguments(command), extra...)); err == nil {
					t.Fatal("foreign/inline/unbounded mutation inputs accepted")
				}
			}
			withCurrentClient := append(mutationArguments(command), "--client-credential", "/private/rotated-client")
			if _, err := parseOptions(withCurrentClient); err != nil {
				t.Fatal("retained operation could not select current protected credentials")
			}
			if command == "resume" || command == "uninstall" {
				if _, err := parseOptions(append(mutationArguments(command), "--target-package", "/private/current")); err == nil {
					t.Fatal("resume/uninstall retargeted original journal")
				}
			}
		})
	}
}

func TestMutationCommandsRequireSecurityBaseline(t *testing.T) {
	for _, command := range []string{"install", "upgrade", "rollback", "uninstall", "resume"} {
		t.Run(command, func(t *testing.T) {
			args := mutationArguments(command)
			without := make([]string, 0, len(args))
			for i := 0; i < len(args); i++ {
				if args[i] == "--security-baseline" {
					i++
					continue
				}
				without = append(without, args[i])
			}
			for _, fault := range []string{"missing", "relative", "root"} {
				bad := append([]string{}, without...)
				if fault == "relative" {
					bad = append(bad, "--security-baseline", "relative")
				} else if fault == "root" {
					bad = append(bad, "--security-baseline", "/")
				}
				var out, diagnostics bytes.Buffer
				if code := run(t.Context(), bad, &out, &diagnostics); code != 2 || out.Len() != 0 {
					t.Fatalf("%s mutation reached trusted loading without explicit absolute baseline: code=%d", fault, code)
				}
			}
		})
	}
}

func TestMutationOptionsKeepCurrentCredentialSeparateFromInitialCandidate(t *testing.T) {
	o, err := parseOptions(append(mutationArguments("upgrade"), "--client-credential", "/private/rotated-client"))
	if err != nil {
		t.Fatal(err)
	}
	options := mutationLifecycleOptions(o, nil)
	if options.Activation.CredentialFile != "/private/rotated-client" || options.Activation.CAFile != "/private/ca" || options.Credentials.CertificateFile != "" || options.Credentials.KeyFile != "" {
		t.Fatal("retained activation rebound to bootstrap TLS/client")
	}
	if options.Now.IsZero() || !reflect.DeepEqual(options.Activation, installengine.ActivationOptions{CredentialFile: "/private/rotated-client", CAFile: "/private/ca"}) {
		t.Fatal("explicit current activation identity lost")
	}
}
