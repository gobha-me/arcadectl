// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installfiles"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
)

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("SECRET-CANARY") }

type shortWriter struct{}

func (shortWriter) Write(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, nil
	}
	return len(body) - 1, nil
}

func TestNilErrorShortStdoutWritesFailHelpBuildAndVerify(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"help"}} {
		var diagnostics bytes.Buffer
		if code := run(args, shortWriter{}, &diagnostics); code != 1 || diagnostics.String() != "package command output unavailable\n" {
			t.Fatalf("help accepted nil-error short write: exit=%d diagnostics=%q", code, diagnostics.String())
		}
	}
	parent, private, public, _ := fixture(t)
	var diagnostics bytes.Buffer
	args := buildArgs(parent, private, public, "candidate", strings.Repeat("a", 40))
	want := "package command output unavailable; preserve and verify existing output\n"
	if code := run(args, shortWriter{}, &diagnostics); code != 1 || diagnostics.String() != want {
		t.Fatalf("build accepted nil-error short write: exit=%d diagnostics=%q", code, diagnostics.String())
	}
	// A short stdout write does not undo an already-published package.
	verifyArgs := []string{"verify", "--package", filepath.Join(parent, "candidate"), "--trust-key", public}
	invoke(t, verifyArgs, 0)
	diagnostics.Reset()
	if code := run(verifyArgs, shortWriter{}, &diagnostics); code != 1 || diagnostics.String() != want {
		t.Fatalf("verify accepted nil-error short write: exit=%d diagnostics=%q", code, diagnostics.String())
	}
	invoke(t, verifyArgs, 0)
}

func TestStdoutFailureReturnsFailureWithoutReflectingError(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"help"}} {
		var diagnostics bytes.Buffer
		if run(args, brokenWriter{}, &diagnostics) != 1 || strings.Contains(diagnostics.String(), "SECRET-CANARY") {
			t.Fatal("help output failure hidden or reflected")
		}
	}
	parent, private, public, _ := fixture(t)
	var diagnostics bytes.Buffer
	args := buildArgs(parent, private, public, "candidate", strings.Repeat("a", 40))
	if run(args, brokenWriter{}, &diagnostics) != 1 || strings.Contains(diagnostics.String(), "SECRET-CANARY") {
		t.Fatal("build output failure hidden or reflected")
	}
	diagnostics.Reset()
	if run([]string{"verify", "--package", filepath.Join(parent, "candidate"), "--trust-key", public}, brokenWriter{}, &diagnostics) != 1 || strings.Contains(diagnostics.String(), "SECRET-CANARY") {
		t.Fatal("verify output failure hidden or reflected")
	}
	invoke(t, []string{"verify", "--package", filepath.Join(parent, "candidate"), "--trust-key", public}, 0)
}

func fixture(t *testing.T) (string, string, string, ed25519.PrivateKey) {
	t.Helper()
	parent := t.TempDir()
	if os.Chmod(parent, 0700) != nil {
		t.Fatal("protect fixture")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	private, public := filepath.Join(parent, "signing.pem"), filepath.Join(parent, "trust.pem")
	if os.WriteFile(private, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600) != nil || os.WriteFile(public, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0644) != nil {
		t.Fatal("write fake keys")
	}
	return parent, private, public, key
}

func buildArgs(parent, private, public, name, source string) []string {
	return []string{"build", "--output", filepath.Join(parent, name), "--signing-key", private, "--trust-key", public, "--version", "0.1.0-rc.1", "--source-sha", source, "--source-epoch", "1791223200", "--controller-image", "registry.example/controller@sha256:" + strings.Repeat("b", 64), "--api-image", "registry.example/api@sha256:" + strings.Repeat("c", 64)}
}

func invoke(t *testing.T, args []string, want int) (string, string) {
	t.Helper()
	var out, diagnostics bytes.Buffer
	if got := run(args, &out, &diagnostics); got != want {
		t.Fatalf("exit=%d want=%d diagnostics=%s", got, want, diagnostics.String())
	}
	return out.String(), diagnostics.String()
}

func TestBuildVerifyReproducibleAndNoOverwrite(t *testing.T) {
	parent, private, public, _ := fixture(t)
	firstArgs := buildArgs(parent, private, public, "first", strings.Repeat("a", 40))
	a, diagnostics := invoke(t, firstArgs, 0)
	if diagnostics != "" || !strings.HasPrefix(a, "package 0.1.0-rc.1 sha256:") || strings.Contains(a, parent) {
		t.Fatal("unsafe or unexpected public output")
	}
	b, _ := invoke(t, buildArgs(parent, private, public, "second", strings.Repeat("a", 40)), 0)
	if a != b {
		t.Fatal("deterministic build changed identity")
	}
	verified, _ := invoke(t, []string{"verify", "--package", filepath.Join(parent, "first"), "--trust-key", public}, 0)
	if verified != a {
		t.Fatal("verify identity changed")
	}
	_, refused := invoke(t, firstArgs, 1)
	if refused != installfiles.ErrExists.Error()+"\n" {
		t.Fatal("overwrite diagnostic")
	}
	for _, path := range []string{installfiles.ManifestName, installfiles.SignatureName, installpackage.AnchorsPath, installpackage.APIPath, installpackage.ControllerPath} {
		first, _ := os.ReadFile(filepath.Join(parent, "first", path))
		second, _ := os.ReadFile(filepath.Join(parent, "second", path))
		if !bytes.Equal(first, second) {
			t.Fatal("output bytes not reproducible")
		}
	}
}

func TestBuildGenuinePredecessorIdentity(t *testing.T) {
	parent, private, public, key := fixture(t)
	legacy := append(buildArgs(parent, private, public, "legacy", installrender.LegacySourceSHA), "--legacy-source")
	invoke(t, legacy, 0)
	args := append(buildArgs(parent, private, public, "current", strings.Repeat("a", 40)), "--predecessor", filepath.Join(parent, "legacy"), "--predecessor-id", "legacy-7dcb")
	invoke(t, args, 0)
	trust := key.Public().(ed25519.PublicKey)
	previous, err := installfiles.Load(filepath.Join(parent, "legacy"), trust)
	if err != nil {
		t.Fatal(err)
	}
	current, err := installfiles.Load(filepath.Join(parent, "current"), trust)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := previous.Manifest()
	metadata, _ := current.Manifest()
	digest, _ := previous.Digest()
	if len(metadata.Predecessors) != 1 || metadata.Predecessors[0].PackageSHA256 != digest || metadata.Predecessors[0].Images != before.Images || metadata.Predecessors[0].SourceSHA != installrender.LegacySourceSHA {
		t.Fatal("predecessor not pinned to actual verified bytes")
	}
	if _, err := installrender.Compile(previous, "custom-install", installrender.Profile137); err == nil {
		t.Fatal("legacy custom namespace accepted")
	}
	invoke(t, append(buildArgs(parent, private, public, "invalid", strings.Repeat("d", 40)), "--predecessor", filepath.Join(parent, "current"), "--predecessor-id", "not-legacy"), 1)
	if _, err := os.Stat(filepath.Join(parent, "invalid")); !os.IsNotExist(err) {
		t.Fatal("unsupported predecessor wrote output")
	}
}

func TestBuildExternalTrustMustMatchBeforeEffects(t *testing.T) {
	parent, private, public, _ := fixture(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	der, _ := x509.MarshalPKIXPublicKey(other.Public())
	if os.WriteFile(public, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0644) != nil {
		t.Fatal("replace fake external trust")
	}
	_, diag := invoke(t, buildArgs(parent, private, public, "candidate", strings.Repeat("a", 40)), 1)
	if diag != installpackage.ErrSignature.Error()+"\n" {
		t.Fatal("trust mismatch diagnostic")
	}
	if _, err := os.Stat(filepath.Join(parent, "candidate")); !os.IsNotExist(err) {
		t.Fatal("trust mismatch created output")
	}
}

func TestVerifyRejectsAuthenticButUnreviewedPayload(t *testing.T) {
	parent, private, public, key := fixture(t)
	invoke(t, buildArgs(parent, private, public, "original", strings.Repeat("a", 40)), 0)
	pkg, err := installfiles.Load(filepath.Join(parent, "original"), key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	metadata, _ := pkg.Manifest()
	metadata.Files = nil
	payloads := map[string][]byte{}
	for _, path := range []string{installpackage.AnchorsPath, installpackage.APIPath, installpackage.ControllerPath} {
		payloads[path], _ = pkg.Payload(path)
	}
	payloads[installpackage.APIPath] = append(payloads[installpackage.APIPath], []byte("---\n{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"inline-secret\"}}\n")...)
	manifest, err := installpackage.Build(metadata, payloads)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := installpackage.Sign(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := installfiles.Write(filepath.Join(parent, "unreviewed"), manifest, signature, payloads, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	_, diag := invoke(t, []string{"verify", "--package", filepath.Join(parent, "unreviewed"), "--trust-key", public}, 1)
	if diag != installrender.ErrInvalid.Error()+"\n" {
		t.Fatal("signature mistaken for resource authorization")
	}
}

func TestArgumentFailuresDoNotReflectInputs(t *testing.T) {
	parent, private, public, _ := fixture(t)
	for _, args := range [][]string{nil, {"SECRET-CANARY"}, {"verify", "--SECRET-CANARY"}, {"verify", "--package", "SECRET-CANARY"}, {"build", "--source-epoch", "SECRET-CANARY"}, append(buildArgs(parent, private, public, "candidate", installrender.LegacySourceSHA), "--legacy-source=false"), append(buildArgs(parent, private, public, "candidate", strings.Repeat("a", 40)), "--legacy-source"), append(buildArgs(parent, private, public, "candidate", strings.Repeat("a", 40)), "SECRET-CANARY")} {
		out, diag := invoke(t, args, 2)
		if out != "" || strings.Contains(diag, "SECRET-CANARY") || strings.Contains(diag, parent) {
			t.Fatal("arguments reflected")
		}
	}
	out, _ := invoke(t, []string{"--help"}, 0)
	if out != usage {
		t.Fatal("help unavailable")
	}
}
