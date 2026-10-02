// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package adminauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileVerifierRotationExpiryAndHighWatermark(t *testing.T) {
	now := time.Date(2026, 10, 2, 2, 0, 0, 0, time.UTC)
	clock := now
	first, err := GenerateCredential(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth.json")
	writeBundle(t, path, first.Bundle)
	verifier := NewFileVerifier(path, func() time.Time { return clock })
	if err := verifier.Reload(); err != nil || !verifier.Ready() {
		t.Fatalf("initial reload = %v ready=%v", err, verifier.Ready())
	}
	principal, err := verifier.Authenticate(context.Background(), first.Token)
	if err != nil || principal.ID != AdminPrincipalID || principal.CredentialID != first.Bundle.CredentialID ||
		len(principal.Roles) != 1 || principal.Roles[0] != RoleAdministrator || !principal.ExpiresAt.Equal(first.Bundle.ExpiresAt) {
		t.Fatalf("principal = %#v, %v", principal, err)
	}
	if _, err := verifier.Authenticate(context.Background(), "not-a-token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong token error = %v", err)
	}

	second, err := GenerateCredential(now, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second.Bundle.Serial = 2
	writeBundle(t, path, second.Bundle)
	if err := verifier.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Authenticate(context.Background(), first.Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old token retained after rotation: %v", err)
	}
	if _, err := verifier.Authenticate(context.Background(), second.Token); err != nil {
		t.Fatalf("new token denied: %v", err)
	}

	writeBundle(t, path, first.Bundle)
	if err := verifier.Reload(); !errors.Is(err, ErrInvalidVerifier) || verifier.Ready() {
		t.Fatalf("rollback reload = %v ready=%v", err, verifier.Ready())
	}
	if _, err := verifier.Authenticate(context.Background(), second.Token); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("rollback did not fail closed: %v", err)
	}
	writeBundle(t, path, second.Bundle)
	if err := verifier.Reload(); err != nil || !verifier.Ready() {
		t.Fatalf("restore high-water bundle = %v ready=%v", err, verifier.Ready())
	}

	clock = second.Bundle.ExpiresAt
	if verifier.Ready() {
		t.Fatal("expired verifier remained ready")
	}
	if _, err := verifier.Authenticate(context.Background(), second.Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired token error = %v", err)
	}
}

func TestFileVerifierInvalidHigherBundleFailsClosed(t *testing.T) {
	now := time.Date(2026, 10, 2, 2, 0, 0, 0, time.UTC)
	credential, _ := GenerateCredential(now, time.Hour)
	path := filepath.Join(t.TempDir(), "auth.json")
	writeBundle(t, path, credential.Bundle)
	verifier := NewFileVerifier(path, func() time.Time { return now })
	if err := verifier.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":"v1","credentialId":"bad","serial":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Reload(); !errors.Is(err, ErrInvalidVerifier) || verifier.Ready() {
		t.Fatalf("invalid reload = %v ready=%v", err, verifier.Ready())
	}
	if _, err := verifier.Authenticate(context.Background(), credential.Token); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("prior token survived invalid bundle: %v", err)
	}
}

func TestFileVerifierRunReloadsAndStops(t *testing.T) {
	now := time.Date(2026, 10, 2, 2, 0, 0, 0, time.UTC)
	credential, _ := GenerateCredential(now, time.Hour)
	path := filepath.Join(t.TempDir(), "auth.json")
	writeBundle(t, path, credential.Bundle)
	verifier := NewFileVerifier(path, func() time.Time { return now })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- verifier.Run(ctx, time.Millisecond) }()
	deadline := time.Now().Add(time.Second)
	for !verifier.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !verifier.Ready() {
		t.Fatal("periodic verifier did not become ready")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := verifier.Run(context.Background(), 0); err == nil {
		t.Fatal("accepted non-positive reload interval")
	}
}

func writeBundle(t *testing.T, path string, bundle VerifierBundle) {
	t.Helper()
	contents, err := MarshalVerifierBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}
