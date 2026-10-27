// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package adminauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFastTimedOutMutantBoundariesAndVerifierRun(t *testing.T) {
	now := time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC)
	credential, err := GenerateCredential(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	private := ClientCredential{
		Version:              ClientCredentialVersion,
		CredentialID:         credential.Bundle.CredentialID,
		Serial:               credential.Bundle.Serial,
		ExpiresAt:            credential.Bundle.ExpiresAt,
		Token:                credential.Token,
		PriorSecretUID:       "uid-fast",
		PriorResourceVersion: "7",
	}
	rawPrivate, err := MarshalClientCredential(private)
	if err != nil {
		t.Fatal(err)
	}
	rawBundle, err := MarshalVerifierBundle(credential.Bundle)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("credential_210_19_conditionals_negation", func(t *testing.T) {
		if _, err := ParseClientCredential(nil); !errors.Is(err, errInvalidCredential) {
			t.Fatalf("ParseClientCredential(nil) = %v, want %v", err, errInvalidCredential)
		}
		if _, err := ParseClientCredential([]byte{}); !errors.Is(err, errInvalidCredential) {
			t.Fatalf("ParseClientCredential(empty) = %v, want %v", err, errInvalidCredential)
		}
		got, err := ParseClientCredential(rawPrivate)
		if err != nil || got != private {
			t.Fatalf("ParseClientCredential(valid) = (%#v, %v), want (%#v, nil)", got, err, private)
		}
	})

	t.Run("credential_210_41_conditionals_boundary", func(t *testing.T) {
		exactPrivate := append(bytes.Repeat([]byte(" "), MaxClientCredentialBytes-len(rawPrivate)), rawPrivate...)
		if len(exactPrivate) != MaxClientCredentialBytes {
			t.Fatalf("exactPrivate len = %d, want %d", len(exactPrivate), MaxClientCredentialBytes)
		}
		got, err := ParseClientCredential(exactPrivate)
		if err != nil || got != private {
			t.Fatalf("ParseClientCredential(exact MaxClientCredentialBytes) = (%#v, %v), want (%#v, nil)", got, err, private)
		}
		overPrivate := append([]byte(" "), exactPrivate...)
		if _, err := ParseClientCredential(overPrivate); !errors.Is(err, errInvalidCredential) {
			t.Fatalf("ParseClientCredential(MaxClientCredentialBytes+1) = %v, want %v", err, errInvalidCredential)
		}
	})

	t.Run("verifier_84_14_conditionals_negation", func(t *testing.T) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("Run panicked instead of returning error: %v", recovered)
			}
		}()
		path := filepath.Join(t.TempDir(), "auth.json")
		if err := os.WriteFile(path, rawBundle, 0o600); err != nil {
			t.Fatal(err)
		}
		verifier := NewFileVerifier(path, func() time.Time { return now })
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := verifier.Run(canceledCtx, time.Millisecond); err != nil {
			t.Fatalf("Run(canceledCtx, 1ms) = %v, want nil", err)
		}
		if !verifier.Ready() {
			t.Fatal("verifier not ready after initial load in Run(canceledCtx, 1ms)")
		}
		if principal, err := verifier.Authenticate(context.Background(), credential.Token); err != nil || principal.CredentialID != credential.Bundle.CredentialID {
			t.Fatalf("Authenticate after Run(canceledCtx, 1ms) = (%#v, %v)", principal, err)
		}
		for _, nonPositive := range []time.Duration{0, -time.Nanosecond, -time.Second} {
			if err := verifier.Run(canceledCtx, nonPositive); err == nil {
				t.Fatalf("Run(%v) = nil, want non-positive interval error", nonPositive)
			}
		}
	})

	t.Run("verifier_129_40_conditionals_boundary", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "auth.json")
		exactBundle := append(bytes.Repeat([]byte(" "), MaxVerifierBundleBytes-len(rawBundle)), rawBundle...)
		if len(exactBundle) != MaxVerifierBundleBytes {
			t.Fatalf("exactBundle len = %d, want %d", len(exactBundle), MaxVerifierBundleBytes)
		}
		if err := os.WriteFile(path, exactBundle, 0o600); err != nil {
			t.Fatal(err)
		}
		readBytes, err := readBoundedFile(path, MaxVerifierBundleBytes)
		if err != nil || !bytes.Equal(readBytes, exactBundle) {
			t.Fatalf("readBoundedFile(exact MaxVerifierBundleBytes) = (len=%d, %v), want (len=%d, nil)", len(readBytes), err, len(exactBundle))
		}
		verifier := NewFileVerifier(path, func() time.Time { return now })
		if err := verifier.Reload(); err != nil || !verifier.Ready() {
			t.Fatalf("Reload(exact MaxVerifierBundleBytes) = %v, ready=%v, want nil/true", err, verifier.Ready())
		}
		overBundle := append([]byte(" "), exactBundle...)
		if err := os.WriteFile(path, overBundle, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBoundedFile(path, MaxVerifierBundleBytes); !errors.Is(err, ErrInvalidVerifier) {
			t.Fatalf("readBoundedFile(MaxVerifierBundleBytes+1) = %v, want %v", err, ErrInvalidVerifier)
		}
		if err := verifier.Reload(); !errors.Is(err, ErrInvalidVerifier) || verifier.Ready() {
			t.Fatalf("Reload(MaxVerifierBundleBytes+1) = %v, ready=%v, want ErrInvalidVerifier/false", err, verifier.Ready())
		}
	})
}

func TestFileVerifierAdversarialReloadSequences(t *testing.T) {
	now := time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)
	first, err := GenerateCredential(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateCredential(now, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second.Bundle.Serial = 2
	third, err := GenerateCredential(now, 3*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	third.Bundle.Serial = 3

	path := filepath.Join(t.TempDir(), "auth.json")
	verifier := NewFileVerifier(path, func() time.Time { return now })

	if verifier.Ready() {
		t.Fatal("unloaded verifier reported ready")
	}
	if principal, err := verifier.Authenticate(context.Background(), first.Token); !errors.Is(err, ErrUnavailable) || principal.ID != "" {
		t.Fatalf("unloaded authenticate = (%#v, %v), want ErrUnavailable", principal, err)
	}
	if err := verifier.Reload(); !errors.Is(err, ErrInvalidVerifier) {
		t.Fatalf("missing file reload = %v, want %v", err, ErrInvalidVerifier)
	}

	// Load serial 2 as the initial high-watermark bundle.
	writeBundle(t, path, second.Bundle)
	if err := verifier.Reload(); err != nil {
		t.Fatalf("initial serial 2 reload = %v, want nil", err)
	}
	if !verifier.Ready() {
		t.Fatal("verifier not ready after valid serial 2 load")
	}
	highStateSerial2 := verifier.current.Load()
	if highStateSerial2 == nil || verifier.highState != highStateSerial2 || verifier.highSerial != 2 {
		t.Fatalf("unexpected verifier high state after load: current=%p highState=%p highSerial=%d", highStateSerial2, verifier.highState, verifier.highSerial)
	}
	principal, err := verifier.Authenticate(context.Background(), second.Token)
	if err != nil || principal.ID != AdminPrincipalID || principal.CredentialID != second.Bundle.CredentialID ||
		len(principal.Roles) != 1 || principal.Roles[0] != RoleAdministrator || !principal.ExpiresAt.Equal(second.Bundle.ExpiresAt) {
		t.Fatalf("serial 2 authenticate = (%#v, %v)", principal, err)
	}

	// Equal serial with identical contents must succeed and preserve the exact prior verifierState.
	writeBundle(t, path, second.Bundle)
	if err := verifier.Reload(); err != nil {
		t.Fatalf("same-serial identical reload = %v, want nil", err)
	}
	if !verifier.Ready() {
		t.Fatal("verifier not ready after same-serial identical reload")
	}
	if verifier.current.Load() != highStateSerial2 || verifier.highState != highStateSerial2 {
		t.Fatalf("same-serial identical reload replaced prior verifierState: current=%p high=%p want=%p", verifier.current.Load(), verifier.highState, highStateSerial2)
	}
	if _, err := verifier.Authenticate(context.Background(), second.Token); err != nil {
		t.Fatalf("same-serial identical authenticate = %v, want nil", err)
	}

	// Serial rollback (serial 1 < highSerial 2) must fail closed and make Ready/Authenticate unavailable.
	writeBundle(t, path, first.Bundle)
	if err := verifier.Reload(); !errors.Is(err, ErrInvalidVerifier) {
		t.Fatalf("serial rollback reload = %v, want %v", err, ErrInvalidVerifier)
	}
	if verifier.Ready() {
		t.Fatal("verifier remained ready after serial rollback")
	}
	if verifier.current.Load() != nil || verifier.highSerial != 2 || verifier.highState != highStateSerial2 {
		t.Fatalf("rollback corrupted high watermark: current=%p highSerial=%d highState=%p", verifier.current.Load(), verifier.highSerial, verifier.highState)
	}
	if got, err := verifier.Authenticate(context.Background(), first.Token); !errors.Is(err, ErrUnavailable) || got.ID != "" {
		t.Fatalf("rollback token authenticate = (%#v, %v), want ErrUnavailable", got, err)
	}
	if got, err := verifier.Authenticate(context.Background(), second.Token); !errors.Is(err, ErrUnavailable) || got.ID != "" {
		t.Fatalf("prior token authenticate after rollback = (%#v, %v), want ErrUnavailable", got, err)
	}

	// Restoring the exact high-watermark bundle must restore the prior state without reallocating.
	writeBundle(t, path, second.Bundle)
	if err := verifier.Reload(); err != nil {
		t.Fatalf("restore serial 2 reload = %v, want nil", err)
	}
	if !verifier.Ready() || verifier.current.Load() != highStateSerial2 {
		t.Fatalf("restore serial 2 ready=%v current=%p want=%p", verifier.Ready(), verifier.current.Load(), highStateSerial2)
	}
	if _, err := verifier.Authenticate(context.Background(), second.Token); err != nil {
		t.Fatalf("authenticate after restoring serial 2 = %v, want nil", err)
	}

	// Equal serial (serial 2 == highSerial 2) with DIFFERENT payload fingerprint (tampered token digest) must fail closed.
	sameSerialTampered := second.Bundle
	sameSerialTampered.TokenSHA256 = third.Bundle.TokenSHA256
	writeBundle(t, path, sameSerialTampered)
	if err := verifier.Reload(); !errors.Is(err, ErrInvalidVerifier) {
		t.Fatalf("same-serial tampered digest reload = %v, want %v", err, ErrInvalidVerifier)
	}
	if verifier.Ready() {
		t.Fatal("verifier remained ready after same-serial digest tamper")
	}
	if got, err := verifier.Authenticate(context.Background(), second.Token); !errors.Is(err, ErrUnavailable) || got.ID != "" {
		t.Fatalf("second token after same-serial tamper = (%#v, %v), want ErrUnavailable", got, err)
	}
	if got, err := verifier.Authenticate(context.Background(), third.Token); !errors.Is(err, ErrUnavailable) || got.ID != "" {
		t.Fatalf("tampered token after same-serial tamper = (%#v, %v), want ErrUnavailable", got, err)
	}

	// Restore serial 2, then tamper raw file bytes (trailing newline) while keeping identical bundle fields & serial.
	writeBundle(t, path, second.Bundle)
	if err := verifier.Reload(); err != nil || !verifier.Ready() {
		t.Fatalf("restore before whitespace tamper = %v ready=%v", err, verifier.Ready())
	}
	rawSecond, err := MarshalVerifierBundle(second.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append([]byte(nil), rawSecond...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Reload(); !errors.Is(err, ErrInvalidVerifier) {
		t.Fatalf("same-serial altered fingerprint reload = %v, want %v", err, ErrInvalidVerifier)
	}
	if verifier.Ready() {
		t.Fatal("verifier remained ready after same-serial fingerprint change")
	}
	if got, err := verifier.Authenticate(context.Background(), second.Token); !errors.Is(err, ErrUnavailable) || got.ID != "" {
		t.Fatalf("authenticate after same-serial fingerprint change = (%#v, %v), want ErrUnavailable", got, err)
	}

	// Advancing to serial 3 after rejected reload must succeed and replace serial 2.
	writeBundle(t, path, third.Bundle)
	if err := verifier.Reload(); err != nil {
		t.Fatalf("serial 3 reload = %v, want nil", err)
	}
	if !verifier.Ready() || verifier.highSerial != 3 || verifier.current.Load() == highStateSerial2 {
		t.Fatalf("serial 3 did not advance state: ready=%v highSerial=%d", verifier.Ready(), verifier.highSerial)
	}
	if _, err := verifier.Authenticate(context.Background(), second.Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old serial 2 token after serial 3 rotation = %v, want %v", err, ErrUnauthorized)
	}
	principal, err = verifier.Authenticate(context.Background(), third.Token)
	if err != nil || principal.CredentialID != third.Bundle.CredentialID {
		t.Fatalf("serial 3 token authenticate = (%#v, %v)", principal, err)
	}
}

func TestFileVerifierBoundedFileExactSizeAndOversize(t *testing.T) {
	now := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	credential, err := GenerateCredential(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalVerifierBundle(credential.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth.json")
	verifier := NewFileVerifier(path, func() time.Time { return now })

	// Exactly MaxVerifierBundleBytes with leading spaces so the closing brace is the final byte.
	exactMax := append(bytes.Repeat([]byte(" "), MaxVerifierBundleBytes-len(raw)), raw...)
	if len(exactMax) != MaxVerifierBundleBytes {
		t.Fatalf("exactMax len = %d, want %d", len(exactMax), MaxVerifierBundleBytes)
	}
	if err := os.WriteFile(path, exactMax, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Reload(); err != nil {
		t.Fatalf("reload at exact MaxVerifierBundleBytes = %v, want nil", err)
	}
	if !verifier.Ready() {
		t.Fatal("verifier not ready at exact MaxVerifierBundleBytes")
	}
	if _, err := verifier.Authenticate(context.Background(), credential.Token); err != nil {
		t.Fatalf("authenticate at exact MaxVerifierBundleBytes = %v, want nil", err)
	}

	// MaxVerifierBundleBytes + 1 must fail closed and clear active verifier state.
	overMax := append([]byte(" "), exactMax...)
	if err := os.WriteFile(path, overMax, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Reload(); !errors.Is(err, ErrInvalidVerifier) {
		t.Fatalf("reload at MaxVerifierBundleBytes+1 = %v, want %v", err, ErrInvalidVerifier)
	}
	if verifier.Ready() {
		t.Fatal("verifier remained ready after oversized bundle reload")
	}
	if _, err := verifier.Authenticate(context.Background(), credential.Token); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("authenticate after oversized bundle reload = %v, want %v", err, ErrUnavailable)
	}
}

func TestCredentialAdversarialArrayAndDuplicateKeyJSON(t *testing.T) {
	now := time.Date(2026, 10, 2, 5, 0, 0, 0, time.UTC)
	credential, err := GenerateCredential(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	validBundle, err := MarshalVerifierBundle(credential.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	validPrivate, err := MarshalClientCredential(ClientCredential{
		Version:      ClientCredentialVersion,
		CredentialID: credential.Bundle.CredentialID,
		Serial:       credential.Bundle.Serial,
		ExpiresAt:    credential.Bundle.ExpiresAt,
		Token:        credential.Token,
	})
	if err != nil {
		t.Fatal(err)
	}

	invalidPayloads := []struct {
		name     string
		contents []byte
	}{
		{
			name:     "top-level array with duplicate-key object",
			contents: []byte(`[{"version":"v1","version":"v1"}]`),
		},
		{
			name:     "top-level array with valid element then duplicate-key object",
			contents: []byte(`[{"version":"v1"},{"serial":1,"serial":2}]`),
		},
		{
			name:     "nested array containing duplicate-key object",
			contents: []byte(`[[{"a":1},{"dup":1,"dup":2}]]`),
		},
		{
			name:     "bundle object with array field containing duplicate-key object",
			contents: bytes.Replace(validBundle, []byte(`"serial":1`), []byte(`"serial":1,"items":[{"k":1,"k":2}]`), 1),
		},
		{
			name:     "bundle object with array field containing valid then duplicate-key object",
			contents: bytes.Replace(validBundle, []byte(`"serial":1`), []byte(`"serial":1,"items":["ok",{"k":1,"k":2}]`), 1),
		},
		{
			name:     "bundle object with array field containing malformed nested element",
			contents: bytes.Replace(validBundle, []byte(`"serial":1`), []byte(`"serial":1,"items":[{"bad":}]`), 1),
		},
		{
			name:     "private credential with array field containing duplicate-key object",
			contents: bytes.Replace(validPrivate, []byte(`"serial":1`), []byte(`"serial":1,"items":[{"k":1,"k":2}]`), 1),
		},
		{
			name:     "top-level array with unclosed nested object",
			contents: []byte(`[{"version":"v1"]`),
		},
	}

	for _, tc := range invalidPayloads {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParseVerifierBundle(tc.contents); !errors.Is(err, errInvalidCredential) || got != (VerifierBundle{}) {
				t.Fatalf("ParseVerifierBundle(%s) = (%#v, %v), want errInvalidCredential", tc.name, got, err)
			}
			if got, err := ParseClientCredential(tc.contents); !errors.Is(err, errInvalidCredential) || got != (ClientCredential{}) {
				t.Fatalf("ParseClientCredential(%s) = (%#v, %v), want errInvalidCredential", tc.name, got, err)
			}
			if err := rejectDuplicateJSONKeys(tc.contents); err == nil {
				t.Fatalf("rejectDuplicateJSONKeys(%s) = nil, want error", tc.name)
			}
			if err := inspectJSONValue(json.NewDecoder(bytes.NewReader(tc.contents))); err == nil {
				t.Fatalf("inspectJSONValue(%s) = nil, want error", tc.name)
			}
		})
	}

	// Exact sentinel checks on inspectJSONValue and rejectDuplicateJSONKeys for array elements.
	for _, arrayDup := range []string{
		`[{"a":1,"a":2}]`,
		`[1,{"a":1,"a":2}]`,
		`[{"a":1},[{"b":1,"b":2}]]`,
		`{"nested":[{"a":1,"a":2}]}`,
	} {
		if err := inspectJSONValue(json.NewDecoder(strings.NewReader(arrayDup))); !errors.Is(err, errInvalidCredential) {
			t.Fatalf("inspectJSONValue(%s) = %v, want %v", arrayDup, err, errInvalidCredential)
		}
		if err := rejectDuplicateJSONKeys([]byte(arrayDup)); !errors.Is(err, errInvalidCredential) {
			t.Fatalf("rejectDuplicateJSONKeys(%s) = %v, want %v", arrayDup, err, errInvalidCredential)
		}
	}

	// Valid arrays without duplicate keys must be accepted by inspectJSONValue and rejectDuplicateJSONKeys.
	for _, validArray := range []string{
		`[{"a":1},{"a":2}]`,
		`[1,{"a":[true,"ok",{"b":2}]}]`,
	} {
		if err := rejectDuplicateJSONKeys([]byte(validArray)); err != nil {
			t.Fatalf("rejectDuplicateJSONKeys(%s) = %v, want nil", validArray, err)
		}
	}

	// Trailing values must be rejected by rejectDuplicateJSONKeys with errInvalidCredential.
	for _, trailing := range []string{
		`{"a":1} {}`,
		`[1] [2]`,
	} {
		if err := rejectDuplicateJSONKeys([]byte(trailing)); !errors.Is(err, errInvalidCredential) {
			t.Fatalf("rejectDuplicateJSONKeys(%q) = %v, want %v", trailing, err, errInvalidCredential)
		}
	}
}

func TestCredentialExactSizeAndLifetimeBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 2, 6, 0, 0, 0, time.UTC)
	for _, nonPositive := range []time.Duration{0, -time.Nanosecond, -time.Hour} {
		if got, err := GenerateCredential(now, nonPositive); !errors.Is(err, errInvalidCredential) || got != (Credential{}) {
			t.Fatalf("GenerateCredential(%v) = (%#v, %v), want errInvalidCredential", nonPositive, got, err)
		}
	}

	credential, err := GenerateCredential(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rawBundle, err := MarshalVerifierBundle(credential.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	exactBundle := append(bytes.Repeat([]byte(" "), MaxVerifierBundleBytes-len(rawBundle)), rawBundle...)
	if len(exactBundle) != MaxVerifierBundleBytes {
		t.Fatalf("exactBundle len = %d, want %d", len(exactBundle), MaxVerifierBundleBytes)
	}
	parsedBundle, err := ParseVerifierBundle(exactBundle)
	if err != nil || parsedBundle != credential.Bundle {
		t.Fatalf("ParseVerifierBundle at exact MaxVerifierBundleBytes = (%#v, %v)", parsedBundle, err)
	}
	if _, err := ParseVerifierBundle(append([]byte(" "), exactBundle...)); !errors.Is(err, errInvalidCredential) {
		t.Fatalf("ParseVerifierBundle at MaxVerifierBundleBytes+1 = %v, want %v", err, errInvalidCredential)
	}
	if _, err := ParseVerifierBundle(nil); !errors.Is(err, errInvalidCredential) {
		t.Fatalf("ParseVerifierBundle(nil) = %v, want %v", err, errInvalidCredential)
	}

	private := ClientCredential{
		Version:              ClientCredentialVersion,
		CredentialID:         credential.Bundle.CredentialID,
		Serial:               credential.Bundle.Serial,
		ExpiresAt:            credential.Bundle.ExpiresAt,
		Token:                credential.Token,
		PriorSecretUID:       "uid-1",
		PriorResourceVersion: "99",
	}
	rawPrivate, err := MarshalClientCredential(private)
	if err != nil {
		t.Fatal(err)
	}
	exactPrivate := append(bytes.Repeat([]byte(" "), MaxClientCredentialBytes-len(rawPrivate)), rawPrivate...)
	if len(exactPrivate) != MaxClientCredentialBytes {
		t.Fatalf("exactPrivate len = %d, want %d", len(exactPrivate), MaxClientCredentialBytes)
	}
	parsedPrivate, err := ParseClientCredential(exactPrivate)
	if err != nil || parsedPrivate != private {
		t.Fatalf("ParseClientCredential at exact MaxClientCredentialBytes = (%#v, %v)", parsedPrivate, err)
	}
	if _, err := ParseClientCredential(append([]byte(" "), exactPrivate...)); !errors.Is(err, errInvalidCredential) {
		t.Fatalf("ParseClientCredential at MaxClientCredentialBytes+1 = %v, want %v", err, errInvalidCredential)
	}
	if _, err := ParseClientCredential(nil); !errors.Is(err, errInvalidCredential) {
		t.Fatalf("ParseClientCredential(nil) = %v, want %v", err, errInvalidCredential)
	}
}
