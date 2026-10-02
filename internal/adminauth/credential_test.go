// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package adminauth

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestGenerateCredentialAndStrictRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 2, 1, 2, 3, 4, time.UTC)
	first, err := GenerateCredential(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateCredential(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first.Token)
	if err != nil || len(decoded) != GeneratedTokenBytes || first.Token == second.Token || first.Bundle.CredentialID == second.Bundle.CredentialID {
		t.Fatalf("generated credentials are not distinct 256-bit values")
	}
	if !TokenMatchesBundle(first.Token, first.Bundle) || TokenMatchesBundle(second.Token, first.Bundle) {
		t.Fatal("token digest match failed")
	}
	if TokenMatchesBundle(first.Token[:len(first.Token)-1]+"B", VerifierBundle{TokenSHA256: TokenDigest(first.Token[:len(first.Token)-1] + "B")}) {
		t.Fatal("accepted noncanonical base64url token")
	}
	contents, err := MarshalVerifierBundle(first.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseVerifierBundle(contents)
	if err != nil || parsed != first.Bundle {
		t.Fatalf("bundle round trip = %#v, %v", parsed, err)
	}
	if bytes.Contains(contents, []byte(first.Token)) {
		t.Fatal("verifier contains raw token")
	}
	private := ClientCredential{
		Version: ClientCredentialVersion, CredentialID: first.Bundle.CredentialID,
		Serial: first.Bundle.Serial, ExpiresAt: first.Bundle.ExpiresAt, Token: first.Token,
		PriorSecretUID: "secret-uid", PriorResourceVersion: "42",
	}
	privateJSON, err := MarshalClientCredential(private)
	if err != nil {
		t.Fatal(err)
	}
	parsedPrivate, err := ParseClientCredential(privateJSON)
	if err != nil || parsedPrivate != private {
		t.Fatalf("private round trip = %#v, %v", parsedPrivate, err)
	}
}

func TestStrictCredentialJSON(t *testing.T) {
	credential, err := GenerateCredential(time.Date(2026, 10, 2, 1, 2, 3, 0, time.UTC), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	valid, _ := MarshalVerifierBundle(credential.Bundle)
	tests := [][]byte{
		bytes.Replace(valid, []byte(`"serial":1`), []byte(`"serial":1,"serial":2`), 1),
		bytes.Replace(valid, []byte(`"serial":1`), []byte(`"serial":1,"unknown":true`), 1),
		append(append([]byte(nil), valid...), []byte(` {}`)...),
		[]byte(`[]`),
		bytes.Repeat([]byte(" "), MaxVerifierBundleBytes+1),
	}
	for _, contents := range tests {
		if _, err := ParseVerifierBundle(contents); err == nil {
			t.Fatalf("accepted invalid verifier %q", string(contents[:min(len(contents), 160)]))
		}
	}
	private, _ := MarshalClientCredential(ClientCredential{
		Version: ClientCredentialVersion, CredentialID: credential.Bundle.CredentialID,
		Serial: 1, ExpiresAt: credential.Bundle.ExpiresAt, Token: credential.Token,
	})
	duplicate := bytes.Replace(private, []byte(`"serial":1`), []byte(`"serial":1,"serial":2`), 1)
	if _, err := ParseClientCredential(duplicate); err == nil {
		t.Fatal("accepted duplicate private credential field")
	}
	if strings.Contains(errInvalidCredential.Error(), credential.Token) {
		t.Fatal("fixed parse error exposed token")
	}
}

func TestManagedSecretLabelsReturnsCopy(t *testing.T) {
	first := ManagedSecretLabels()
	first[ManagedByLabelKey] = "changed"
	if ManagedSecretLabels()[ManagedByLabelKey] != ManagedByLabelValue {
		t.Fatal("managed labels share mutable state")
	}
}
