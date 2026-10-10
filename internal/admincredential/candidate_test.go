// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package admincredential

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
)

func TestInitialCandidatePrepareResumePreservesPrivateAndSecretFormat(t *testing.T) {
	now := time.Date(2026, 10, 5, 21, 0, 0, 0, time.UTC)
	c, err := PrepareInitialCandidate("isolated-install", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body := c.PrivateBytes()
	resumed, err := ResumeInitialCandidate("isolated-install", body, now.Add(time.Minute))
	if err != nil || !bytes.Equal(body, resumed.PrivateBytes()) {
		t.Fatal("resume regenerated candidate")
	}
	s, err := resumed.Secret()
	if err != nil || s.Name != adminauth.CredentialSecretName || s.Namespace != "isolated-install" || !reflect.DeepEqual(s.Labels, adminauth.ManagedSecretLabels()) || string(s.Type) != adminauth.CredentialSecretType || len(s.Data) != 2 {
		t.Fatal("Secret format changed")
	}
	if _, _, err := validateManagedSecret(s, "isolated-install"); err != nil {
		t.Fatal(err)
	}
	body[0] = 'X'
	s.Labels["foreign"] = "true"
	s.Data[adminauth.TokenSecretKey][0] = 'X'
	newSecret, err := resumed.Secret()
	if err != nil || bytes.Equal(body, resumed.PrivateBytes()) || newSecret.Labels["foreign"] != "" {
		t.Fatal("mutable candidate escaped")
	}
	if _, _, err := validateManagedSecret(newSecret, "isolated-install"); err != nil {
		t.Fatal("Secret bytes escaped")
	}
}

func TestInitialCandidateRefusesExpiryRotationAndMalformedInputs(t *testing.T) {
	now := time.Date(2026, 10, 5, 21, 0, 0, 0, time.UTC)
	c, err := PrepareInitialCandidate("isolated-install", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResumeInitialCandidate("isolated-install", c.PrivateBytes(), now.Add(time.Hour)); !errors.Is(err, ErrInvalidManagedSecret) {
		t.Fatal("expired candidate regenerated/accepted")
	}
	private, err := adminauth.ParseClientCredential(c.PrivateBytes())
	if err != nil {
		t.Fatal(err)
	}
	private.Serial = 2
	private.PriorSecretUID = "original"
	private.PriorResourceVersion = "42"
	body, err := adminauth.MarshalClientCredential(private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResumeInitialCandidate("isolated-install", body, now); !errors.Is(err, ErrInvalidManagedSecret) {
		t.Fatal("rotation candidate admitted as initial")
	}
	if _, err := PrepareInitialCandidate("", now, time.Hour); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("unscoped candidate")
	}
	if _, err := PrepareInitialCandidate("isolated-install", time.Time{}, time.Hour); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("zero clock accepted")
	}
	if _, err := ResumeInitialCandidate("isolated-install", c.PrivateBytes(), time.Time{}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("zero resume clock accepted")
	}
	if _, err := ResumeInitialCandidate("isolated-install", []byte(`{"token":"PRIVATE-CANARY"}`), now); !errors.Is(err, ErrInvalidManagedSecret) {
		t.Fatal("malformed candidate")
	}
}
