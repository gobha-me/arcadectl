// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
)

func TestCommandFailureDiagnosticsDoNotExposeRawErrors(t *testing.T) {
	var output bytes.Buffer
	writeFixedFailure(&output, errors.New("credential-canary-secret"))
	if strings.Contains(output.String(), "canary") {
		t.Fatal("raw error leaked")
	}
}

func TestCommandDefaultsToThirtyDayCredential(t *testing.T) {
	options, err := parseOptions([]string{"init", "--output", "/private/credential.json"})
	if err != nil || options.lifetime != 30*24*time.Hour || options.namespace != adminauth.CredentialNamespace {
		t.Fatalf("default options invalid: %v", err)
	}
}

func TestCommandTrustedNamespaceValidation(t *testing.T) {
	for _, namespace := range []string{"", "bad/namespace", "UPPER", "a.b", "-leading"} {
		if _, err := parseOptions([]string{"init", "--output", "/private/credential.json", "--namespace", namespace}); err == nil {
			t.Fatal("invalid trusted namespace accepted")
		}
	}
	options, err := parseOptions([]string{"init", "--output", "/private/credential.json", "--namespace", "isolated-install"})
	if err != nil || options.namespace != "isolated-install" {
		t.Fatal("trusted namespace not retained")
	}
}
