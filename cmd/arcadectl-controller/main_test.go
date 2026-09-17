// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
)

func TestManagerOptionsAreNamespaceScoped(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	options, err := managerOptions(scheme, "arcadectl-system", "0", ":8081", true)
	if err != nil {
		t.Fatalf("managerOptions() error = %v", err)
	}
	if options.Scheme != scheme {
		t.Fatal("manager options do not preserve the configured scheme")
	}
	if len(options.Cache.DefaultNamespaces) != 1 {
		t.Fatalf("default cache namespaces = %#v, want exactly one", options.Cache.DefaultNamespaces)
	}
	if _, exists := options.Cache.DefaultNamespaces["arcadectl-system"]; !exists {
		t.Fatalf("default cache namespaces = %#v, want arcadectl-system", options.Cache.DefaultNamespaces)
	}
	if options.LeaderElectionNamespace != "arcadectl-system" || !options.LeaderElection {
		t.Fatalf("leader election options = namespace %q enabled %t", options.LeaderElectionNamespace, options.LeaderElection)
	}
	if options.Metrics.BindAddress != "0" || options.HealthProbeBindAddress != ":8081" {
		t.Fatalf("listener options = metrics %q health %q", options.Metrics.BindAddress, options.HealthProbeBindAddress)
	}
}

func TestManagerOptionsRejectInvalidNamespace(t *testing.T) {
	t.Parallel()

	for _, namespace := range []string{"", "   ", "Not Valid"} {
		_, err := managerOptions(runtime.NewScheme(), namespace, "0", ":8081", false)
		if err == nil || (!strings.Contains(err.Error(), "namespace") && !strings.Contains(err.Error(), "required")) {
			t.Fatalf("managerOptions(%q) error = %v, want namespace validation", namespace, err)
		}
	}
}
