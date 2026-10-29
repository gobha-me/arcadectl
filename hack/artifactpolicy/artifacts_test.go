// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package artifactpolicy

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Keep actual archive/checksum/refusal tests in ordinary go-test discovery.
func TestArtifactPackaging(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(source), "..", "..")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-B", "-m", "unittest", "discover", "-s", "hack", "-p", "test_pack_cli_artifacts.py")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("artifact packaging tests failed: %s", output)
	}
}
