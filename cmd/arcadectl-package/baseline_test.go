// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installfiles"
	"github.com/gobha-me/arcadectl/internal/installrender"
)

func baselineBuildArgs(parent, private, public, name string) []string {
	return []string{"build-baseline", "--output", filepath.Join(parent, name), "--signing-key", private, "--trust-key", public, "--source-sha", strings.Repeat("a", 40), "--source-epoch", "1791500000"}
}

func TestBaselineCommandBuildVerifyReproducibleAndSeparate(t *testing.T) {
	parent, private, public, key := fixture(t)
	first := baselineBuildArgs(parent, private, public, "first")
	output, diagnostics := invoke(t, first, 0)
	if diagnostics != "" || !strings.HasPrefix(output, "security baseline "+installbaseline.Version+" sha256:") || strings.Contains(output, parent) {
		t.Fatal("baseline command public output is not bounded")
	}
	second, _ := invoke(t, baselineBuildArgs(parent, private, public, "second"), 0)
	if output != second {
		t.Fatal("baseline command changed reproducible artifact identity")
	}
	verify := []string{"verify-baseline", "--baseline", filepath.Join(parent, "first"), "--trust-key", public}
	verified, _ := invoke(t, verify, 0)
	if verified != output {
		t.Fatal("baseline verification changed signed identity")
	}
	if _, diagnostics := invoke(t, first, 1); diagnostics != installfiles.ErrExists.Error()+"\n" {
		t.Fatal("baseline command overwrote existing output")
	}
	for _, name := range []string{installfiles.ManifestName, installfiles.SignatureName, installfiles.BaselinePayloadName} {
		a, errA := os.ReadFile(filepath.Join(parent, "first", name))
		b, errB := os.ReadFile(filepath.Join(parent, "second", name))
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			t.Fatal("baseline command changed exact artifact bytes")
		}
	}
	artifact, err := installfiles.LoadBaseline(filepath.Join(parent, "first"), key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal("baseline command published unauthenticated output")
	}
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		if _, err := installbaseline.Compile(artifact, "isolated-baseline", profile); err != nil {
			t.Fatal("baseline command output does not support declared profile")
		}
	}
	invoke(t, []string{"verify", "--package", filepath.Join(parent, "first"), "--trust-key", public}, 1)
	invoke(t, buildArgs(parent, private, public, "runtime", strings.Repeat("a", 40)), 0)
	invoke(t, []string{"verify-baseline", "--baseline", filepath.Join(parent, "runtime"), "--trust-key", public}, 1)
}

func TestBaselineCommandArgumentsAndTrustRefuseBeforePublication(t *testing.T) {
	for _, scenario := range []string{"missing-output", "missing-key", "missing-trust", "missing-source", "missing-epoch", "legacy-source", "source-canary", "unknown-option", "trailing-argument", "wrong-trust", "relative-output"} {
		t.Run(scenario, func(t *testing.T) {
			parent, private, public, _ := fixture(t)
			args := baselineBuildArgs(parent, private, public, "candidate")
			want := 2
			switch scenario {
			case "missing-output":
				args[2] = ""
			case "missing-key":
				args[4] = ""
			case "missing-trust":
				args[6] = ""
			case "missing-source":
				args[8] = ""
			case "missing-epoch":
				args[10] = "0"
			case "legacy-source":
				args[8] = installrender.LegacySourceSHA
			case "source-canary":
				args[8], want = "INPUT-CANARY-MUST-NOT-ECHO", 1
			case "unknown-option":
				args = append(args, "--INPUT-CANARY-MUST-NOT-ECHO")
			case "trailing-argument":
				args = append(args, "INPUT-CANARY-MUST-NOT-ECHO")
			case "wrong-trust":
				_, _, wrongPublic, _ := fixture(t)
				// Fixtures use the same fake key. Mutate only this task-owned
				// public file to an invalid explicit key, never discover trust.
				if os.WriteFile(wrongPublic, []byte("INPUT-CANARY-MUST-NOT-ECHO"), 0644) != nil {
					t.Fatal("wrong trust fixture unavailable")
				}
				args[6], want = wrongPublic, 1
			case "relative-output":
				args[2], want = "INPUT-CANARY-MUST-NOT-ECHO", 1
			}
			output, diagnostics := invoke(t, args, want)
			if output != "" || strings.Contains(diagnostics, "INPUT-CANARY-MUST-NOT-ECHO") || strings.Contains(diagnostics, parent) {
				t.Fatal("baseline command reflected private inputs")
			}
			if _, err := os.Lstat(filepath.Join(parent, "candidate")); !os.IsNotExist(err) {
				t.Fatal("rejected baseline command caused publication effects")
			}
		})
	}
	for _, args := range [][]string{{"verify-baseline"}, {"verify-baseline", "--package", "INPUT-CANARY-MUST-NOT-ECHO"}, {"verify-baseline", "--baseline", "INPUT-CANARY-MUST-NOT-ECHO"}} {
		output, diagnostics := invoke(t, args, 2)
		if output != "" || strings.Contains(diagnostics, "INPUT-CANARY-MUST-NOT-ECHO") {
			t.Fatal("baseline verification arguments reflected inputs")
		}
	}
}

func TestBaselineCommandStdoutFailurePreservesPublishedArtifact(t *testing.T) {
	for _, writer := range []interface{ Write([]byte) (int, error) }{brokenWriter{}, shortWriter{}} {
		parent, private, public, _ := fixture(t)
		var diagnostics bytes.Buffer
		if code := run(baselineBuildArgs(parent, private, public, "candidate"), writer, &diagnostics); code != 1 || diagnostics.String() != "package command output unavailable; preserve and verify existing output\n" {
			t.Fatal("baseline build hid output failure or reflected error")
		}
		args := []string{"verify-baseline", "--baseline", filepath.Join(parent, "candidate"), "--trust-key", public}
		invoke(t, args, 0)
		diagnostics.Reset()
		if code := run(args, writer, &diagnostics); code != 1 || diagnostics.String() != "package command output unavailable; preserve and verify existing output\n" {
			t.Fatal("baseline verification hid output failure or reflected error")
		}
		invoke(t, args, 0)
	}
}

// This exercises the actual executable boundary, not run() instrumentation.
// It publishes only offline test-signed artifacts; no cluster is contacted.
func TestBaselineCommandActualExecutable(t *testing.T) {
	parent, private, public, key := fixture(t)
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("repository source for executable fixture unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	binary := filepath.Join(parent, "arcadectl-package")
	build := exec.CommandContext(ctx, "go", "build", "-p", "1", "-trimpath", "-o", binary, "./cmd/arcadectl-package")
	build.Dir = root
	build.Env = append(os.Environ(), "GOMAXPROCS=2", "GOMEMLIMIT=1GiB")
	if _, err := build.CombinedOutput(); err != nil {
		t.Fatal("actual packager executable fixture build failed")
	}
	runBinary := func(args []string, want int) string {
		t.Helper()
		command := exec.CommandContext(ctx, binary, args...)
		command.Dir = parent
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("actual packager executable did not complete")
			}
			code = exit.ExitCode()
		}
		if code != want || strings.Contains(stdout.String()+stderr.String(), parent) || strings.Contains(stdout.String()+stderr.String(), "INPUT-CANARY-MUST-NOT-ECHO") || want == 0 && stderr.Len() != 0 || want != 0 && stdout.Len() != 0 {
			t.Fatal("actual packager executable changed refusal/output boundary", code)
		}
		return stdout.String()
	}
	args := baselineBuildArgs(parent, private, public, "candidate")
	output := runBinary(args, 0)
	if !strings.HasPrefix(output, "security baseline "+installbaseline.Version+" sha256:") {
		t.Fatal("actual packager executable output lost signed baseline identity")
	}
	verify := []string{"verify-baseline", "--baseline", filepath.Join(parent, "candidate"), "--trust-key", public}
	if runBinary(verify, 0) != output {
		t.Fatal("actual executable verification changed signed artifact identity")
	}
	artifact, err := installfiles.LoadBaseline(filepath.Join(parent, "candidate"), key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal("actual executable output did not authenticate independently")
	}
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		if _, err := installbaseline.Compile(artifact, "isolated-binary", profile); err != nil {
			t.Fatal("actual executable output failed independent semantic compilation")
		}
	}
	runBinary(args, 1) // must not replace the original published artifact
	if runBinary(verify, 0) != output {
		t.Fatal("actual executable collision corrupted original output")
	}
	bad := append([]string{}, args...)
	bad[2], bad[8] = filepath.Join(parent, "invalid"), "INPUT-CANARY-MUST-NOT-ECHO"
	runBinary(bad, 1)
	if _, err := os.Lstat(filepath.Join(parent, "invalid")); !os.IsNotExist(err) {
		t.Fatal("actual executable invalid inputs caused publication effects")
	}
}
