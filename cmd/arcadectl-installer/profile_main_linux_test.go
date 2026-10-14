// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installerprofile"
)

func TestInstallerProfileMainHelper(t *testing.T) {
	mode := os.Getenv("ARCADECTL_INSTALLER_MAIN_TEST_HELPER")
	if mode == "" {
		return
	}
	os.Args = []string{"arcadectl-installer"}
	if mode == "help" {
		os.Args = append(os.Args, "--help")
	}
	main() // Actual explicit Stop/os.Exit path; no cluster input or mutation.
}

func TestInstallerMainProfileDoesNotChangeHelpOrArgumentExit(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("owned installer test executable unavailable")
	}
	for _, mode := range []string{"help", "arguments"} {
		for _, enabled := range []bool{false, true} {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestInstallerProfileMainHelper$")
			cmd.Env = append(os.Environ(), "ARCADECTL_INSTALLER_MAIN_TEST_HELPER="+mode)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			var body []byte
			var diag error
			if enabled {
				capture, captureErr := installerprofile.NewCapture()
				if captureErr != nil {
					cancel()
					t.Fatal("owned installer capture unavailable")
				}
				body, diag, err = capture.Run(cmd)
				capture.Close()
				if diag != nil || len(body) == 0 {
					cancel()
					t.Fatal("actual main exited without explicit owned finalization")
				}
			} else {
				err = cmd.Run()
			}
			if ctx.Err() != nil || cmd.ProcessState == nil {
				cancel()
				t.Fatal("installer helper exceeded its existing budget")
			}
			cancel()
			if mode == "help" {
				if err != nil || cmd.ProcessState.ExitCode() != 0 || stdout.String() != usage || stderr.Len() != 0 {
					t.Fatal("profiling changed actual main help output or status")
				}
			} else if err == nil || cmd.ProcessState.ExitCode() != 2 || stdout.Len() != 0 || stderr.String() != errArguments.Error()+"\n" {
				t.Fatal("profiling changed actual main argument refusal output or status")
			}
		}
	}
}
