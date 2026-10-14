//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installerprofile"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"golang.org/x/sys/unix"
)

func installerBinaryCPUAttempt(command *exec.Cmd, create func() (*installerprofile.Capture, error)) ([]byte, error, error) {
	capture, err := create()
	if err != nil || capture == nil {
		if capture != nil {
			capture.Close()
		}
		// Setup has not launched anything. Run the unchanged command exactly
		// once without profiling; diagnostic failure is never its exit status.
		return nil, ErrFixtures, command.Run()
	}
	defer capture.Close()
	return capture.Run(command)
}

// Hash only the already-built current executable in the private fixture base.
// This is diagnostic custody, not a replacement for signed installation inputs.
func installerBinaryCPUDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", ErrFixtures
	}
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(int(file.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Mode&0022 != 0 || before.Size <= 0 || before.Size > 256*1024*1024 {
		return "", ErrFixtures
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, 256*1024*1024+1))
	if err != nil || n != before.Size || unix.Fstat(int(file.Fd()), &after) != nil {
		return "", ErrFixtures
	}
	before.Atim = after.Atim // Reading may change only the access timestamp.
	if before != after {
		return "", ErrFixtures
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type installerBinaryCPURecord struct {
	Format          string                       `json:"format"`
	Scope           string                       `json:"scope"`
	SourceSHA       string                       `json:"sourceSHA"`
	SourceDirty     bool                         `json:"sourceDirty"`
	BinarySHA256    string                       `json:"binarySHA256"`
	Profile         string                       `json:"profile"`
	Mode            string                       `json:"mode"`
	Command         string                       `json:"command"`
	CommandOutcome  string                       `json:"commandOutcome"`
	Diagnostic      string                       `json:"diagnostic"`
	FlushTimeliness string                       `json:"flushTimeliness"`
	CPU             *installerprofile.CPUSummary `json:"cpu,omitempty"`
}

func installerBinaryCPURecordBytes(source, digest, profile, mode, command, outcome, diagnostic string, dirty bool, summary *installerprofile.CPUSummary) ([]byte, error) {
	hexadecimal := func(value string, size int) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == size && value == strings.ToLower(value)
	}
	if !hexadecimal(source, 20) || !hexadecimal(digest, 32) || profile != installrender.Profile135 && profile != installrender.Profile137 || mode != "fresh" && mode != "transition" {
		return nil, ErrFixtures
	}
	switch command {
	case "install", "enroll-baseline", "upgrade", "rollback", "uninstall", "resume":
	default:
		return nil, ErrFixtures
	}
	switch outcome {
	case "success", "exit-failure", "terminated", "launch-failure":
	default:
		return nil, ErrFixtures
	}
	switch diagnostic {
	case "available":
		if summary == nil || outcome == "terminated" || outcome == "launch-failure" {
			return nil, ErrFixtures
		}
	case "capture-incomplete", "cpu-format-unavailable":
		if summary != nil {
			return nil, ErrFixtures
		}
	default:
		return nil, ErrFixtures
	}
	return json.Marshal(installerBinaryCPURecord{
		Format: "installer-child-cpu-summary-v1", Scope: "same-attempt-current-child-cpu-only",
		SourceSHA: source, SourceDirty: dirty, BinarySHA256: digest, Profile: profile, Mode: mode,
		Command: command, CommandOutcome: outcome, Diagnostic: diagnostic,
		FlushTimeliness: "not-certified", CPU: summary,
	})
}

func TestInstallerBinaryCPURecordClosedCustody(t *testing.T) {
	source, digest := strings.Repeat("a", 40), strings.Repeat("b", 64)
	for _, mode := range []string{"fresh", "transition"} {
		for _, outcome := range []string{"success", "exit-failure", "terminated", "launch-failure"} {
			body, err := installerBinaryCPURecordBytes(source, digest, installrender.Profile137, mode, "upgrade", outcome, "capture-incomplete", false, nil)
			if err != nil || !json.Valid(body) || !strings.Contains(string(body), `"flushTimeliness":"not-certified"`) {
				t.Fatal("closed diagnostic custody unavailable or inferred timely flush")
			}
		}
	}
	for _, scenario := range []string{"source", "digest", "profile", "mode", "command", "outcome", "diagnostic"} {
		values := []string{source, digest, installrender.Profile137, "transition", "upgrade", "exit-failure", "capture-incomplete"}
		for i, field := range []string{"source", "digest", "profile", "mode", "command", "outcome", "diagnostic"} {
			if field == scenario {
				values[i] = "PRIVATE-CANARY"
			}
		}
		if _, err := installerBinaryCPURecordBytes(values[0], values[1], values[2], values[3], values[4], values[5], values[6], false, nil); err == nil {
			t.Fatal("unreviewed diagnostic custody escaped fixed fields")
		}
	}
	if _, err := installerBinaryCPURecordBytes(source, digest, installrender.Profile137, "transition", "upgrade", "exit-failure", "available", false, nil); err == nil {
		t.Fatal("nil CPU record claimed available")
	}
}

func TestInstallerBinaryCPUSetupFailureRunsUnchangedCommandOnce(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "printf 'unchanged-output'; printf 'unchanged-error' >&2; exit 7")
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	setups := 0
	body, diag, err := installerBinaryCPUAttempt(command, func() (*installerprofile.Capture, error) { setups++; return nil, ErrFixtures })
	if setups != 1 || len(body) != 0 || diag == nil || err == nil || command.ProcessState == nil || command.ProcessState.ExitCode() != 7 || stdout.String() != "unchanged-output" || stderr.String() != "unchanged-error" || len(command.ExtraFiles) != 0 {
		t.Fatal("profile setup failure changed command output/status or requested replay")
	}
}
