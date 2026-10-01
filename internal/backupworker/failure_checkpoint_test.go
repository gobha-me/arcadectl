// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package backupworker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type checkpointRunner struct {
	*fakeRunner
	failStats bool
}

func (runner *checkpointRunner) Control(ctx context.Context, environment map[string]string, arguments ...string) ([]byte, error) {
	if runner.failStats && arguments[0] == "stats" {
		return nil, errors.New("credential-canary")
	}
	return runner.fakeRunner.Control(ctx, environment, arguments...)
}

func TestVerificationFailuresPublishOnlyFixedCheckpoints(t *testing.T) {
	t.Parallel()
	for _, checkpoint := range []verificationCheckpoint{
		checkpointSnapshotSelection, checkpointRepositoryCheck, checkpointManifest,
		checkpointInventory, checkpointFile, checkpointSourceRecheck, checkpointStats,
	} {
		t.Run(string(checkpoint), func(t *testing.T) {
			input, credentials, source, work := workerFixture(t, t.TempDir())
			runner := &checkpointRunner{fakeRunner: &fakeRunner{createdAt: time.Unix(1_700_000_000, 0).UTC()}}
			runner.afterCommit = func(runner *fakeRunner) {
				switch checkpoint {
				case checkpointSnapshotSelection:
					runner.manifestTag = "credential-canary"
				case checkpointRepositoryCheck:
					runner.checkFailures = 1
				case checkpointManifest:
					runner.repository[filepath.ToSlash(filepath.Join(work, manifestName))] = []byte("credential-canary")
				case checkpointInventory:
					runner.inventory = []byte("credential-canary")
				case checkpointFile:
					runner.repository[filepath.ToSlash(filepath.Join(source, "world", "save.zip"))] = []byte("credential-canary")
				case checkpointSourceRecheck:
					if err := os.WriteFile(filepath.Join(source, "world", "save.zip"), []byte("changed-world"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			runner.failStats = checkpoint == checkpointStats
			result, err := Run(context.Background(), Config{InputPath: input, CredentialsPath: credentials, SourceRoot: source, WorkPath: work, Runner: runner})
			if err == nil || ExitCode(err) != 30 || result.ArtifactID != "" {
				t.Fatalf("verification failure published an artifact: result=%#v err=%v", result, err)
			}
			var message struct {
				Failure    FailureKind            `json:"failure"`
				Checkpoint verificationCheckpoint `json:"checkpoint"`
			}
			if json.Unmarshal(FailureMessage(err), &message) != nil || message.Failure != FailureVerification || message.Checkpoint != checkpoint {
				t.Fatalf("wrong bounded checkpoint: %s", FailureMessage(err))
			}
			if strings.Contains(err.Error()+string(FailureMessage(err)), "canary") {
				t.Fatal("untrusted verification details escaped")
			}
		})
	}
}

func TestFailureMessageRejectsForgedKindAndCheckpoint(t *testing.T) {
	t.Parallel()
	for _, failure := range []*Failure{
		{Kind: FailureKind("credential-canary"), checkpoint: checkpointRepositoryCheck},
		{Kind: FailureVerification, checkpoint: verificationCheckpoint("credential-canary")},
		{Kind: FailureRepository, checkpoint: checkpointRepositoryCheck},
	} {
		if strings.Contains(failure.Error()+string(FailureMessage(failure)), "canary") {
			t.Fatal("forged failure leaked material")
		}
		var message map[string]string
		if json.Unmarshal(FailureMessage(failure), &message) != nil || message["checkpoint"] != "" {
			t.Fatalf("forged or non-verification checkpoint was emitted: %s", FailureMessage(failure))
		}
	}
}
