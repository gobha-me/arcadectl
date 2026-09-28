// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package backupworker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
)

func TestRunCreatesOneSnapshotAndVerifiesEveryFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	inputPath, credentialsPath, sourceRoot, workPath := workerFixture(t, root)
	runner := &fakeRunner{createdAt: time.Unix(1_700_000_000, 0).UTC()}
	result, err := Run(context.Background(), Config{
		InputPath: inputPath, CredentialsPath: credentialsPath, SourceRoot: sourceRoot, WorkPath: workPath,
		Runner: runner, Now: func() time.Time { return time.Unix(1_700_000_100, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Version != platformdata.BackupFormatVersion || result.ArtifactID != "backup-artifact" || result.PathCount != 2 || result.SizeBytes != 1234 {
		t.Fatalf("result = %#v", result)
	}
	if runner.backups != 1 || runner.checks != 1 || runner.dumps != 3 {
		t.Fatalf("runner calls: backups=%d checks=%d dumps=%d", runner.backups, runner.checks, runner.dumps)
	}
	for _, argument := range runner.arguments {
		if strings.Contains(argument, "repository-password-canary") || strings.Contains(argument, "secret-key-canary") {
			t.Fatalf("credential appeared in command argument %q", argument)
		}
	}
}

func TestRunReusesMatchingSnapshotWithoutDuplicate(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	inputPath, credentialsPath, sourceRoot, workPath := workerFixture(t, root)
	_, manifest, err := platformdata.BuildBackupManifest(platformdata.BackupWorkerInput{
		Version: platformdata.WorkerInputVersion, ArtifactID: "backup-artifact",
		OperationRef: platformdataTestOperation(), WorkerLeaseName: "data-operation-lease",
		RepositorySecretRef: platformdataTestRepository(), Source: platformdataTestSource(),
	}, sourceRoot)
	if err != nil {
		t.Fatalf("build expected manifest: %v", err)
	}
	runner := &fakeRunner{
		existing: true, createdAt: time.Unix(1_700_000_000, 0).UTC(),
		manifestTag: "arcadectl-manifest=" + strings.TrimPrefix(platformdata.ManifestDigest(manifest), "sha256:"),
	}
	if _, err := Run(context.Background(), Config{InputPath: inputPath, CredentialsPath: credentialsPath, SourceRoot: sourceRoot, WorkPath: workPath, Runner: runner}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if runner.backups != 0 {
		t.Fatalf("backup calls = %d, want reuse without another snapshot", runner.backups)
	}
}

func TestRunRetriesInterruptedWorkWithoutPublishingAnIncompleteSnapshot(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		configure       func(*fakeRunner)
		wantBackupCalls int
		wantCheckCalls  int
	}{
		{
			name: "upload before snapshot commit",
			configure: func(runner *fakeRunner) {
				runner.backupFailuresBeforeCommit = 1
			},
			wantBackupCalls: 2,
			wantCheckCalls:  1,
		},
		{
			name: "worker exit after snapshot commit",
			configure: func(runner *fakeRunner) {
				runner.backupFailuresAfterCommit = 1
			},
			wantBackupCalls: 1,
			wantCheckCalls:  1,
		},
		{
			name: "verification interruption",
			configure: func(runner *fakeRunner) {
				runner.checkFailures = 1
			},
			wantBackupCalls: 1,
			wantCheckCalls:  2,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			inputPath, credentialsPath, sourceRoot, workPath := workerFixture(t, root)
			runner := &fakeRunner{createdAt: time.Unix(1_700_000_000, 0).UTC()}
			test.configure(runner)
			config := Config{
				InputPath: inputPath, CredentialsPath: credentialsPath, SourceRoot: sourceRoot, WorkPath: workPath,
				Runner: runner, Now: func() time.Time { return time.Unix(1_700_000_100, 0).UTC() },
			}

			if result, err := Run(context.Background(), config); err == nil || result.ArtifactID != "" {
				t.Fatalf("first Run() = (%#v, %v), want failure without a published artifact", result, err)
			}
			result, err := Run(context.Background(), config)
			if err != nil {
				t.Fatalf("retry Run() error = %v", err)
			}
			if result.ArtifactID != "backup-artifact" || result.VerifiedAt.IsZero() {
				t.Fatalf("retry result = %#v, want verified artifact", result)
			}
			if runner.backups != test.wantBackupCalls || runner.checks != test.wantCheckCalls {
				t.Fatalf("runner calls: backups=%d checks=%d, want %d and %d", runner.backups, runner.checks, test.wantBackupCalls, test.wantCheckCalls)
			}
		})
	}
}

func TestCredentialFailureIsBoundedAndRedacted(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	inputPath, credentialsPath, sourceRoot, workPath := workerFixture(t, root)
	if err := os.WriteFile(filepath.Join(credentialsPath, "repository"), []byte("https://not-restic.example/repository-password-canary"), 0o600); err != nil {
		t.Fatalf("replace repository: %v", err)
	}
	_, err := Run(context.Background(), Config{InputPath: inputPath, CredentialsPath: credentialsPath, SourceRoot: sourceRoot, WorkPath: workPath, Runner: &fakeRunner{}})
	if err == nil || ExitCode(err) != 11 {
		t.Fatalf("Run() error = %v code=%d, want bounded credential failure", err, ExitCode(err))
	}
	combined := err.Error() + string(FailureMessage(err))
	if strings.Contains(combined, "repository-password-canary") || strings.Contains(combined, "https://") {
		t.Fatalf("failure reflected repository material: %q", combined)
	}
}

func workerFixture(t *testing.T, root string) (string, string, string, string) {
	t.Helper()
	inputPath := filepath.Join(root, "input.json")
	credentialsPath := filepath.Join(root, "credentials")
	sourceRoot := filepath.Join(root, "source")
	workPath := filepath.Join(root, "work")
	for _, directory := range []string{credentialsPath, filepath.Join(sourceRoot, "world"), filepath.Join(sourceRoot, "mods"), workPath} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", directory, err)
		}
	}
	input := platformdata.BackupWorkerInput{
		Version: platformdata.WorkerInputVersion, ArtifactID: "backup-artifact",
		OperationRef: platformdataTestOperation(), WorkerLeaseName: "data-operation-lease",
		RepositorySecretRef: platformdataTestRepository(), Source: platformdataTestSource(),
	}
	contents, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	if err := os.WriteFile(inputPath, contents, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	for name, contents := range map[string]string{
		"repository": "s3:http://minio.example/arcadectl", "password": "repository-password-canary",
		"awsAccessKeyID": "access-key", "awsSecretAccessKey": "secret-key-canary",
	} {
		if err := os.WriteFile(filepath.Join(credentialsPath, name), []byte(contents), 0o600); err != nil {
			t.Fatalf("write credential %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "world", "save.zip"), []byte("world"), 0o600); err != nil {
		t.Fatalf("write world: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "mods", "mod.json"), []byte("mods"), 0o600); err != nil {
		t.Fatalf("write mods: %v", err)
	}
	return inputPath, credentialsPath, sourceRoot, workPath
}

func platformdataTestOperation() v1alpha1.ExactLocalReference {
	return v1alpha1.ExactLocalReference{Name: "backup", UID: "backup-uid"}
}

func platformdataTestRepository() v1alpha1.ExactSecretReference {
	return v1alpha1.ExactSecretReference{
		ExactLocalReference: v1alpha1.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42",
	}
}

func platformdataTestSource() v1alpha1.DataSourceSnapshot {
	return v1alpha1.DataSourceSnapshot{
		GameServer: v1alpha1.ExactGameServerReference{
			ExactLocalReference: v1alpha1.ExactLocalReference{Name: "factory", UID: "server-uid"},
			Generation:          1, DesiredState: v1alpha1.DesiredStateStopped,
		},
		Game: "factorio", ImageDigest: "sha256:" + strings.Repeat("1", 64), SettingsDigest: "sha256:" + strings.Repeat("2", 64),
		Paths: []v1alpha1.DataPathIdentity{
			{Name: "world", MountPath: "/factorio", ClaimRef: v1alpha1.ExactLocalReference{Name: "world-pvc", UID: "world-uid"}},
			{Name: "mods", MountPath: "/mods", ClaimRef: v1alpha1.ExactLocalReference{Name: "mods-pvc", UID: "mods-uid"}},
		},
	}
}

type fakeRunner struct {
	existing                   bool
	backups                    int
	checks                     int
	dumps                      int
	createdAt                  time.Time
	arguments                  []string
	manifestTag                string
	backupFailuresBeforeCommit int
	backupFailuresAfterCommit  int
	checkFailures              int
}

func (runner *fakeRunner) Control(_ context.Context, _ map[string]string, arguments ...string) ([]byte, error) {
	runner.arguments = append(runner.arguments, arguments...)
	switch arguments[0] {
	case "snapshots":
		if !runner.existing {
			return []byte("[]"), nil
		}
		tag := ""
		for index, argument := range arguments {
			if argument == "--tag" && index+1 < len(arguments) {
				tag = arguments[index+1]
			}
		}
		return json.Marshal([]resticSnapshot{{ID: "snapshot-id", Time: runner.createdAt, Tags: []string{tag, runner.manifestTag}}})
	case "backup":
		runner.backups++
		for _, argument := range arguments {
			if strings.HasPrefix(argument, "arcadectl-manifest=") {
				runner.manifestTag = argument
			}
		}
		if runner.backupFailuresBeforeCommit > 0 {
			runner.backupFailuresBeforeCommit--
			return nil, errors.New("simulated interruption before commit")
		}
		runner.existing = true
		if runner.backupFailuresAfterCommit > 0 {
			runner.backupFailuresAfterCommit--
			return nil, errors.New("simulated interruption after commit")
		}
		return []byte("{}"), nil
	case "check":
		runner.checks++
		if runner.checkFailures > 0 {
			runner.checkFailures--
			return nil, errors.New("simulated verification interruption")
		}
		return nil, nil
	case "stats":
		return []byte(`{"total_size":1234}`), nil
	default:
		return nil, nil
	}
}

func (runner *fakeRunner) Stream(_ context.Context, _ map[string]string, destination io.Writer, arguments ...string) error {
	runner.arguments = append(runner.arguments, arguments...)
	runner.dumps++
	name := arguments[len(arguments)-1]
	contents, err := os.ReadFile(filepath.FromSlash(name))
	if err != nil {
		return err
	}
	_, err = destination.Write(contents)
	return err
}
