// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package restoreworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	"k8s.io/apimachinery/pkg/types"
)

const testSnapshotID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fixture struct {
	input       Input
	manifest    []byte
	inventory   []byte
	files       map[string][]byte
	inputPath   string
	credentials string
	candidates  string
	work        string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	sourceRoot := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(sourceRoot, "state", "maps"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(sourceRoot, "state", "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "state", "maps", "save.zip"), []byte("verified world data"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupRef := arcadev1alpha1.ExactLocalReference{Name: "backup", UID: "backup-uid"}
	repository := arcadev1alpha1.ExactSecretReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42"}
	source := arcadev1alpha1.DataSourceSnapshot{
		GameServer: arcadev1alpha1.ExactGameServerReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "original", UID: "original-uid"}, Generation: 1, DesiredState: arcadev1alpha1.DesiredStateStopped},
		Game:       "factorio", ImageDigest: "sha256:" + strings.Repeat("a", 64), SettingsDigest: "sha256:" + strings.Repeat("b", 64),
		Paths: []arcadev1alpha1.DataPathIdentity{{Name: "state", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "old-world", UID: "old-world-uid"}}},
	}
	artifactID, err := platformdata.ArtifactID(types.UID(backupRef.UID))
	if err != nil {
		t.Fatal(err)
	}
	backupInput := platformdata.BackupWorkerInput{Version: platformdata.WorkerInputVersion, ArtifactID: artifactID, OperationRef: backupRef, WorkerLeaseName: "data-operation-test", RepositorySecretRef: repository, Source: source}
	manifest, manifestBytes, err := platformdata.BuildBackupManifest(backupInput, sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{
		Version: InputVersion, Stage: StagePreflight,
		OperationRef:    arcadev1alpha1.ExactLocalReference{Name: "restore", UID: "restore-uid"},
		BackupRef:       backupRef,
		Target:          arcadev1alpha1.ExactGameServerReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "target", UID: "target-uid"}, Generation: 1, DesiredState: arcadev1alpha1.DesiredStateStopped},
		WorkerLeaseName: "data-operation-test", RepositorySecretRef: repository,
		Artifact: arcadev1alpha1.BackupArtifact{
			Provenance: arcadev1alpha1.ArtifactProvenance{BackupRef: backupRef, RepositorySecretRef: repository},
			ID:         artifactID, FormatVersion: platformdata.BackupFormatVersion, ManifestDigest: platformdata.ManifestDigest(manifestBytes),
			PathCount: 1, Verification: arcadev1alpha1.ArtifactVerification{Result: arcadev1alpha1.VerificationVerified},
		},
		Source: source, TargetGame: source.Game, TargetImageDigest: source.ImageDigest, TargetSettingsDigest: source.SettingsDigest,
		TargetPaths: []PathContract{{Name: "state", MountPath: "/factorio"}},
	}
	inventory := makeInventory(t, manifest, int64(len(manifestBytes)))
	credentials := filepath.Join(root, "credentials")
	if err := os.Mkdir(credentials, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		platformdata.RepositoryKeyRepository:      "s3:http://minio.example/arcadectl",
		platformdata.RepositoryKeyPassword:        "password-canary",
		platformdata.RepositoryKeyAccessKeyID:     "access-canary",
		platformdata.RepositoryKeySecretAccessKey: "secret-canary",
	} {
		if err := os.WriteFile(filepath.Join(credentials, name), []byte(value), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{
		DefaultManifestPath: manifestBytes,
		filepath.ToSlash(filepath.Join(DefaultSourceRoot, "state", "maps", "save.zip")): []byte("verified world data"),
	}
	return fixture{
		input: input, manifest: manifestBytes, inventory: inventory, files: files,
		inputPath: filepath.Join(root, "input.json"), credentials: credentials,
		candidates: filepath.Join(root, "candidate"), work: filepath.Join(root, "work"),
	}
}

func makeInventory(t *testing.T, manifest platformdata.BackupManifest, manifestSize int64) []byte {
	t.Helper()
	records := []resticInventoryRecord{{StructType: "snapshot", ID: testSnapshotID}}
	for _, path := range manifest.Paths {
		root := filepath.ToSlash(filepath.Join(DefaultSourceRoot, path.Name))
		records = append(records, resticInventoryRecord{StructType: "node", Path: root, Type: "dir"})
		for _, dir := range path.Directories {
			records = append(records, resticInventoryRecord{StructType: "node", Path: filepath.ToSlash(filepath.Join(root, dir)), Type: "dir"})
		}
		for _, file := range path.Files {
			records = append(records, resticInventoryRecord{StructType: "node", Path: filepath.ToSlash(filepath.Join(root, file.Path)), Type: "file", Size: file.Size})
		}
	}
	records = append(records, resticInventoryRecord{StructType: "node", Path: DefaultManifestPath, Type: "file", Size: manifestSize})
	var output []byte
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		output = append(output, line...)
		output = append(output, '\n')
	}
	return output
}

func (f fixture) config(t *testing.T, runner Runner) Config {
	t.Helper()
	contents, err := json.Marshal(f.input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.inputPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{InputPath: f.inputPath, CredentialsPath: f.credentials, CandidateRoot: f.candidates, WorkPath: f.work, Runner: runner,
		Now: func() time.Time { return time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC) }}
}

type fakeRunner struct {
	fixture          fixture
	fileDumps        int
	failFileDump     int
	oversizePopulate bool
	corruptManifest  bool
	inventory        []byte
}

func (runner *fakeRunner) Control(_ context.Context, _ map[string]string, args ...string) ([]byte, error) {
	switch args[0] {
	case "snapshots":
		return json.Marshal([]snapshot{{ID: testSnapshotID, Tags: []string{"arcadectl-artifact=" + runner.fixture.input.Artifact.ID, "arcadectl-manifest=" + strings.TrimPrefix(runner.fixture.input.Artifact.ManifestDigest, "sha256:")}}})
	case "check":
		return []byte(""), nil
	default:
		return nil, errors.New("unsupported fake control")
	}
}

func (runner *fakeRunner) Stream(_ context.Context, _ map[string]string, destination io.Writer, args ...string) error {
	switch args[0] {
	case "ls":
		data := runner.fixture.inventory
		if runner.inventory != nil {
			data = runner.inventory
		}
		_, err := destination.Write(data)
		return err
	case "dump":
		data, found := runner.fixture.files[args[len(args)-1]]
		if !found {
			return errors.New("missing fake repository file")
		}
		if args[len(args)-1] == DefaultManifestPath && runner.corruptManifest {
			data = []byte("corrupt manifest\n")
		}
		if args[len(args)-1] != DefaultManifestPath {
			runner.fileDumps++
			if runner.oversizePopulate && runner.fileDumps == 2 {
				data = append(bytes.Clone(data), 'x')
			}
			if runner.fileDumps == runner.failFileDump {
				_, _ = destination.Write(data[:len(data)/2])
				return errors.New("repository secret-canary must not escape")
			}
		}
		_, err := destination.Write(data)
		return err
	default:
		return errors.New("unsupported fake stream")
	}
}

func TestPopulateBoundsChangedDumpAndLeavesActiveWorldUntouched(t *testing.T) {
	f := newFixture(t)
	f.input.Stage = StagePopulate
	f.input.PreviousDataIdentity = "data-previous"
	f.input.PreviousData = []arcadev1alpha1.DataPathIdentity{{Name: "state", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "previous-world", UID: "previous-uid"}}}
	candidateName, err := platformdata.RestoreCandidateID(types.UID(f.input.OperationRef.UID), "state")
	if err != nil {
		t.Fatal(err)
	}
	f.input.CandidatePaths = []arcadev1alpha1.DataPathIdentity{{Name: "state", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: candidateName, UID: "candidate-uid"}}}
	if err := os.MkdirAll(filepath.Join(f.candidates, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(filepath.Dir(f.candidates), "active-world")
	if err := os.WriteFile(active, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), f.config(t, &fakeRunner{fixture: f, oversizePopulate: true})); err == nil {
		t.Fatal("oversized repository dump was written to candidate")
	}
	contents, err := os.ReadFile(active)
	if err != nil || string(contents) != "untouched" {
		t.Fatalf("active world changed: %q %v", contents, err)
	}
	info, err := os.Stat(filepath.Join(f.candidates, "state", "maps", "save.zip"))
	if err != nil || info.Size() != 0 {
		t.Fatalf("oversized dump wrote candidate bytes: %v %v", info, err)
	}
}

func TestPopulateRejectsCandidateSymlinkOrHardlink(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.input.Stage = StagePopulate
			f.input.PreviousDataIdentity = "data-previous"
			f.input.PreviousData = []arcadev1alpha1.DataPathIdentity{{Name: "state", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "previous-world", UID: "previous-uid"}}}
			candidateName, err := platformdata.RestoreCandidateID(types.UID(f.input.OperationRef.UID), "state")
			if err != nil {
				t.Fatal(err)
			}
			f.input.CandidatePaths = []arcadev1alpha1.DataPathIdentity{{Name: "state", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: candidateName, UID: "candidate-uid"}}}
			maps := filepath.Join(f.candidates, "state", "maps")
			if err := os.MkdirAll(maps, 0o700); err != nil {
				t.Fatal(err)
			}
			active := filepath.Join(filepath.Dir(f.candidates), "active-world")
			if err := os.WriteFile(active, []byte("untouched"), 0o600); err != nil {
				t.Fatal(err)
			}
			candidate := filepath.Join(maps, "save.zip")
			if kind == "symlink" {
				err = os.Symlink(active, candidate)
			} else {
				err = os.Link(active, candidate)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Run(context.Background(), f.config(t, &fakeRunner{fixture: f})); err == nil {
				t.Fatal("unsafe candidate alias accepted")
			}
			contents, err := os.ReadFile(active)
			if err != nil || string(contents) != "untouched" {
				t.Fatalf("active alias changed: %q %v", contents, err)
			}
		})
	}
}

func TestPreflightVerifiesRepositoryWithoutCandidateMount(t *testing.T) {
	f := newFixture(t)
	runner := &fakeRunner{fixture: f}
	result, err := Run(context.Background(), f.config(t, runner))
	if err != nil {
		t.Fatalf("preflight failed: %v", err)
	}
	if result.Stage != StagePreflight || result.ManifestDigest != f.input.Artifact.ManifestDigest {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, err := os.Lstat(f.candidates); !os.IsNotExist(err) {
		t.Fatalf("preflight touched candidate path: %v", err)
	}
	message, err := SuccessMessage(result)
	if err != nil || bytes.Contains(message, []byte("canary")) {
		t.Fatalf("unsafe result: %q %v", message, err)
	}
}

func TestInputRejectsV1CrossGameAndCandidatePreflight(t *testing.T) {
	f := newFixture(t)
	for _, mutate := range []func(*Input){
		func(input *Input) { input.Artifact.FormatVersion = "arcadectl.backup/v1" },
		func(input *Input) { input.TargetGame = "other-game" },
		func(input *Input) { input.TargetImageDigest = "sha256:" + strings.Repeat("c", 64) },
		func(input *Input) { input.TargetSettingsDigest = "sha256:" + strings.Repeat("c", 64) },
		func(input *Input) { input.TargetPaths[0].MountPath = "/other" },
		func(input *Input) { input.CandidatePaths = append(input.CandidatePaths, input.Source.Paths[0]) },
	} {
		input := f.input
		input.TargetPaths = append([]PathContract(nil), input.TargetPaths...)
		mutate(&input)
		if err := ValidateInput(input); err == nil {
			t.Fatalf("unsafe input accepted: %+v", input)
		}
	}
}

func TestCorruptManifestAndUnsafeInventoryNeverTouchCandidate(t *testing.T) {
	for _, kind := range []string{"manifest", "inventory"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.input.Stage = StagePopulate
			f.input.PreviousDataIdentity = "data-previous"
			f.input.PreviousData = []arcadev1alpha1.DataPathIdentity{{Name: "state", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "previous-world", UID: "previous-uid"}}}
			candidateName, err := platformdata.RestoreCandidateID(types.UID(f.input.OperationRef.UID), "state")
			if err != nil {
				t.Fatal(err)
			}
			f.input.CandidatePaths = []arcadev1alpha1.DataPathIdentity{{Name: "state", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: candidateName, UID: "candidate-uid"}}}
			if err := os.MkdirAll(filepath.Join(f.candidates, "state"), 0o700); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(filepath.Dir(f.candidates), "active-world-sentinel")
			if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
				t.Fatal(err)
			}
			runner := &fakeRunner{fixture: f, corruptManifest: kind == "manifest"}
			if kind == "inventory" {
				unsafe := resticInventoryRecord{StructType: "node", Path: "/arcadectl/source/state/unsafe", Type: "symlink"}
				encoded, _ := json.Marshal(unsafe)
				runner.inventory = append(append([]byte(nil), f.inventory...), append(encoded, '\n')...)
			}
			_, err = Run(context.Background(), f.config(t, runner))
			if err == nil || strings.Contains(err.Error(), "canary") {
				t.Fatalf("unsafe result: %v", err)
			}
			contents, readErr := os.ReadFile(sentinel)
			if readErr != nil || string(contents) != "untouched" {
				t.Fatalf("candidate mutated before verification: %q %v", contents, readErr)
			}
			entries, readErr := os.ReadDir(filepath.Join(f.candidates, "state"))
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("candidate was populated before verification: %d entries, %v", len(entries), readErr)
			}
		})
	}
}

func TestPopulateRestoresDirectoriesAndFilesAndRetriesPartial(t *testing.T) {
	f := newFixture(t)
	f.input.Stage = StagePopulate
	f.input.PreviousDataIdentity = "data-previous"
	f.input.PreviousData = []arcadev1alpha1.DataPathIdentity{{Name: "state", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "previous-world", UID: "previous-uid"}}}
	candidateName, err := platformdata.RestoreCandidateID(types.UID(f.input.OperationRef.UID), "state")
	if err != nil {
		t.Fatal(err)
	}
	f.input.CandidatePaths = []arcadev1alpha1.DataPathIdentity{{Name: "state", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: candidateName, UID: "candidate-uid"}}}
	if err := os.MkdirAll(filepath.Join(f.candidates, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	partialRunner := &fakeRunner{fixture: f, failFileDump: 2}
	if _, err := Run(context.Background(), f.config(t, partialRunner)); err == nil {
		t.Fatal("interrupted candidate write succeeded")
	}
	partial, err := os.ReadFile(filepath.Join(f.candidates, "state", "maps", "save.zip"))
	if err != nil || len(partial) == len(f.files[filepath.ToSlash(filepath.Join(DefaultSourceRoot, "state", "maps", "save.zip"))]) {
		t.Fatalf("partial candidate not retained: %q %v", partial, err)
	}
	goodRunner := &fakeRunner{fixture: f}
	result, err := Run(context.Background(), f.config(t, goodRunner))
	if err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if result.Stage != StagePopulate {
		t.Fatalf("wrong stage: %+v", result)
	}
	if info, err := os.Stat(filepath.Join(f.candidates, "state", "empty")); err != nil || !info.IsDir() {
		t.Fatalf("empty directory missing: %v", err)
	}
	contents, err := os.ReadFile(filepath.Join(f.candidates, "state", "maps", "save.zip"))
	if err != nil || string(contents) != "verified world data" {
		t.Fatalf("candidate content wrong: %q %v", contents, err)
	}
	if err := os.WriteFile(filepath.Join(f.candidates, "state", "unexpected"), []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), f.config(t, &fakeRunner{fixture: f})); err == nil {
		t.Fatal("unexpected candidate entry accepted")
	}
}
