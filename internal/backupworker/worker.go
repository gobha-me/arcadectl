// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package backupworker executes one bounded, cold, repository-verified backup.
// It is deliberately independent of Kubernetes clients: authority arrives only
// through read-only mounted data, non-secret controller input, and one Secret.
package backupworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	"github.com/gobha-me/arcadectl/internal/workerio"
)

const (
	DefaultInputPath       = "/arcadectl/input/input.json"
	DefaultCredentialsPath = "/arcadectl/credentials"
	DefaultSourceRoot      = "/arcadectl/source"
	DefaultWorkPath        = "/arcadectl/work"
	DefaultTerminationPath = "/dev/termination-log"
	manifestName           = "manifest.json"
	maxControlOutput       = 1 << 20
)

// FailureKind is a bounded controller-facing failure classification.
type FailureKind string

const (
	FailureInput        FailureKind = "InputInvalid"
	FailureCredentials  FailureKind = "CredentialsInvalid"
	FailureRepository   FailureKind = "WorkerFailed"
	FailureVerification FailureKind = "VerificationFailed"
)

type verificationCheckpoint string

const (
	checkpointSnapshotSelection verificationCheckpoint = "snapshot-selection"
	checkpointRepositoryCheck   verificationCheckpoint = "repository-check"
	checkpointManifest          verificationCheckpoint = "manifest"
	checkpointInventory         verificationCheckpoint = "inventory"
	checkpointFile              verificationCheckpoint = "file"
	checkpointSourceRecheck     verificationCheckpoint = "source-recheck"
	checkpointStats             verificationCheckpoint = "stats"
)

// Failure never contains repository output or credential material. Its private
// checkpoint identifies only a fixed verification stage, never a path or error.
type Failure struct {
	Kind       FailureKind
	checkpoint verificationCheckpoint
}

func (failure *Failure) Error() string {
	kind := FailureRepository
	if failure != nil {
		kind = boundedFailureKind(failure.Kind)
	}
	return "backup worker failed: " + string(kind)
}

// Config contains fixed mount and executable locations. Production uses the
// defaults; tests provide isolated paths and a fake Restic runner.
type Config struct {
	InputPath       string
	CredentialsPath string
	SourceRoot      string
	WorkPath        string
	ResticPath      string
	Now             func() time.Time
	Runner          Runner
}

// Runner executes Restic without reflecting its output in returned errors.
type Runner interface {
	Control(context.Context, map[string]string, ...string) ([]byte, error)
	Stream(context.Context, map[string]string, io.Writer, ...string) error
}

// Run performs or resumes exactly one artifact and verifies it before return.
func Run(ctx context.Context, config Config) (platformdata.BackupWorkerResult, error) {
	config = withDefaults(config)
	input, err := readInput(config.InputPath)
	if err != nil {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureInput}
	}
	credentials, err := readCredentials(config.CredentialsPath)
	if err != nil {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureCredentials}
	}
	manifest, contents, err := platformdata.BuildBackupManifest(input, config.SourceRoot)
	if err != nil {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureInput}
	}
	if err := os.MkdirAll(config.WorkPath, 0o700); err != nil {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureInput}
	}
	if err := os.MkdirAll(filepath.Join(config.WorkPath, "tmp"), 0o700); err != nil {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureInput}
	}
	manifestPath := filepath.Join(config.WorkPath, manifestName)
	if err := os.WriteFile(manifestPath, contents, 0o600); err != nil {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureInput}
	}
	manifestDigest := platformdata.ManifestDigest(contents)
	artifactTag := "arcadectl-artifact=" + input.ArtifactID
	manifestTag := "arcadectl-manifest=" + strings.TrimPrefix(manifestDigest, "sha256:")

	if _, err := config.Runner.Control(ctx, credentials.environment(), "unlock", "--no-cache"); err != nil {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureRepository}
	}
	snapshots, err := findSnapshots(ctx, config.Runner, credentials.environment(), artifactTag)
	if err != nil {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureRepository}
	}
	if len(snapshots) == 0 {
		arguments := []string{"backup", "--quiet", "--json", "--no-cache", "--host", "arcadectl", "--tag", artifactTag, "--tag", manifestTag}
		for _, path := range manifest.Paths {
			arguments = append(arguments, filepath.Join(config.SourceRoot, path.Name))
		}
		arguments = append(arguments, manifestPath)
		if _, err := config.Runner.Control(ctx, credentials.environment(), arguments...); err != nil {
			return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureRepository}
		}
		snapshots, err = findSnapshots(ctx, config.Runner, credentials.environment(), artifactTag)
		if err != nil {
			return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureRepository}
		}
	}
	if len(snapshots) != 1 || !slices.Contains(snapshots[0].Tags, manifestTag) {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureVerification, checkpoint: checkpointSnapshotSelection}
	}
	snapshot := snapshots[0]
	if snapshot.ID == "" {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureVerification, checkpoint: checkpointSnapshotSelection}
	}

	if _, err := config.Runner.Control(ctx, credentials.environment(), "check", "--no-cache", "--read-data-subset=100%"); err != nil {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureVerification, checkpoint: checkpointRepositoryCheck}
	}
	if err := verifyDump(ctx, config.Runner, credentials.environment(), snapshot.ID, manifestPath, contents); err != nil {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureVerification, checkpoint: checkpointManifest}
	}
	if err := verifyInventory(ctx, config.Runner, credentials.environment(), snapshot.ID, config.SourceRoot, manifestPath, int64(len(contents)), manifest); err != nil {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureVerification, checkpoint: checkpointInventory}
	}
	for _, path := range manifest.Paths {
		for _, file := range path.Files {
			repositoryPath := filepath.ToSlash(filepath.Join(config.SourceRoot, path.Name, filepath.FromSlash(file.Path)))
			if err := verifyFile(ctx, config.Runner, credentials.environment(), snapshot.ID, repositoryPath, file); err != nil {
				return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureVerification, checkpoint: checkpointFile}
			}
		}
	}
	_, after, err := platformdata.BuildBackupManifest(input, config.SourceRoot)
	if err != nil || !bytes.Equal(after, contents) {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureVerification, checkpoint: checkpointSourceRecheck}
	}
	stats, err := readStats(ctx, config.Runner, credentials.environment(), snapshot.ID)
	if err != nil || stats.TotalSize < 0 {
		return platformdata.BackupWorkerResult{}, &Failure{Kind: FailureVerification, checkpoint: checkpointStats}
	}

	verifiedAt := config.Now().UTC()
	return platformdata.BackupWorkerResult{
		Version:        platformdata.BackupFormatVersion,
		ArtifactID:     input.ArtifactID,
		ManifestDigest: manifestDigest,
		SizeBytes:      stats.TotalSize,
		PathCount:      int32(len(manifest.Paths)),
		CreatedAt:      snapshot.Time.UTC(),
		VerifiedAt:     verifiedAt,
	}, nil
}

type repositoryCredentials struct {
	repository      string
	password        string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	caCertificate   string
}

func (credentials repositoryCredentials) environment() map[string]string {
	environment := map[string]string{
		"RESTIC_REPOSITORY":     credentials.repository,
		"RESTIC_PASSWORD":       credentials.password,
		"AWS_ACCESS_KEY_ID":     credentials.accessKeyID,
		"AWS_SECRET_ACCESS_KEY": credentials.secretAccessKey,
		"HOME":                  "/arcadectl/work",
		"RESTIC_CACHE_DIR":      "/arcadectl/work/cache",
		"TMPDIR":                "/arcadectl/work/tmp",
	}
	if credentials.sessionToken != "" {
		environment["AWS_SESSION_TOKEN"] = credentials.sessionToken
	}
	if credentials.caCertificate != "" {
		environment["RESTIC_CACERT"] = credentials.caCertificate
	}
	return environment
}

func readInput(name string) (platformdata.BackupWorkerInput, error) {
	contents, err := os.ReadFile(name)
	if err != nil || len(contents) > maxControlOutput {
		return platformdata.BackupWorkerInput{}, errors.New("worker input is unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var input platformdata.BackupWorkerInput
	if err := decoder.Decode(&input); err != nil {
		return platformdata.BackupWorkerInput{}, errors.New("worker input is invalid")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return platformdata.BackupWorkerInput{}, errors.New("worker input has trailing content")
	}
	return input, platformdata.ValidateBackupWorkerInput(input)
}

func readCredentials(directory string) (repositoryCredentials, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return repositoryCredentials{}, errors.New("repository credentials are unavailable")
	}
	data := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "..") {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return repositoryCredentials{}, errors.New("repository credentials are unavailable")
		}
		data[entry.Name()] = contents
	}
	if err := platformdata.ValidateRepositorySecretData(data); err != nil {
		return repositoryCredentials{}, err
	}
	caPath := ""
	if len(data[platformdata.RepositoryKeyCACertificate]) > 0 {
		caPath = filepath.Join(directory, platformdata.RepositoryKeyCACertificate)
	}
	return repositoryCredentials{
		repository: string(data[platformdata.RepositoryKeyRepository]), password: string(data[platformdata.RepositoryKeyPassword]),
		accessKeyID: string(data[platformdata.RepositoryKeyAccessKeyID]), secretAccessKey: string(data[platformdata.RepositoryKeySecretAccessKey]),
		sessionToken: string(data[platformdata.RepositoryKeySessionToken]), caCertificate: caPath,
	}, nil
}

type resticSnapshot struct {
	ID   string    `json:"id"`
	Time time.Time `json:"time"`
	Tags []string  `json:"tags"`
}

func findSnapshots(ctx context.Context, runner Runner, environment map[string]string, tag string) ([]resticSnapshot, error) {
	contents, err := runner.Control(ctx, environment, "snapshots", "--json", "--no-cache", "--tag", tag)
	if err != nil {
		return nil, err
	}
	var snapshots []resticSnapshot
	if err := json.Unmarshal(contents, &snapshots); err != nil {
		return nil, errors.New("repository snapshot response is invalid")
	}
	return snapshots, nil
}

func verifyDump(ctx context.Context, runner Runner, environment map[string]string, snapshotID, repositoryPath string, expected []byte) error {
	hash := sha256.New()
	counting := &countingWriter{writer: hash}
	if err := runner.Stream(ctx, environment, counting, "dump", "--no-cache", snapshotID, filepath.ToSlash(repositoryPath)); err != nil {
		return err
	}
	want := sha256.Sum256(expected)
	if counting.bytes != int64(len(expected)) || !bytes.Equal(hash.Sum(nil), want[:]) {
		return errors.New("repository manifest does not match")
	}
	return nil
}

func verifyFile(ctx context.Context, runner Runner, environment map[string]string, snapshotID, repositoryPath string, expected platformdata.BackupFileChecksum) error {
	hash := sha256.New()
	counting := &countingWriter{writer: hash}
	if err := runner.Stream(ctx, environment, counting, "dump", "--no-cache", snapshotID, repositoryPath); err != nil {
		return err
	}
	got := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if counting.bytes != expected.Size || got != expected.SHA256 {
		return errors.New("repository file verification failed")
	}
	return nil
}

type resticStats struct {
	TotalSize int64 `json:"total_size"`
}

func readStats(ctx context.Context, runner Runner, environment map[string]string, snapshotID string) (resticStats, error) {
	contents, err := runner.Control(ctx, environment, "stats", "--json", "--no-cache", "--mode", "restore-size", snapshotID)
	if err != nil {
		return resticStats{}, err
	}
	var stats resticStats
	if err := json.Unmarshal(contents, &stats); err != nil {
		return resticStats{}, errors.New("repository statistics are invalid")
	}
	return stats, nil
}

type countingWriter struct {
	writer io.Writer
	bytes  int64
}

func (writer *countingWriter) Write(contents []byte) (int, error) {
	written, err := writer.writer.Write(contents)
	writer.bytes += int64(written)
	return written, err
}

func withDefaults(config Config) Config {
	if config.InputPath == "" {
		config.InputPath = DefaultInputPath
	}
	if config.CredentialsPath == "" {
		config.CredentialsPath = DefaultCredentialsPath
	}
	if config.SourceRoot == "" {
		config.SourceRoot = DefaultSourceRoot
	}
	if config.WorkPath == "" {
		config.WorkPath = DefaultWorkPath
	}
	if config.ResticPath == "" {
		config.ResticPath = "/restic"
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Runner == nil {
		config.Runner = &commandRunner{path: config.ResticPath}
	}
	return config
}

type commandRunner struct{ path string }

func (runner *commandRunner) Control(ctx context.Context, environment map[string]string, arguments ...string) ([]byte, error) {
	buffer := &boundedBuffer{maximum: maxControlOutput}
	if err := runner.run(ctx, environment, buffer, arguments...); err != nil {
		return nil, err
	}
	return slices.Clone(buffer.contents), nil
}

func (runner *commandRunner) Stream(ctx context.Context, environment map[string]string, destination io.Writer, arguments ...string) error {
	return runner.run(ctx, environment, destination, arguments...)
}

func (runner *commandRunner) run(ctx context.Context, environment map[string]string, destination io.Writer, arguments ...string) error {
	command := exec.CommandContext(ctx, runner.path, arguments...)
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	command.Env = make([]string, 0, len(keys))
	for _, key := range keys {
		command.Env = append(command.Env, key+"="+environment[key])
	}
	output := workerio.NewDrainingWriter(destination)
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || output.Failed() {
		return errors.New("repository command failed")
	}
	return nil
}

type boundedBuffer struct {
	contents []byte
	maximum  int
}

func (buffer *boundedBuffer) Write(contents []byte) (int, error) {
	if len(buffer.contents)+len(contents) > buffer.maximum {
		return 0, errors.New("repository control output exceeded limit")
	}
	buffer.contents = append(buffer.contents, contents...)
	return len(contents), nil
}

// ExitCode maps a bounded failure class to the worker process contract.
func ExitCode(err error) int {
	var failure *Failure
	if !errors.As(err, &failure) {
		return 20
	}
	switch failure.Kind {
	case FailureInput:
		return 10
	case FailureCredentials:
		return 11
	case FailureVerification:
		return 30
	default:
		return 20
	}
}

// FailureMessage is safe for the termination log and controller status.
func FailureMessage(err error) []byte {
	var failure *Failure
	kind := FailureRepository
	var checkpoint verificationCheckpoint
	if errors.As(err, &failure) && failure != nil {
		kind = boundedFailureKind(failure.Kind)
		if kind == FailureVerification {
			switch failure.checkpoint {
			case checkpointSnapshotSelection, checkpointRepositoryCheck, checkpointManifest,
				checkpointInventory, checkpointFile, checkpointSourceRecheck, checkpointStats:
				checkpoint = failure.checkpoint
			}
		}
	}
	contents, _ := json.Marshal(struct {
		Version    string                 `json:"version"`
		Failure    FailureKind            `json:"failure"`
		Checkpoint verificationCheckpoint `json:"checkpoint,omitempty"`
	}{Version: platformdata.WorkerInputVersion, Failure: kind, Checkpoint: checkpoint})
	return append(contents, '\n')
}

func boundedFailureKind(kind FailureKind) FailureKind {
	switch kind {
	case FailureInput, FailureCredentials, FailureRepository, FailureVerification:
		return kind
	default:
		return FailureRepository
	}
}

// SuccessMessage serializes the bounded result for the termination log.
func SuccessMessage(result platformdata.BackupWorkerResult) ([]byte, error) {
	contents, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encode worker result: %w", err)
	}
	if len(contents) > 4095 {
		return nil, errors.New("worker result exceeds termination-log limit")
	}
	return append(contents, '\n'), nil
}
