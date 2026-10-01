// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package restoreworker verifies one v2 backup without mounting target data,
// then (in a separate invocation) populates only fresh candidate claims.
// Kubernetes authority and Pod admission are supplied by the controller;
// this package never uses an API token or reads an active world.
package restoreworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	InputVersion           = "arcadectl.restore-worker/v1"
	ResultVersion          = "arcadectl.restore-result/v1"
	DefaultInputPath       = "/arcadectl/input/input.json"
	DefaultCredentialsPath = "/arcadectl/credentials"
	DefaultCandidateRoot   = "/arcadectl/candidate"
	DefaultWorkPath        = "/arcadectl/work"
	DefaultResticPath      = "/restic"
	DefaultTerminationPath = "/arcadectl/work/termination.json"
	DefaultSourceRoot      = "/arcadectl/source"
	DefaultManifestPath    = "/arcadectl/work/manifest.json"
	maxInputBytes          = 1 << 20
	maxControlBytes        = 1 << 20
	maxManifestBytes       = 8 << 20
	maxInventoryBytes      = 32 << 20
)

type Stage string

const (
	StagePreflight Stage = "Preflight"
	StagePopulate  Stage = "Populate"
)

// PathContract describes the target adapter's paths without naming active
// claims. A preflight Pod has no PVC mounts and therefore no target-data IO.
type PathContract struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
}

// Input is non-secret, immutable controller input for one worker stage.
// Artifact and Source are copied from one exact, verified GameBackup status.
type Input struct {
	Version              string                                  `json:"version"`
	Stage                Stage                                   `json:"stage"`
	OperationRef         arcadev1alpha1.ExactLocalReference      `json:"operationRef"`
	BackupRef            arcadev1alpha1.ExactLocalReference      `json:"backupRef"`
	Target               arcadev1alpha1.ExactGameServerReference `json:"target"`
	WorkerLeaseName      string                                  `json:"workerLeaseName"`
	RepositorySecretRef  arcadev1alpha1.ExactSecretReference     `json:"repositorySecretRef"`
	Artifact             arcadev1alpha1.BackupArtifact           `json:"artifact"`
	Source               arcadev1alpha1.DataSourceSnapshot       `json:"source"`
	TargetGame           string                                  `json:"targetGame"`
	TargetImageDigest    string                                  `json:"targetImageDigest"`
	TargetSettingsDigest string                                  `json:"targetSettingsDigest"`
	TargetPaths          []PathContract                          `json:"targetPaths"`
	PreviousDataIdentity string                                  `json:"previousDataIdentity,omitempty"`
	PreviousData         []arcadev1alpha1.DataPathIdentity       `json:"previousData,omitempty"`
	CandidatePaths       []arcadev1alpha1.DataPathIdentity       `json:"candidatePaths,omitempty"`
}

// Result is safe for a bounded termination log. It intentionally omits the
// repository URL, native Restic snapshot ID, Kubernetes Secret, and credentials.
type Result struct {
	Version        string    `json:"version"`
	Stage          Stage     `json:"stage"`
	ArtifactID     string    `json:"artifactID"`
	ManifestDigest string    `json:"manifestDigest"`
	PathCount      int32     `json:"pathCount"`
	VerifiedAt     time.Time `json:"verifiedAt"`
}

type FailureKind string

const (
	FailureInput        FailureKind = "InputInvalid"
	FailureCredentials  FailureKind = "CredentialsInvalid"
	FailureRepository   FailureKind = "RepositoryUnavailable"
	FailureVerification FailureKind = "VerificationFailed"
	FailureCandidate    FailureKind = "CandidateUnsafe"
)

// Failure is the only worker-facing error shape. It carries no Restic output,
// path, repository location, or credential content.
type Failure struct{ Kind FailureKind }

func (failure *Failure) Error() string { return "restore worker failed: " + string(failure.Kind) }

// Runner is injectable for hermetic tests. Implementations must not expose
// command output through returned errors.
type Runner interface {
	Control(context.Context, map[string]string, ...string) ([]byte, error)
	Stream(context.Context, map[string]string, io.Writer, ...string) error
}

type Config struct {
	InputPath       string
	CredentialsPath string
	CandidateRoot   string
	WorkPath        string
	ResticPath      string
	Now             func() time.Time
	Runner          Runner
}

type snapshot struct {
	ID   string   `json:"id"`
	Tags []string `json:"tags"`
}

var snapshotIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Run repeats full repository verification for both stages. Populate does not
// touch a candidate path until that repeated preflight has completed.
func Run(ctx context.Context, config Config) (Result, error) {
	config = defaults(config)
	if !filepath.IsAbs(config.WorkPath) || filepath.Clean(config.WorkPath) != config.WorkPath ||
		!filepath.IsAbs(config.CandidateRoot) || filepath.Clean(config.CandidateRoot) != config.CandidateRoot ||
		pathsOverlap(config.WorkPath, config.CandidateRoot) {
		return Result{}, &Failure{Kind: FailureInput}
	}
	input, err := readInput(config.InputPath)
	if err != nil {
		return Result{}, &Failure{Kind: FailureInput}
	}
	credentials, err := readCredentials(config.CredentialsPath, config.WorkPath)
	if err != nil {
		return Result{}, &Failure{Kind: FailureCredentials}
	}
	environment := credentials.environment
	tag := "arcadectl-artifact=" + input.Artifact.ID
	snapshotsOutput, err := config.Runner.Control(ctx, environment, "snapshots", "--json", "--no-cache", "--tag", tag)
	if err != nil {
		return Result{}, &Failure{Kind: FailureRepository}
	}
	if len(snapshotsOutput) > maxControlBytes {
		return Result{}, &Failure{Kind: FailureVerification}
	}
	var snapshots []snapshot
	if json.Unmarshal(snapshotsOutput, &snapshots) != nil || len(snapshots) != 1 || !snapshotIDPattern.MatchString(snapshots[0].ID) ||
		!slices.Contains(snapshots[0].Tags, tag) ||
		!slices.Contains(snapshots[0].Tags, "arcadectl-manifest="+strings.TrimPrefix(input.Artifact.ManifestDigest, "sha256:")) {
		return Result{}, &Failure{Kind: FailureVerification}
	}
	snapshotID := snapshots[0].ID
	manifestBytes, err := limitedStream(ctx, config.Runner, environment, maxManifestBytes, "dump", "--no-cache", snapshotID, DefaultManifestPath)
	if err != nil {
		return Result{}, &Failure{Kind: FailureVerification}
	}
	if platformdata.ManifestDigest(manifestBytes) != input.Artifact.ManifestDigest {
		return Result{}, &Failure{Kind: FailureVerification}
	}
	manifest, err := parseManifest(manifestBytes)
	if err != nil || validateManifest(input, manifest) != nil {
		return Result{}, &Failure{Kind: FailureVerification}
	}
	if err := verifyInventory(ctx, config.Runner, environment, snapshotID, manifest, int64(len(manifestBytes))); err != nil {
		return Result{}, &Failure{Kind: FailureVerification}
	}
	if _, err := config.Runner.Control(ctx, environment, "check", "--no-cache", "--read-data-subset=100%"); err != nil {
		return Result{}, &Failure{Kind: FailureVerification}
	}
	for _, path := range manifest.Paths {
		for _, file := range path.Files {
			if err := verifyRepositoryFile(ctx, config.Runner, environment, snapshotID, path.Name, file); err != nil {
				return Result{}, &Failure{Kind: FailureVerification}
			}
		}
	}
	if input.Stage == StagePopulate {
		if err := populate(ctx, config, input, manifest, manifestBytes, snapshotID, environment); err != nil {
			var failure *Failure
			if errors.As(err, &failure) {
				return Result{}, failure
			}
			return Result{}, &Failure{Kind: FailureCandidate}
		}
	}
	return Result{
		Version: ResultVersion, Stage: input.Stage, ArtifactID: input.Artifact.ID,
		ManifestDigest: input.Artifact.ManifestDigest, PathCount: int32(len(manifest.Paths)),
		VerifiedAt: config.Now().UTC(),
	}, nil
}

func pathsOverlap(left, right string) bool {
	relative, err := filepath.Rel(left, right)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	relative, err = filepath.Rel(right, left)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func defaults(config Config) Config {
	if config.InputPath == "" {
		config.InputPath = DefaultInputPath
	}
	if config.CredentialsPath == "" {
		config.CredentialsPath = DefaultCredentialsPath
	}
	if config.CandidateRoot == "" {
		config.CandidateRoot = DefaultCandidateRoot
	}
	if config.WorkPath == "" {
		config.WorkPath = DefaultWorkPath
	}
	if config.ResticPath == "" {
		config.ResticPath = DefaultResticPath
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Runner == nil {
		config.Runner = &commandRunner{path: config.ResticPath}
	}
	return config
}

func readInput(name string) (Input, error) {
	contents, err := os.ReadFile(name)
	if err != nil || len(contents) == 0 || len(contents) > maxInputBytes {
		return Input{}, errors.New("input unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var input Input
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || ValidateInput(input) != nil {
		return Input{}, errors.New("input invalid")
	}
	return input, nil
}

// ValidateInput is shared by a future exact-Pod authorizer and the worker.
func ValidateInput(input Input) error {
	if input.Version != InputVersion || (input.Stage != StagePreflight && input.Stage != StagePopulate) ||
		input.OperationRef.Name == "" || input.OperationRef.UID == "" || input.OperationRef.Namespace != nil ||
		input.BackupRef.Name == "" || input.BackupRef.UID == "" || input.BackupRef.Namespace != nil ||
		input.Target.Name == "" || input.Target.UID == "" || input.Target.Namespace != nil || input.Target.Generation < 1 ||
		(input.Target.DesiredState != arcadev1alpha1.DesiredStateStopped && input.Target.DesiredState != arcadev1alpha1.DesiredStateRunning) ||
		input.WorkerLeaseName == "" || len(input.WorkerLeaseName) > 253 || strings.Contains(input.WorkerLeaseName, "/") ||
		input.RepositorySecretRef.Name == "" || input.RepositorySecretRef.UID == "" || input.RepositorySecretRef.ResourceVersion == "" || input.RepositorySecretRef.Namespace != nil ||
		input.Artifact.FormatVersion != platformdata.BackupFormatVersion || input.Artifact.Verification.Result != arcadev1alpha1.VerificationVerified ||
		input.Artifact.Provenance.BackupRef != input.BackupRef || input.Artifact.Provenance.RepositorySecretRef != input.RepositorySecretRef ||
		input.Artifact.PathCount < 1 || !strings.HasPrefix(input.Artifact.ManifestDigest, "sha256:") || len(input.Artifact.ManifestDigest) != 71 ||
		input.Source.GameServer.UID == "" || input.TargetGame == "" || input.TargetImageDigest == "" || input.TargetSettingsDigest == "" ||
		len(input.TargetPaths) == 0 || len(input.TargetPaths) != len(input.Source.Paths) {
		return errors.New("restore input contract is invalid")
	}
	expectedID, err := platformdata.ArtifactID(types.UID(input.BackupRef.UID))
	if err != nil || input.Artifact.ID != expectedID || input.Artifact.PathCount != int32(len(input.Source.Paths)) ||
		input.TargetGame != input.Source.Game || input.TargetImageDigest != input.Source.ImageDigest || input.TargetSettingsDigest != input.Source.SettingsDigest {
		return errors.New("restore artifact or adapter is incompatible")
	}
	backupInput := platformdata.BackupWorkerInput{
		Version: platformdata.WorkerInputVersion, ArtifactID: input.Artifact.ID,
		OperationRef: input.BackupRef, WorkerLeaseName: input.WorkerLeaseName,
		RepositorySecretRef: input.RepositorySecretRef, Source: input.Source,
	}
	if platformdata.ValidateBackupWorkerInput(backupInput) != nil {
		return errors.New("source identity is invalid")
	}
	if len(validation.IsDNS1123Subdomain(input.WorkerLeaseName)) != 0 {
		return errors.New("worker lease identity is invalid")
	}
	paths := make(map[string]string, len(input.TargetPaths))
	for _, path := range input.TargetPaths {
		if !safePathName(path.Name) || !safeMountPath(path.MountPath) || paths[path.Name] != "" {
			return errors.New("target paths are invalid")
		}
		paths[path.Name] = path.MountPath
	}
	for _, path := range input.Source.Paths {
		if !safePathName(path.Name) || !safeMountPath(path.MountPath) || paths[path.Name] != path.MountPath {
			return errors.New("source and target paths differ")
		}
	}
	if input.Stage == StagePreflight {
		if len(input.CandidatePaths) != 0 || len(input.PreviousData) != 0 || input.PreviousDataIdentity != "" {
			return errors.New("preflight cannot receive target claim identities")
		}
		return nil
	}
	if len(validation.IsDNS1123Label(input.PreviousDataIdentity)) != 0 ||
		len(input.PreviousData) != len(input.Source.Paths) || len(input.CandidatePaths) != len(input.Source.Paths) {
		return errors.New("previous or candidate paths are incomplete")
	}
	previousNames := make(map[string]struct{}, len(input.PreviousData))
	previousUIDs := make(map[string]struct{}, len(input.PreviousData))
	previousPaths := make(map[string]struct{}, len(input.PreviousData))
	for _, previous := range input.PreviousData {
		if !safePathName(previous.Name) || paths[previous.Name] != previous.MountPath ||
			previous.ClaimRef.Name == "" || previous.ClaimRef.UID == "" || previous.ClaimRef.Namespace != nil {
			return errors.New("previous data identity is invalid")
		}
		if _, exists := previousPaths[previous.Name]; exists {
			return errors.New("previous data paths overlap")
		}
		if _, exists := previousNames[previous.ClaimRef.Name]; exists {
			return errors.New("previous claim names overlap")
		}
		if _, exists := previousUIDs[previous.ClaimRef.UID]; exists {
			return errors.New("previous claim UIDs overlap")
		}
		previousPaths[previous.Name] = struct{}{}
		previousNames[previous.ClaimRef.Name] = struct{}{}
		previousUIDs[previous.ClaimRef.UID] = struct{}{}
	}
	candidateNames := make(map[string]struct{}, len(input.CandidatePaths))
	candidateUIDs := make(map[string]struct{}, len(input.CandidatePaths))
	candidatePaths := make(map[string]struct{}, len(input.CandidatePaths))
	for _, candidate := range input.CandidatePaths {
		expectedName, err := platformdata.RestoreCandidateID(types.UID(input.OperationRef.UID), candidate.Name)
		if err != nil || candidate.ClaimRef.Name != expectedName || candidate.ClaimRef.UID == "" || candidate.ClaimRef.Namespace != nil ||
			paths[candidate.Name] != candidate.MountPath {
			return errors.New("candidate identity is invalid")
		}
		if _, duplicate := candidatePaths[candidate.Name]; duplicate {
			return errors.New("candidate paths overlap")
		}
		if _, duplicate := candidateNames[candidate.ClaimRef.Name]; duplicate {
			return errors.New("candidate names overlap")
		}
		if _, duplicate := candidateUIDs[candidate.ClaimRef.UID]; duplicate {
			return errors.New("candidate UIDs overlap")
		}
		candidateNames[candidate.ClaimRef.Name] = struct{}{}
		candidateUIDs[candidate.ClaimRef.UID] = struct{}{}
		candidatePaths[candidate.Name] = struct{}{}
	}
	for _, source := range input.Source.Paths {
		if _, duplicate := candidateNames[source.ClaimRef.Name]; duplicate {
			return errors.New("candidate aliases source claim")
		}
		if _, duplicate := candidateUIDs[source.ClaimRef.UID]; duplicate {
			return errors.New("candidate aliases source UID")
		}
	}
	for _, previous := range input.PreviousData {
		if _, duplicate := candidateNames[previous.ClaimRef.Name]; duplicate {
			return errors.New("candidate aliases previous claim")
		}
		if _, duplicate := candidateUIDs[previous.ClaimRef.UID]; duplicate {
			return errors.New("candidate aliases previous UID")
		}
	}
	return nil
}

func safePathName(name string) bool {
	return len(validation.IsDNS1123Label(name)) == 0
}

func safeMountPath(name string) bool {
	return filepath.IsAbs(name) && filepath.Clean(name) == name && name != "/"
}

func parseManifest(contents []byte) (platformdata.BackupManifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var manifest platformdata.BackupManifest
	if decoder.Decode(&manifest) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return manifest, errors.New("manifest invalid")
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(contents, append(canonical, '\n')) {
		return manifest, errors.New("manifest noncanonical")
	}
	return manifest, nil
}

func validateManifest(input Input, manifest platformdata.BackupManifest) error {
	if manifest.FormatVersion != platformdata.BackupFormatVersion || manifest.ArtifactID != input.Artifact.ID ||
		manifest.ServerUID != input.Source.GameServer.UID || manifest.Game != input.Source.Game ||
		manifest.ImageDigest != input.Source.ImageDigest || manifest.SettingsDigest != input.Source.SettingsDigest ||
		len(manifest.Paths) != len(input.Source.Paths) {
		return errors.New("manifest provenance differs")
	}
	sourcePaths := make(map[string]arcadev1alpha1.DataPathIdentity, len(input.Source.Paths))
	for _, path := range input.Source.Paths {
		sourcePaths[path.Name] = path
	}
	lastName := ""
	for _, path := range manifest.Paths {
		source, exists := sourcePaths[path.Name]
		if !exists || path.Name <= lastName || path.MountPath != source.MountPath ||
			path.ClaimName != source.ClaimRef.Name || path.ClaimUID != source.ClaimRef.UID ||
			path.Directories == nil || path.Files == nil {
			return errors.New("manifest path identity differs")
		}
		lastName = path.Name
		lastDir := ""
		dirs := make(map[string]struct{}, len(path.Directories))
		for _, dir := range path.Directories {
			if !safeRelative(dir) || dir <= lastDir {
				return errors.New("manifest directories are unsafe")
			}
			dirs[dir] = struct{}{}
			lastDir = dir
		}
		lastFile := ""
		for _, file := range path.Files {
			if !safeRelative(file.Path) || file.Path <= lastFile || file.Size < 0 || !validDigest(file.SHA256) {
				return errors.New("manifest files are unsafe")
			}
			if _, overlap := dirs[file.Path]; overlap {
				return errors.New("manifest file aliases directory")
			}
			for parent := filepath.Dir(file.Path); parent != "."; parent = filepath.Dir(parent) {
				if _, exists := dirs[parent]; !exists {
					return errors.New("manifest file parent missing")
				}
			}
			lastFile = file.Path
		}
		for _, dir := range path.Directories {
			for parent := filepath.Dir(dir); parent != "."; parent = filepath.Dir(parent) {
				if _, exists := dirs[parent]; !exists {
					return errors.New("manifest directory parent missing")
				}
			}
		}
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

type credentialEnvironment struct{ environment map[string]string }

func readCredentials(directory, workPath string) (credentialEnvironment, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return credentialEnvironment{}, errors.New("credentials unavailable")
	}
	data := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.Name() == "" || strings.HasPrefix(entry.Name(), "..") || !entry.Type().IsRegular() {
			return credentialEnvironment{}, errors.New("credentials invalid")
		}
		value, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return credentialEnvironment{}, errors.New("credentials unavailable")
		}
		data[entry.Name()] = value
	}
	if platformdata.ValidateRepositorySecretData(data) != nil {
		return credentialEnvironment{}, errors.New("credentials invalid")
	}
	if err := os.MkdirAll(filepath.Join(workPath, "tmp"), 0o700); err != nil {
		return credentialEnvironment{}, errors.New("private work path unavailable")
	}
	environment := map[string]string{
		"RESTIC_REPOSITORY":     string(data[platformdata.RepositoryKeyRepository]),
		"RESTIC_PASSWORD":       string(data[platformdata.RepositoryKeyPassword]),
		"AWS_ACCESS_KEY_ID":     string(data[platformdata.RepositoryKeyAccessKeyID]),
		"AWS_SECRET_ACCESS_KEY": string(data[platformdata.RepositoryKeySecretAccessKey]),
		"HOME":                  workPath, "RESTIC_CACHE_DIR": filepath.Join(workPath, "cache"), "TMPDIR": filepath.Join(workPath, "tmp"),
	}
	if len(data[platformdata.RepositoryKeySessionToken]) > 0 {
		environment["AWS_SESSION_TOKEN"] = string(data[platformdata.RepositoryKeySessionToken])
	}
	if len(data[platformdata.RepositoryKeyCACertificate]) > 0 {
		environment["RESTIC_CACERT"] = filepath.Join(directory, platformdata.RepositoryKeyCACertificate)
	}
	return credentialEnvironment{environment: environment}, nil
}

func verifyRepositoryFile(ctx context.Context, runner Runner, environment map[string]string, snapshotID, pathName string, file platformdata.BackupFileChecksum) error {
	hash := sha256.New()
	count := &countingWriter{writer: hash, maximum: file.Size}
	if err := runner.Stream(ctx, environment, count, "dump", "--no-cache", snapshotID, filepath.ToSlash(filepath.Join(DefaultSourceRoot, pathName, filepath.FromSlash(file.Path)))); err != nil {
		return err
	}
	if count.bytes != file.Size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
		return errors.New("stored file differs")
	}
	return nil
}

type countingWriter struct {
	writer  io.Writer
	bytes   int64
	maximum int64
}

func (writer *countingWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > writer.maximum-writer.bytes {
		return 0, errors.New("repository file exceeds declared size")
	}
	n, err := writer.writer.Write(data)
	writer.bytes += int64(n)
	return n, err
}

type limitedWriter struct {
	data    []byte
	maximum int
}

func (writer *limitedWriter) Write(data []byte) (int, error) {
	if len(writer.data)+len(data) > writer.maximum {
		return 0, errors.New("output limit exceeded")
	}
	writer.data = append(writer.data, data...)
	return len(data), nil
}

func limitedStream(ctx context.Context, runner Runner, environment map[string]string, maximum int, args ...string) ([]byte, error) {
	buffer := &limitedWriter{maximum: maximum}
	if err := runner.Stream(ctx, environment, buffer, args...); err != nil {
		return nil, err
	}
	return buffer.data, nil
}

type commandRunner struct{ path string }

func (runner *commandRunner) Control(ctx context.Context, environment map[string]string, args ...string) ([]byte, error) {
	buffer := &limitedWriter{maximum: maxControlBytes}
	if err := runner.run(ctx, environment, buffer, args...); err != nil {
		return nil, err
	}
	return slices.Clone(buffer.data), nil
}
func (runner *commandRunner) Stream(ctx context.Context, environment map[string]string, destination io.Writer, args ...string) error {
	return runner.run(ctx, environment, destination, args...)
}
func (runner *commandRunner) run(ctx context.Context, environment map[string]string, destination io.Writer, args ...string) error {
	command := exec.CommandContext(ctx, runner.path, args...)
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	command.Env = make([]string, 0, len(keys))
	for _, key := range keys {
		command.Env = append(command.Env, key+"="+environment[key])
	}
	command.Stdout = destination
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return errors.New("repository command failed")
	}
	return nil
}

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
	case FailureCandidate:
		return 31
	default:
		return 20
	}
}

func FailureMessage(err error) []byte {
	var failure *Failure
	kind := FailureRepository
	if errors.As(err, &failure) {
		kind = failure.Kind
	}
	contents, _ := json.Marshal(struct {
		Version string      `json:"version"`
		Failure FailureKind `json:"failure"`
	}{ResultVersion, kind})
	return append(contents, '\n')
}

func SuccessMessage(result Result) ([]byte, error) {
	contents, err := json.Marshal(result)
	if err != nil || len(contents) > 4094 {
		return nil, errors.New("restore result encoding failed")
	}
	return append(contents, '\n'), nil
}
