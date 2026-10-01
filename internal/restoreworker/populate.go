// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package restoreworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
)

// populate may write only below separately mounted, deterministic candidate
// path roots. A failed/retried attempt can overwrite previously declared
// regular files, but refuses any unlisted entry or symlink before writing.
func populate(ctx context.Context, config Config, input Input, manifest platformdata.BackupManifest, original []byte, snapshotID string, environment map[string]string) error {
	if !filepath.IsAbs(config.CandidateRoot) || filepath.Clean(config.CandidateRoot) != config.CandidateRoot {
		return errors.New("candidate root invalid")
	}
	if err := requireDirectory(config.CandidateRoot); err != nil {
		return err
	}
	for _, path := range manifest.Paths {
		root := filepath.Join(config.CandidateRoot, path.Name)
		if err := requireDirectory(root); err != nil {
			return err
		}
		if err := scanCandidate(root, path); err != nil {
			return err
		}
	}
	for _, path := range manifest.Paths {
		root := filepath.Join(config.CandidateRoot, path.Name)
		for _, relative := range path.Directories {
			name := filepath.Join(root, filepath.FromSlash(relative))
			if err := os.Mkdir(name, 0o700); err != nil && !os.IsExist(err) {
				return errors.New("candidate directory cannot be created")
			}
			if err := requireDirectory(name); err != nil {
				return err
			}
		}
		for _, file := range path.Files {
			name := filepath.Join(root, filepath.FromSlash(file.Path))
			if err := writeCandidateFile(ctx, config.Runner, environment, snapshotID, path.Name, file, name); err != nil {
				return err
			}
		}
		// A successful worker result must survive a crash: file.Sync does not
		// persist newly created directory entries or the directories themselves.
		for index := len(path.Directories) - 1; index >= 0; index-- {
			if err := syncDirectory(filepath.Join(root, filepath.FromSlash(path.Directories[index]))); err != nil {
				return err
			}
		}
		if err := syncDirectory(root); err != nil {
			return err
		}
	}
	// Rebuild with the original source identities, not the new PVC identities:
	// this compares complete restored content/topology with the signed manifest.
	backupInput := platformdata.BackupWorkerInput{
		Version: platformdata.WorkerInputVersion, ArtifactID: input.Artifact.ID,
		OperationRef: input.BackupRef, WorkerLeaseName: input.WorkerLeaseName,
		RepositorySecretRef: input.RepositorySecretRef, Source: input.Source,
	}
	_, after, err := platformdata.BuildBackupManifest(backupInput, config.CandidateRoot)
	if err != nil || !bytes.Equal(after, original) {
		return errors.New("candidate content differs from verified manifest")
	}
	return nil
}

func requireDirectory(name string) error {
	info, err := os.Lstat(name)
	if err != nil || !info.IsDir() {
		return errors.New("candidate mount is unavailable or unsafe")
	}
	return nil
}

func syncDirectory(name string) error {
	file, err := os.Open(name)
	if err != nil {
		return errors.New("candidate directory cannot be opened for sync")
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("candidate directory cannot be persisted")
	}
	return nil
}

func scanCandidate(root string, manifest platformdata.BackupManifestPath) error {
	expected := make(map[string]string, len(manifest.Directories)+len(manifest.Files))
	for _, name := range manifest.Directories {
		expected[name] = "dir"
	}
	for _, file := range manifest.Files {
		expected[file.Path] = "file"
	}
	return filepath.WalkDir(root, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("candidate cannot be inspected")
		}
		if name == root {
			return nil
		}
		relative, err := filepath.Rel(root, name)
		if err != nil || !safeRelative(relative) {
			return errors.New("candidate path is unsafe")
		}
		want, exists := expected[filepath.ToSlash(relative)]
		if !exists || (want == "dir" && !entry.IsDir()) || (want == "file" && !entry.Type().IsRegular()) {
			return errors.New("candidate contains an unexpected entry")
		}
		return nil
	})
}

func writeCandidateFile(ctx context.Context, runner Runner, environment map[string]string, snapshotID, pathName string, expected platformdata.BackupFileChecksum, name string) error {
	if err := requireDirectory(filepath.Dir(name)); err != nil {
		return err
	}
	if info, err := os.Lstat(name); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("candidate file is unsafe")
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
			return errors.New("candidate file has multiple links")
		}
	} else if !os.IsNotExist(err) {
		return errors.New("candidate file cannot be inspected")
	}
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("candidate file cannot be opened")
	}
	hash := sha256.New()
	count := &countingWriter{writer: io.MultiWriter(file, hash), maximum: expected.Size}
	streamErr := runner.Stream(ctx, environment, count, "dump", "--no-cache", snapshotID, filepath.ToSlash(filepath.Join(DefaultSourceRoot, pathName, filepath.FromSlash(expected.Path))))
	syncErr := file.Sync()
	closeErr := file.Close()
	if streamErr != nil {
		return &Failure{Kind: FailureRepository}
	}
	if syncErr != nil || closeErr != nil {
		return errors.New("candidate file cannot be persisted")
	}
	if count.bytes != expected.Size ||
		"sha256:"+hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return &Failure{Kind: FailureVerification}
	}
	return nil
}
