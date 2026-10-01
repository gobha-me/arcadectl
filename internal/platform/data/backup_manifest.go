// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package data

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
)

const (
	// BackupFormatVersion identifies the canonical Arcadectl manifest stored in
	// every verified repository snapshot.
	BackupFormatVersion = "arcadectl.backup/v1"
	// WorkerInputVersion identifies the controller-to-worker contract.
	WorkerInputVersion = "arcadectl.backup-worker/v1"
)

// BackupWorkerInput is the non-secret, immutable input mounted into one backup
// worker. Repository configuration and credentials are deliberately excluded.
type BackupWorkerInput struct {
	Version             string                              `json:"version"`
	ArtifactID          string                              `json:"artifactID"`
	OperationRef        arcadev1alpha1.ExactLocalReference  `json:"operationRef"`
	WorkerLeaseName     string                              `json:"workerLeaseName"`
	RepositorySecretRef arcadev1alpha1.ExactSecretReference `json:"repositorySecretRef"`
	Source              arcadev1alpha1.DataSourceSnapshot   `json:"source"`
}

// BackupManifest is the canonical, repository-resident description of one
// cold backup. File checksums bind verification to every declared path.
type BackupManifest struct {
	FormatVersion  string               `json:"formatVersion"`
	ArtifactID     string               `json:"artifactID"`
	ServerUID      string               `json:"serverUID"`
	Game           string               `json:"game"`
	ImageDigest    string               `json:"imageDigest"`
	SettingsDigest string               `json:"settingsDigest"`
	Paths          []BackupManifestPath `json:"paths"`
}

// BackupManifestPath binds one adapter path to its exact retained claim and
// the complete regular-file set observed while the world was cold.
type BackupManifestPath struct {
	Name      string               `json:"name"`
	MountPath string               `json:"mountPath"`
	ClaimName string               `json:"claimName"`
	ClaimUID  string               `json:"claimUID"`
	Files     []BackupFileChecksum `json:"files"`
}

// BackupFileChecksum is relative to the named persistent-path root. Arcadectl
// refuses special files and symlinks rather than archiving ambiguous content.
type BackupFileChecksum struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// BackupWorkerResult is the bounded success message written to the Kubernetes
// termination log. It contains no repository location, native snapshot ID, or
// credentials.
type BackupWorkerResult struct {
	Version        string    `json:"version"`
	ArtifactID     string    `json:"artifactID"`
	ManifestDigest string    `json:"manifestDigest"`
	SizeBytes      int64     `json:"sizeBytes"`
	PathCount      int32     `json:"pathCount"`
	CreatedAt      time.Time `json:"createdAt"`
	VerifiedAt     time.Time `json:"verifiedAt"`
}

// BuildBackupManifest hashes every regular file under each declared source
// root. sourceRoot contains one child directory named for each persistent path.
func BuildBackupManifest(input BackupWorkerInput, sourceRoot string) (BackupManifest, []byte, error) {
	if err := ValidateBackupWorkerInput(input); err != nil {
		return BackupManifest{}, nil, err
	}
	if filepath.Clean(sourceRoot) != sourceRoot || !filepath.IsAbs(sourceRoot) {
		return BackupManifest{}, nil, errors.New("source root must be a clean absolute path")
	}

	manifest := BackupManifest{
		FormatVersion:  BackupFormatVersion,
		ArtifactID:     input.ArtifactID,
		ServerUID:      input.Source.GameServer.UID,
		Game:           input.Source.Game,
		ImageDigest:    input.Source.ImageDigest,
		SettingsDigest: input.Source.SettingsDigest,
		Paths:          make([]BackupManifestPath, 0, len(input.Source.Paths)),
	}
	for _, sourcePath := range input.Source.Paths {
		root := filepath.Join(sourceRoot, sourcePath.Name)
		files, err := hashPath(root)
		if err != nil {
			return BackupManifest{}, nil, fmt.Errorf("hash persistent path %q: %w", sourcePath.Name, err)
		}
		manifest.Paths = append(manifest.Paths, BackupManifestPath{
			Name:      sourcePath.Name,
			MountPath: sourcePath.MountPath,
			ClaimName: sourcePath.ClaimRef.Name,
			ClaimUID:  sourcePath.ClaimRef.UID,
			Files:     files,
		})
	}
	slices.SortFunc(manifest.Paths, func(left, right BackupManifestPath) int {
		return strings.Compare(left.Name, right.Name)
	})
	contents, err := json.Marshal(manifest)
	if err != nil {
		return BackupManifest{}, nil, errors.New("encode canonical backup manifest")
	}
	contents = append(contents, '\n')
	return manifest, contents, nil
}

// ValidateBackupWorkerInput rejects incomplete or ambiguous controller input.
func ValidateBackupWorkerInput(input BackupWorkerInput) error {
	if input.Version != WorkerInputVersion {
		return errors.New("unsupported backup worker input version")
	}
	if input.ArtifactID == "" || input.OperationRef.Name == "" || input.OperationRef.UID == "" || input.OperationRef.Namespace != nil ||
		input.WorkerLeaseName == "" || len(input.WorkerLeaseName) > 253 || strings.Contains(input.WorkerLeaseName, "/") ||
		input.RepositorySecretRef.Name == "" || input.RepositorySecretRef.UID == "" ||
		input.RepositorySecretRef.ResourceVersion == "" || input.RepositorySecretRef.Namespace != nil ||
		input.Source.GameServer.UID == "" || input.Source.Game == "" ||
		input.Source.ImageDigest == "" || input.Source.SettingsDigest == "" || len(input.Source.Paths) == 0 {
		return errors.New("backup worker input is incomplete")
	}
	names := make(map[string]struct{}, len(input.Source.Paths))
	claims := make(map[string]struct{}, len(input.Source.Paths))
	claimUIDs := make(map[string]struct{}, len(input.Source.Paths))
	for _, path := range input.Source.Paths {
		if path.Name == "" || strings.Contains(path.Name, "/") || path.MountPath == "" ||
			path.ClaimRef.Name == "" || path.ClaimRef.UID == "" || path.ClaimRef.Namespace != nil {
			return errors.New("backup worker path identity is incomplete")
		}
		if _, duplicate := names[path.Name]; duplicate {
			return errors.New("backup worker path names must be unique")
		}
		if _, duplicate := claims[path.ClaimRef.Name]; duplicate {
			return errors.New("backup worker claim names must be unique")
		}
		if _, duplicate := claimUIDs[path.ClaimRef.UID]; duplicate {
			return errors.New("backup worker claim UIDs must be unique")
		}
		names[path.Name] = struct{}{}
		claims[path.ClaimRef.Name] = struct{}{}
		claimUIDs[path.ClaimRef.UID] = struct{}{}
	}
	return nil
}

// ManifestDigest returns the API-format SHA-256 fingerprint of canonical
// manifest bytes.
func ManifestDigest(contents []byte) string {
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func hashPath(root string) ([]BackupFileChecksum, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, errors.New("persistent path is unavailable")
	}
	if !info.IsDir() {
		return nil, errors.New("persistent path is not a directory")
	}
	files := make([]BackupFileChecksum, 0)
	err = filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("persistent path cannot be read completely")
		}
		if name == root {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return errors.New("persistent path metadata is unavailable")
		}
		if !info.Mode().IsRegular() {
			return errors.New("persistent path contains an unsupported non-regular entry")
		}
		relative, err := filepath.Rel(root, name)
		if err != nil || relative == "." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("persistent path contains an unsafe entry")
		}
		checksum, err := hashFile(name)
		if err != nil {
			return err
		}
		files = append(files, BackupFileChecksum{Path: filepath.ToSlash(relative), Size: info.Size(), SHA256: checksum})
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(files, func(left, right BackupFileChecksum) int {
		return strings.Compare(left.Path, right.Path)
	})
	return files, nil
}

func hashFile(name string) (string, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", errors.New("persistent file cannot be opened")
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", errors.New("persistent file cannot be read completely")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
