// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package backupworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
)

const maxInventoryOutput = 8 << 20

type inventoryEntry struct {
	kind     string
	size     int64
	required bool
}

type resticInventoryRecord struct {
	StructType string `json:"struct_type"`
	ID         string `json:"id"`
	Path       string `json:"path"`
	Type       string `json:"type"`
	Size       int64  `json:"size"`
}

// verifyInventory proves that the repository snapshot contains exactly the
// directory and file topology signed by the v2 manifest. Restic also lists
// ancestor directories of absolute backup arguments; those may appear but
// never authorize an additional child entry.
func verifyInventory(ctx context.Context, runner Runner, environment map[string]string, snapshotID, sourceRoot, manifestPath string, manifestSize int64, manifest platformdata.BackupManifest) error {
	expected := make(map[string]inventoryEntry)
	add := func(path string, entry inventoryEntry) error {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("expected repository path is invalid")
		}
		if prior, exists := expected[path]; exists {
			if prior.kind != entry.kind || (prior.kind == "file" && prior.size != entry.size) {
				return errors.New("expected repository paths overlap")
			}
			entry.required = entry.required || prior.required
		}
		expected[path] = entry
		for parent := filepath.Dir(path); parent != path; parent = filepath.Dir(parent) {
			if prior, exists := expected[parent]; exists {
				if prior.kind != "dir" {
					return errors.New("expected repository paths overlap")
				}
			} else {
				expected[parent] = inventoryEntry{kind: "dir"}
			}
			if parent == "/" {
				break
			}
		}
		return nil
	}
	for _, path := range manifest.Paths {
		root := filepath.Join(sourceRoot, path.Name)
		if err := add(root, inventoryEntry{kind: "dir", required: true}); err != nil {
			return err
		}
		for _, relative := range path.Directories {
			if !safeInventoryRelative(relative) {
				return errors.New("manifest directory path is unsafe")
			}
			if err := add(filepath.Join(root, filepath.FromSlash(relative)), inventoryEntry{kind: "dir", required: true}); err != nil {
				return err
			}
		}
		for _, file := range path.Files {
			if !safeInventoryRelative(file.Path) || file.Size < 0 {
				return errors.New("manifest file path is unsafe")
			}
			if err := add(filepath.Join(root, filepath.FromSlash(file.Path)), inventoryEntry{kind: "file", size: file.Size, required: true}); err != nil {
				return err
			}
		}
	}
	if err := add(manifestPath, inventoryEntry{kind: "file", size: manifestSize, required: true}); err != nil {
		return err
	}

	buffer := &boundedBuffer{maximum: maxInventoryOutput}
	if err := runner.Stream(ctx, environment, buffer, "ls", "--json", "--no-cache", snapshotID); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(buffer.contents))
	seen := make(map[string]struct{}, len(expected))
	seenSnapshot := false
	for {
		var record resticInventoryRecord
		if err := decoder.Decode(&record); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return errors.New("repository inventory is invalid")
		}
		switch record.StructType {
		case "snapshot":
			if seenSnapshot || len(seen) != 0 || record.ID != snapshotID {
				return errors.New("repository snapshot identity is inconsistent")
			}
			seenSnapshot = true
		case "node":
			if !seenSnapshot || !filepath.IsAbs(record.Path) || filepath.Clean(record.Path) != record.Path ||
				!utf8.ValidString(record.Path) || strings.ContainsRune(record.Path, utf8.RuneError) {
				return errors.New("repository inventory path is unsafe")
			}
			want, exists := expected[record.Path]
			if !exists || record.Type != want.kind || (want.kind == "file" && want.size >= 0 && record.Size != want.size) {
				return errors.New("repository inventory differs from manifest")
			}
			if _, duplicate := seen[record.Path]; duplicate {
				return errors.New("repository inventory contains duplicate paths")
			}
			seen[record.Path] = struct{}{}
		default:
			return errors.New("unsupported repository inventory record type")
		}
	}
	if !seenSnapshot {
		return errors.New("repository inventory is missing snapshot identity")
	}
	for path, entry := range expected {
		if _, exists := seen[path]; entry.required && !exists {
			return errors.New("repository inventory is incomplete")
		}
	}
	return nil
}

func safeInventoryRelative(path string) bool {
	return path != "" && path != "." && !filepath.IsAbs(path) && filepath.Clean(path) == path &&
		path != ".." && !strings.HasPrefix(path, "../") && utf8.ValidString(path) && !strings.ContainsRune(path, utf8.RuneError)
}
