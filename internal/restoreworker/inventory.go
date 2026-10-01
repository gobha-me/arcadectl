// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package restoreworker

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

type inventoryNode struct {
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

// verifyInventory rejects any repository node not accounted for by the v2
// manifest, including symlinks, special files, and unlisted empty directories.
// Restic may also list ancestors of absolute backup arguments; those alone
// are optional and cannot authorize additional descendants.
func verifyInventory(ctx context.Context, runner Runner, environment map[string]string, snapshotID string, manifest platformdata.BackupManifest, manifestSize int64) error {
	expected := make(map[string]inventoryNode)
	add := func(name, kind string, size int64, required bool) error {
		if !filepath.IsAbs(name) || filepath.Clean(name) != name {
			return errors.New("expected repository path invalid")
		}
		if prior, exists := expected[name]; exists {
			if prior.kind != kind || (prior.kind == "file" && prior.size != size) || (prior.required && required) {
				return errors.New("expected repository paths overlap")
			}
			required = required || prior.required
		}
		expected[name] = inventoryNode{kind: kind, size: size, required: required}
		for parent := filepath.Dir(name); parent != name; parent = filepath.Dir(parent) {
			if prior, exists := expected[parent]; exists {
				if prior.kind != "dir" {
					return errors.New("expected ancestor is not a directory")
				}
			} else {
				expected[parent] = inventoryNode{kind: "dir"}
			}
			if parent == "/" {
				break
			}
		}
		return nil
	}
	for _, path := range manifest.Paths {
		root := filepath.Join(DefaultSourceRoot, path.Name)
		if err := add(root, "dir", 0, true); err != nil {
			return err
		}
		for _, relative := range path.Directories {
			if err := add(filepath.Join(root, filepath.FromSlash(relative)), "dir", 0, true); err != nil {
				return err
			}
		}
		for _, file := range path.Files {
			if err := add(filepath.Join(root, filepath.FromSlash(file.Path)), "file", file.Size, true); err != nil {
				return err
			}
		}
	}
	if err := add(DefaultManifestPath, "file", manifestSize, true); err != nil {
		return err
	}

	contents, err := limitedStream(ctx, runner, environment, maxInventoryBytes, "ls", "--json", "--no-cache", snapshotID)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	seen := make(map[string]struct{}, len(expected))
	seenSnapshot := false
	for {
		var record resticInventoryRecord
		if err := decoder.Decode(&record); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return errors.New("repository inventory invalid")
		}
		switch record.StructType {
		case "snapshot":
			if seenSnapshot || len(seen) != 0 || record.ID != snapshotID {
				return errors.New("repository snapshot identity differs")
			}
			seenSnapshot = true
		case "node":
			if !seenSnapshot || !filepath.IsAbs(record.Path) || filepath.Clean(record.Path) != record.Path ||
				!utf8.ValidString(record.Path) || strings.ContainsRune(record.Path, utf8.RuneError) {
				return errors.New("repository path unsafe")
			}
			want, exists := expected[record.Path]
			if !exists || want.kind != record.Type || (want.kind == "file" && want.size != record.Size) {
				return errors.New("repository inventory differs")
			}
			if _, duplicate := seen[record.Path]; duplicate {
				return errors.New("repository inventory duplicates path")
			}
			seen[record.Path] = struct{}{}
		default:
			return errors.New("repository inventory record unsupported")
		}
	}
	if !seenSnapshot {
		return errors.New("repository snapshot identity missing")
	}
	for name, node := range expected {
		if _, exists := seen[name]; node.required && !exists {
			return errors.New("repository inventory incomplete")
		}
	}
	return nil
}

func safeRelative(name string) bool {
	return name != "" && name != "." && name != ".." && !filepath.IsAbs(name) &&
		filepath.Clean(name) == name && !strings.HasPrefix(name, "../") && !strings.ContainsRune(name, 0) &&
		utf8.ValidString(name) && !strings.ContainsRune(name, utf8.RuneError)
}
