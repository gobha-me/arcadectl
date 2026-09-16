// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/util/validation"
)

const MaxRenderedSettingsBytes = 64 * 1024

// RenderSettingsFiles invokes the certified renderer with an isolated copy of
// settings, validates its constrained output, and returns files in stable name
// order. Rendered files are intentionally non-secret ConfigMap material.
func (d Definition) RenderSettingsFiles(settings json.RawMessage) ([]ConfigurationFile, error) {
	if d.RenderSettings == nil {
		return nil, errors.New("settings renderer is required")
	}
	rendered, err := d.RenderSettings(append(json.RawMessage(nil), settings...))
	if err != nil {
		return nil, fmt.Errorf("render settings: %w", err)
	}
	files, err := pairRenderedFiles(d.ConfigurationTargets, rendered)
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}

func validateConfigurationTargets(targets []ConfigurationTarget, persistentPaths []PersistentPath) error {
	if len(targets) == 0 {
		return errors.New("at least one configuration target is required")
	}
	names := make(map[string]struct{}, len(targets))
	mounts := make([]string, 0, len(targets))
	for _, target := range targets {
		if problems := validation.IsDNS1123Label(target.Name); len(problems) > 0 {
			return fmt.Errorf("configuration target name %q is invalid: %s", target.Name, strings.Join(problems, "; "))
		}
		if _, exists := names[target.Name]; exists {
			return fmt.Errorf("configuration target name %q is duplicated", target.Name)
		}
		if !strings.HasPrefix(target.MountPath, "/") || path.Clean(target.MountPath) != target.MountPath || target.MountPath == "/" {
			return fmt.Errorf("configuration target %q must have a clean absolute non-root mount path", target.Name)
		}
		for _, mount := range mounts {
			if pathsOverlap(mount, target.MountPath) {
				return fmt.Errorf("configuration mount %q overlaps %q", target.MountPath, mount)
			}
		}
		for _, persistentPath := range persistentPaths {
			if target.MountPath == persistentPath.MountPath {
				return fmt.Errorf("configuration mount %q overlaps persistent mount %q", target.MountPath, persistentPath.MountPath)
			}
		}
		if !nestedBelowPersistentPath(target.MountPath, persistentPaths) {
			return fmt.Errorf("configuration mount %q must be nested below a persistent path", target.MountPath)
		}
		names[target.Name] = struct{}{}
		mounts = append(mounts, target.MountPath)
	}
	return nil
}

func pairRenderedFiles(targets []ConfigurationTarget, rendered map[string][]byte) ([]ConfigurationFile, error) {
	if len(rendered) != len(targets) {
		return nil, errors.New("settings renderer output does not match declared configuration targets")
	}
	files := make([]ConfigurationFile, 0, len(targets))
	totalBytes := 0
	for _, target := range targets {
		contents, exists := rendered[target.Name]
		if !exists {
			return nil, fmt.Errorf("settings renderer omitted declared target %q", target.Name)
		}
		if len(contents) == 0 {
			return nil, fmt.Errorf("configuration file %q is empty", target.Name)
		}
		if !utf8.Valid(contents) || bytes.IndexByte(contents, 0) >= 0 {
			return nil, fmt.Errorf("configuration file %q must contain non-NUL UTF-8 text", target.Name)
		}
		totalBytes += len(contents)
		if totalBytes > MaxRenderedSettingsBytes {
			return nil, fmt.Errorf("rendered configuration exceeds the %d byte limit", MaxRenderedSettingsBytes)
		}
		files = append(files, ConfigurationFile{
			Name:      target.Name,
			MountPath: target.MountPath,
			Contents:  bytes.Clone(contents),
		})
	}
	return files, nil
}

func nestedBelowPersistentPath(mount string, persistentPaths []PersistentPath) bool {
	for _, persistentPath := range persistentPaths {
		prefix := strings.TrimSuffix(persistentPath.MountPath, "/") + "/"
		if strings.HasPrefix(mount, prefix) {
			return true
		}
	}
	return false
}
