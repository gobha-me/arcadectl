// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

var (
	idPattern     = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	namePattern   = regexp.MustCompile(`^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

const platformMountRoot = "/arcadectl"

// Validate checks the complete adapter definition before it can enter a
// catalog or influence a cluster mutation.
func (d Definition) Validate() error {
	if !idPattern.MatchString(d.ID) {
		return errors.New("game id must be a lowercase DNS label")
	}
	if strings.TrimSpace(d.DisplayName) == "" {
		return errors.New("display name is required")
	}
	if err := validateRepository(d.ImageRepository); err != nil {
		return err
	}
	if err := validateEndpoints(d.Endpoints, d.ReadinessEndpoint); err != nil {
		return err
	}
	if err := validatePersistentPaths(d.PersistentPaths); err != nil {
		return err
	}
	if err := validateRuntimeIdentity(d.RuntimeIdentity); err != nil {
		return err
	}
	if (d.Capabilities.ColdBackup || d.Capabilities.Restore) && len(d.PersistentPaths) == 0 {
		return errors.New("backup and restore capabilities require persistent paths")
	}
	if d.Capabilities.Restore && !d.Capabilities.ColdBackup {
		return errors.New("restore capability requires cold backup capability")
	}
	if err := validateSettingsSchema(d.SettingsSchema); err != nil {
		return err
	}
	if err := validateConfigurationTargets(d.ConfigurationTargets, d.PersistentPaths); err != nil {
		return err
	}
	if d.RenderSettings == nil {
		return errors.New("settings renderer is required")
	}
	return nil
}

func validateRuntimeIdentity(identity RuntimeIdentity) error {
	const maxLinuxID = int64(1<<31 - 2)
	if identity.UserID <= 0 || identity.UserID > maxLinuxID {
		return errors.New("runtime user ID must be a positive Linux ID")
	}
	if identity.GroupID <= 0 || identity.GroupID > maxLinuxID {
		return errors.New("runtime group ID must be a positive Linux ID")
	}
	if identity.FSGroup <= 0 || identity.FSGroup > maxLinuxID {
		return errors.New("runtime filesystem group ID must be a positive Linux ID")
	}
	return nil
}

func validateRepository(repository string) error {
	if repository == "" || strings.TrimSpace(repository) != repository {
		return errors.New("image repository is required and cannot contain surrounding whitespace")
	}
	if strings.ContainsAny(repository, "\t\r\n@") {
		return errors.New("image repository must not contain whitespace or a digest")
	}
	return nil
}

func validateEndpoints(endpoints []Endpoint, readiness string) error {
	if len(endpoints) == 0 {
		return errors.New("at least one endpoint is required")
	}
	names := make(map[string]Endpoint, len(endpoints))
	hasPlayerEndpoint := false
	for _, endpoint := range endpoints {
		if !namePattern.MatchString(endpoint.Name) {
			return fmt.Errorf("endpoint %q must have a lowercase DNS-label name", endpoint.Name)
		}
		if _, exists := names[endpoint.Name]; exists {
			return fmt.Errorf("endpoint name %q is duplicated", endpoint.Name)
		}
		if endpoint.Protocol != ProtocolTCP && endpoint.Protocol != ProtocolUDP {
			return fmt.Errorf("endpoint %q has unsupported protocol %q", endpoint.Name, endpoint.Protocol)
		}
		if endpoint.ContainerPort == 0 {
			return fmt.Errorf("endpoint %q has an invalid zero port", endpoint.Name)
		}
		switch endpoint.Scope {
		case ScopePlayer:
			hasPlayerEndpoint = true
		case ScopeAdmin, ScopeInternal:
		default:
			return fmt.Errorf("endpoint %q has unsupported scope %q", endpoint.Name, endpoint.Scope)
		}
		names[endpoint.Name] = endpoint
	}
	if !hasPlayerEndpoint {
		return errors.New("at least one player endpoint is required")
	}
	if readiness != "" {
		endpoint, exists := names[readiness]
		if !exists {
			return fmt.Errorf("readiness endpoint %q is not defined", readiness)
		}
		if endpoint.Protocol != ProtocolTCP {
			return fmt.Errorf("readiness endpoint %q must use TCP", readiness)
		}
	}
	return nil
}

func validatePersistentPaths(paths []PersistentPath) error {
	names := make(map[string]struct{}, len(paths))
	mounts := make([]string, 0, len(paths))
	for _, persistentPath := range paths {
		if !namePattern.MatchString(persistentPath.Name) {
			return fmt.Errorf("persistent path %q must have a lowercase DNS-label name", persistentPath.Name)
		}
		if _, exists := names[persistentPath.Name]; exists {
			return fmt.Errorf("persistent path name %q is duplicated", persistentPath.Name)
		}
		if !strings.HasPrefix(persistentPath.MountPath, "/") || path.Clean(persistentPath.MountPath) != persistentPath.MountPath || persistentPath.MountPath == "/" {
			return fmt.Errorf("persistent path %q must be a clean absolute non-root path", persistentPath.Name)
		}
		if pathsOverlap(platformMountRoot, persistentPath.MountPath) {
			return fmt.Errorf("persistent path %q overlaps the reserved platform mount root %q", persistentPath.Name, platformMountRoot)
		}
		for _, mount := range mounts {
			if pathsOverlap(mount, persistentPath.MountPath) {
				return fmt.Errorf("persistent mount %q overlaps %q", persistentPath.MountPath, mount)
			}
		}
		names[persistentPath.Name] = struct{}{}
		mounts = append(mounts, persistentPath.MountPath)
	}
	return nil
}

func pathsOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func validateSettingsSchema(schema json.RawMessage) error {
	if len(schema) > 64*1024 {
		return errors.New("settings schema exceeds the 64 KiB limit")
	}
	if len(schema) == 0 {
		return errors.New("settings schema is required")
	}
	var document any
	if err := json.Unmarshal(schema, &document); err != nil {
		return fmt.Errorf("settings schema must be valid JSON: %w", err)
	}
	object, ok := document.(map[string]any)
	if !ok {
		return errors.New("settings schema must be a JSON object")
	}
	if object["type"] != "object" {
		return errors.New("settings schema must describe an object")
	}
	if err := rejectSchemaReferences(document); err != nil {
		return err
	}
	return nil
}

func rejectSchemaReferences(value any) error {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			switch key {
			case "$ref", "$dynamicRef", "$id", "$schema":
				return fmt.Errorf("settings schema keyword %q is not allowed", key)
			}
			if err := rejectSchemaReferences(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := rejectSchemaReferences(child); err != nil {
				return err
			}
		}
	}
	return nil
}

// ResolvedImage joins an adapter repository with a registry-resolved digest.
// Workloads never launch a mutable tag through this boundary.
func ResolvedImage(repository, digest string) (string, error) {
	if err := validateRepository(repository); err != nil {
		return "", err
	}
	if !digestPattern.MatchString(digest) {
		return "", errors.New("image digest must be a lowercase sha256 digest")
	}
	return repository + "@" + digest, nil
}
