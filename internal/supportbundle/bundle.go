// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package supportbundle collects a bounded, explicitly partial diagnostic.
// It has no mutation, Kubernetes, Secret, event, log or filesystem interface.
package supportbundle

import (
	"context"
	"errors"
	"sort"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/buildinfo"
)

var ErrTargetChanged = errors.New("diagnostic target changed")

// Reader is the authenticated admin client's validated, read-only DTO surface.
type Reader interface {
	Read(context.Context, string, any) (string, error)
}

// Server deliberately omits settings, endpoints, resource fields and maps.
// Future fields added to the ordinary Server DTO cannot silently enter bundles.
type Server struct {
	Name               string              `json:"name"`
	UID                string              `json:"uid"`
	Generation         int64               `json:"generation"`
	ObservedGeneration int64               `json:"observedGeneration"`
	DesiredState       string              `json:"desiredState"`
	Phase              string              `json:"phase"`
	RequestedImage     string              `json:"requestedImageDigest"`
	Conditions         []adminv1.Condition `json:"conditions"`
}

// Component also uses an explicit projection: expanding API/build DTOs must
// never silently expand support-bundle output.
type Component struct {
	SourceSHA   string `json:"sourceSha"`
	SourceEpoch int64  `json:"sourceEpoch"`
	GoVersion   string `json:"goVersion"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
}

type Bundle struct {
	SchemaVersion string     `json:"schemaVersion"`
	Scope         string     `json:"scope"`
	Partial       bool       `json:"partial"`
	Namespace     string     `json:"namespace"`
	CLI           Component  `json:"cli"`
	API           *Component `json:"api"`
	Server        Server     `json:"server"`
	Omissions     []string   `json:"omissions"`
}

// Collect closes the server UID/generation around independent version reads.
// This is a status observation, not an atomic snapshot, preflight certificate,
// proof of running image identity, or authority for another lifecycle intent.
func Collect(ctx context.Context, reader Reader, namespace, name string) (Bundle, error) {
	var before, after adminv1.Server
	if _, err := reader.Read(ctx, "/v1/servers/"+name, &before); err != nil {
		return Bundle{}, err
	}
	omissions := []string{"controller_versions_not_collected", "events_not_collected", "logs_not_collected", "running_image_identity_not_collected"}
	var api *Component
	version := new(adminv1.ComponentVersion)
	if _, err := reader.Read(ctx, "/v1/version", version); err != nil {
		var remote *adminclient.Error
		if !errors.As(err, &remote) || remote.HTTPStatus != 404 || remote.Code != "not_found" {
			return Bundle{}, err
		}
		omissions = append(omissions, "api_version_not_supported")
	} else {
		api = &Component{SourceSHA: version.SourceSHA, SourceEpoch: version.SourceEpoch, GoVersion: version.GoVersion, OS: version.OS, Arch: version.Arch}
		if api.SourceSHA == "unknown" {
			omissions = append(omissions, "api_source_unknown")
		}
	}
	if _, err := reader.Read(ctx, "/v1/servers/"+name, &after); err != nil {
		return Bundle{}, err
	}
	if before.Name != name || after.Name != name || before.UID == "" || before.UID != after.UID || before.Generation != after.Generation {
		return Bundle{}, ErrTargetChanged
	}
	conditions := make([]adminv1.Condition, 0, 6)
	for _, kind := range []string{"SpecValid", "StorageReady", "ConfigurationReady", "WorkloadReady", "NetworkReady", "Ready"} {
		for _, value := range after.Conditions {
			if value.Type == kind {
				reason, _ := adminv1.ConditionGuidance(value.Reason)
				conditions = append(conditions, adminv1.Condition{Type: kind, Status: value.Status, Reason: reason, ObservedGeneration: value.ObservedGeneration})
			}
		}
	}
	cli := buildinfo.Current()
	if cli.SourceSHA == "unknown" {
		omissions = append(omissions, "cli_source_unknown")
	}
	sort.Strings(omissions)
	return Bundle{SchemaVersion: "arcadectl.support/v1", Scope: "server-status-and-build-claims", Partial: true, Namespace: namespace,
		CLI: Component{SourceSHA: cli.SourceSHA, SourceEpoch: cli.SourceEpoch, GoVersion: cli.GoVersion, OS: cli.OS, Arch: cli.Arch}, API: api, Omissions: omissions,
		Server: Server{Name: after.Name, UID: after.UID, Generation: after.Generation, ObservedGeneration: after.ObservedGeneration,
			DesiredState: after.DesiredState, Phase: after.Phase, RequestedImage: after.ImageDigest, Conditions: conditions}}, nil
}
