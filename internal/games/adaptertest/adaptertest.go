// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package adaptertest checks the shared contract of curated game adapters.
// It is test support and must not be imported into production binaries.
package adaptertest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/gobha-me/arcadectl/internal/platform/game"
)

// EquivalentPair contains two encodings of the same settings meaning.
type EquivalentPair struct {
	Left  json.RawMessage
	Right json.RawMessage
}

// Case supplies an adapter and non-empty collections of valid settings,
// equivalent encodings and settings the renderer must reject.
type Case struct {
	Definition game.Definition
	Valid      []json.RawMessage
	Equivalent []EquivalentPair
	Invalid    []json.RawMessage
}

// Run reports every conformance failure through the calling test.
func Run(t *testing.T, c Case) {
	t.Helper()
	for _, err := range Check(c) {
		t.Error(err)
	}
}

// Check exercises the real adapter without changing caller-owned data. It
// returns contextual failures instead of requiring a testing.T, enabling the
// kit's self-tests to exercise deliberately broken adapters.
func Check(c Case) []error {
	// Do not rely on Clone to isolate the caller: clone isolation is itself one
	// of the contracts under test, including when a future Clone regresses.
	d := detached(c.Definition)
	if err := d.Validate(); err != nil {
		return []error{fmt.Errorf("definition: %w", err)}
	}
	var failures []error
	if len(c.Valid) == 0 || len(c.Equivalent) == 0 || len(c.Invalid) == 0 {
		failures = append(failures, fmt.Errorf("case requires valid, equivalent and invalid samples"))
	}
	for i, sample := range c.Valid {
		first, err := d.RenderSettingsFiles(sample)
		if err != nil {
			failures = append(failures, fmt.Errorf("valid[%d] render: %w", i, err))
			continue
		}
		second, err := d.RenderSettingsFiles(sample)
		if err != nil {
			failures = append(failures, fmt.Errorf("valid[%d] repeat render: %w", i, err))
		} else if !reflect.DeepEqual(first, second) {
			failures = append(failures, fmt.Errorf("valid[%d] render is not deterministic", i))
		}
		// RenderSettingsFiles enforces the exact declared names, destinations,
		// file count and content bounds; its error is a conformance failure.
		var object map[string]json.RawMessage
		if err := json.Unmarshal(sample, &object); err != nil || object == nil {
			failures = append(failures, fmt.Errorf("valid[%d] must be a JSON object", i))
			continue
		}
		key := "__arcadectl_conformance_unknown"
		for object[key] != nil {
			key += "_"
		}
		object[key] = json.RawMessage(`1`)
		unknown, err := json.Marshal(object)
		if err != nil {
			failures = append(failures, fmt.Errorf("valid[%d] unknown-field fixture: %w", i, err))
			continue
		}
		if _, err := d.RenderSettingsFiles(unknown); err == nil {
			failures = append(failures, fmt.Errorf("valid[%d] renderer accepted unknown top-level field", i))
		}
		trailing := append(bytes.Clone(sample), []byte(" {}")...)
		if _, err := d.RenderSettingsFiles(trailing); err == nil {
			failures = append(failures, fmt.Errorf("valid[%d] renderer accepted trailing JSON value", i))
		}
	}
	for i, pair := range c.Equivalent {
		left, leftErr := d.SettingsDigest(pair.Left)
		right, rightErr := d.SettingsDigest(pair.Right)
		if leftErr != nil || rightErr != nil {
			failures = append(failures, fmt.Errorf("equivalent[%d] digest errors: left=%v right=%v", i, leftErr, rightErr))
		} else if left != right {
			failures = append(failures, fmt.Errorf("equivalent[%d] settings digests differ", i))
		}
	}
	for i, sample := range c.Invalid {
		if _, err := d.RenderSettingsFiles(sample); err == nil {
			failures = append(failures, fmt.Errorf("invalid[%d] renderer accepted invalid settings", i))
		}
	}
	return append(failures, cloneIsolation(d, d.Clone())...)
}

func detached(d game.Definition) game.Definition {
	d.Endpoints = append([]game.Endpoint(nil), d.Endpoints...)
	d.PersistentPaths = append([]game.PersistentPath(nil), d.PersistentPaths...)
	d.ConfigurationTargets = append([]game.ConfigurationTarget(nil), d.ConfigurationTargets...)
	d.SettingsSchema = bytes.Clone(d.SettingsSchema)
	if d.VersionPolicy != nil {
		policy := *d.VersionPolicy
		d.VersionPolicy = &policy
	}
	return d
}

func cloneIsolation(original, clone game.Definition) []error {
	before := detached(original)
	for i := range clone.Endpoints {
		clone.Endpoints[i].Name = "changed"
		clone.Endpoints[i].ContainerPort = 0
	}
	for i := range clone.PersistentPaths {
		clone.PersistentPaths[i].MountPath = "/"
	}
	for i := range clone.ConfigurationTargets {
		clone.ConfigurationTargets[i].MountPath = "/"
	}
	for i := range clone.SettingsSchema {
		clone.SettingsSchema[i] = '!'
	}
	if clone.VersionPolicy != nil {
		clone.VersionPolicy.Pattern = ""
	}
	var failures []error
	for _, field := range []struct {
		name        string
		before, now any
	}{
		{"endpoints", before.Endpoints, original.Endpoints},
		{"persistent paths", before.PersistentPaths, original.PersistentPaths},
		{"configuration targets", before.ConfigurationTargets, original.ConfigurationTargets},
		{"schema bytes", before.SettingsSchema, original.SettingsSchema},
		{"version policy", before.VersionPolicy, original.VersionPolicy},
	} {
		if !reflect.DeepEqual(field.before, field.now) {
			failures = append(failures, fmt.Errorf("clone aliases %s", field.name))
		}
	}
	if err := original.Validate(); err != nil {
		failures = append(failures, fmt.Errorf("clone mutation invalidated original: %w", err))
	}
	return failures
}
