// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import "encoding/json"

const OptionMetadataVersion = "v1"

// OptionMetadata describes only the supported, non-secret settings subset.
// Nil metadata means discovery is unavailable, never that arbitrary settings
// are supported. This contract is descriptive and cannot execute changes.
type OptionMetadata struct {
	Version     string
	Supported   []SettingOption
	Unsupported []UnsupportedOption
}

// SettingOption binds a stable identifier to one top-level schema property.
// Schema is the exact scalar JSON-schema fragment, including type and bounds.
// OmittedValue describes renderer output; Default is an optional schema-valid
// explicit input. Neither value is inserted into administrator settings.
type SettingOption struct {
	ID           string
	Property     string
	Label        string
	Help         string
	Group        string
	Schema       json.RawMessage
	Lifecycle    OptionLifecycle
	Availability OptionAvailability
	Omission     OptionOmission
	OmittedValue json.RawMessage
	Default      json.RawMessage
}

type UnsupportedOption struct {
	ID     string
	Reason string
}

type OptionLifecycle string

const (
	OptionRestartRequired OptionLifecycle = "restart-required"
	OptionCreateOnly      OptionLifecycle = "create-only"
)

type OptionOmission string

const (
	OptionRequired      OptionOmission = "required"
	OptionRendererValue OptionOmission = "renderer-value"
)

// OptionAvailability is a half-open interval of numeric major.minor.patch game
// versions, intersected with the adapter's curated version policy. Empty bounds
// mean no additional restriction; they do not certify any game/image version.
type OptionAvailability struct {
	Since  string
	Before string
}

// OptionMetadataError reports a stable refusal category without reflecting
// adapter-provided labels, values, help text or schema contents.
type OptionMetadataError struct{ Category string }

func (e *OptionMetadataError) Error() string { return "invalid option metadata: " + e.Category }

func (m *OptionMetadata) clone() *OptionMetadata {
	if m == nil {
		return nil
	}
	c := *m
	c.Supported = append([]SettingOption(nil), m.Supported...)
	for i := range c.Supported {
		c.Supported[i].Schema = append(json.RawMessage(nil), m.Supported[i].Schema...)
		c.Supported[i].OmittedValue = append(json.RawMessage(nil), m.Supported[i].OmittedValue...)
		c.Supported[i].Default = append(json.RawMessage(nil), m.Supported[i].Default...)
	}
	c.Unsupported = append([]UnsupportedOption(nil), m.Unsupported...)
	return &c
}
