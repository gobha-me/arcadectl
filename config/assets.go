// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package config contains the reviewed installation templates embedded into the
// installer. Package signatures do not authorize arbitrary Kubernetes manifests.
package config

import "embed"

// Installation includes only the canonical installation resource inputs.
// Consumers must not use arbitrary paths supplied by a package or user.
//
//go:embed install/*.yaml install/deployment.yaml.tmpl rbac/*.yaml api/*.yaml api/deployment.yaml.tmpl
var Installation embed.FS
