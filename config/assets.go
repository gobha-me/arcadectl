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

// LegacyInstallation preserves the authentic predecessor's original bytes.
// Its separate prefix is deliberately outside every current Installation glob.
//
//go:embed legacy7dcbad/install/*.yaml legacy7dcbad/install/deployment.yaml.tmpl legacy7dcbad/rbac/*.yaml legacy7dcbad/api/*.yaml legacy7dcbad/api/deployment.yaml.tmpl
var LegacyInstallation embed.FS
