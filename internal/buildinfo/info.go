// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package buildinfo exposes bounded build claims, not artifact authentication.
package buildinfo

import (
	"regexp"
	"runtime"
	"strconv"
)

// SourceSHA and SourceEpoch are set only by the exact-source artifact builder.
// Ordinary development builds intentionally report an unknown source identity.
var SourceSHA = "unknown"
var SourceEpoch = "0"

type Info struct {
	SourceSHA   string `json:"sourceSha"`
	SourceEpoch int64  `json:"sourceEpoch"`
	GoVersion   string `json:"goVersion"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
}

func Current() Info {
	sha, epoch := "unknown", int64(0)
	if regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(SourceSHA) {
		if parsed, err := strconv.ParseInt(SourceEpoch, 10, 64); err == nil && parsed > 0 && parsed <= 253402300799 {
			sha, epoch = SourceSHA, parsed
		}
	}
	return Info{SourceSHA: sha, SourceEpoch: epoch, GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
}
