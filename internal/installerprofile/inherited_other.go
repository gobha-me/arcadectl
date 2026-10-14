// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package installerprofile

// StartInherited never enables the Linux descriptor protocol on other systems.
func StartInherited() *Session { return nil }
