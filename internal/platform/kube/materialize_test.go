// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMaterializeConfigurationScript(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("runtime materializer uses the Linux container shell")
	}

	root := filepath.Join(t.TempDir(), "world; shell syntax stays data")
	sourceDirectory := t.TempDir()
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("create persistent root: %v", err)
	}
	firstSource := filepath.Join(sourceDirectory, "first")
	secondSource := filepath.Join(sourceDirectory, "second")
	writeTestFile(t, firstSource, "first version\n")
	writeTestFile(t, secondSource, "second file\n")
	firstTarget := filepath.Join(root, "config", "first.conf")
	secondTarget := filepath.Join(root, "other", "second.conf")
	runMaterializer(t, true,
		root, firstSource, firstTarget,
		root, secondSource, secondTarget,
	)
	assertTestFile(t, firstTarget, "first version\n", 0o444)
	assertTestFile(t, secondTarget, "second file\n", 0o444)

	writeTestFile(t, firstSource, "updated\n")
	declaredSibling := firstTarget + ".arcadectl.tmp"
	writeTestFile(t, declaredSibling, "retained world data\n")
	runMaterializer(t, true, root, firstSource, firstTarget)
	assertTestFile(t, firstTarget, "updated\n", 0o444)
	assertTestFile(t, declaredSibling, "retained world data\n", 0o644)
	temporaryFiles, err := filepath.Glob(filepath.Join(root, "config", ".arcadectl-configuration.*"))
	if err != nil {
		t.Fatalf("find temporary materializer files: %v", err)
	}
	if len(temporaryFiles) != 0 {
		t.Fatalf("temporary materializer files remain: %v", temporaryFiles)
	}
}

func TestMaterializeConfigurationRejectsSymlinks(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("runtime materializer uses Linux symlink semantics")
	}

	t.Run("parent", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		source := filepath.Join(t.TempDir(), "source")
		writeTestFile(t, source, "safe\n")
		if err := os.Symlink(outside, filepath.Join(root, "config")); err != nil {
			t.Fatalf("create parent symlink: %v", err)
		}
		runMaterializer(t, false, root, source, filepath.Join(root, "config", "server.conf"))
		if _, err := os.Lstat(filepath.Join(outside, "server.conf")); !os.IsNotExist(err) {
			t.Fatalf("materializer wrote through parent symlink: %v", err)
		}
	})

	t.Run("target", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(t.TempDir(), "source")
		outside := filepath.Join(t.TempDir(), "outside")
		writeTestFile(t, source, "safe\n")
		writeTestFile(t, outside, "unchanged\n")
		targetDirectory := filepath.Join(root, "config")
		if err := os.Mkdir(targetDirectory, 0o755); err != nil {
			t.Fatalf("create target directory: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(targetDirectory, "server.conf")); err != nil {
			t.Fatalf("create target symlink: %v", err)
		}
		runMaterializer(t, false, root, source, filepath.Join(targetDirectory, "server.conf"))
		assertTestFile(t, outside, "unchanged\n", 0o644)
	})
}

func runMaterializer(t *testing.T, wantSuccess bool, pathTuples ...string) {
	t.Helper()
	arguments := append([]string{"-ec", materializeConfigurationScript, "arcadectl-configuration-materializer"}, pathTuples...)
	output, err := exec.Command("/bin/sh", arguments...).CombinedOutput()
	if wantSuccess && err != nil {
		t.Fatalf("materializer failed: %v\n%s", err, output)
	}
	if !wantSuccess && err == nil {
		t.Fatalf("materializer unexpectedly succeeded:\n%s", output)
	}
}

func writeTestFile(t *testing.T, name, contents string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func assertTestFile(t *testing.T, name, wantContents string, wantMode os.FileMode) {
	t.Helper()
	contents, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if string(contents) != wantContents {
		t.Errorf("%s contents = %q, want %q", name, contents, wantContents)
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	if info.Mode().Perm() != wantMode {
		t.Errorf("%s mode = %o, want %o", name, info.Mode().Perm(), wantMode)
	}
}
