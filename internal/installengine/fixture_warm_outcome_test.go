// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

// Optional private TEST bookkeeping, not CI/release, identity or safety authority.
// No object, log, error, identity, credential, environment or path is recorded.
// Records child checks/cleanup only, NOT terminal root/package/runner success:
// writing or closing this store can still fail after the child result is visible.
// Missing evidence is unknown; even children-passed requires separately verified
// terminal runner success. Use a fresh protected directory on persistent storage.
type warmNativeOutcome struct {
	files   *privatefs.Store
	binary  string
	started string
}

func beginWarmNativeOutcome() (*warmNativeOutcome, error) {
	dir := os.Getenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES")
	if dir == "" {
		return nil, nil
	}
	files, err := privatefs.Open(dir, false)
	if err != nil {
		return nil, errWarmOutcomeDirectory
	}
	ok := false
	defer func() {
		if !ok {
			_ = files.Close()
		}
	}()
	if _, _, err := files.Read("warm-controllers-result.json", 4096); err != privatefs.ErrNotFound {
		return nil, errWarmOutcomeResult
	}
	path, err := os.Executable()
	if err != nil {
		return nil, errWarmOutcomeExecutable
	}
	binary, err := os.Open(path)
	if err != nil {
		return nil, errWarmOutcomeExecutable
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, binary)
	closeErr := binary.Close()
	if readErr != nil || closeErr != nil {
		return nil, errWarmOutcomeExecutable
	}
	r := &warmNativeOutcome{files: files, binary: hex.EncodeToString(hash.Sum(nil)), started: time.Now().UTC().Format(time.RFC3339Nano)}
	body, err := json.Marshal(map[string]any{"format": "warm-native-child-outcome-v1", "scope": "native-child-checks-and-cleanup", "state": "started", "binarySHA256": r.binary, "startedAt": r.started})
	if err != nil {
		return nil, ErrFixtures
	}
	if _, err := files.CreateExclusive("warm-controllers-start.json", body); err != nil {
		return nil, errWarmOutcomeStart
	}
	ok = true
	return r, nil
}

// Fixed test-only stages; never retain or print the underlying platform error.
type warmOutcomeSetupError string

func (e warmOutcomeSetupError) Error() string { return string(e) }
func (e warmOutcomeSetupError) Unwrap() error { return ErrFixtures }

const (
	errWarmOutcomeDirectory  warmOutcomeSetupError = "private native outcome directory unavailable"
	errWarmOutcomeResult     warmOutcomeSetupError = "private native outcome prior-result check refused"
	errWarmOutcomeExecutable warmOutcomeSetupError = "private native outcome executable hash unavailable"
	errWarmOutcomeStart      warmOutcomeSetupError = "private native outcome start persistence refused"
)

// Called by the native root cleanup AFTER both child Runs (including every
// child's original-object and exact-owned Docker cleanup) returned. Each flag
// additionally requires the child to reach its complete body, so skipped or
// unrun children cannot masquerade as successful Runs.
func (r *warmNativeOutcome) finish(failed bool, complete [2]bool) error {
	if r == nil {
		return nil
	}
	state := "children-incomplete"
	if failed {
		state = "children-failed"
	} else if complete == [2]bool{true, true} {
		state = "children-passed"
	}
	body, err := json.Marshal(map[string]any{
		"format": "warm-native-child-outcome-v1", "scope": "native-child-checks-and-cleanup", "state": state, "binarySHA256": r.binary,
		"startedAt": r.started, "finishedAt": time.Now().UTC().Format(time.RFC3339Nano),
		"profiles": []any{map[string]any{"id": installrender.Profile135, "complete": complete[0]}, map[string]any{"id": installrender.Profile137, "complete": complete[1]}},
	})
	if err != nil {
		return ErrFixtures
	}
	_, err = r.files.CreateExclusive("warm-controllers-result.json", body)
	if err != nil {
		return ErrFixtures
	}
	return nil
}

func TestWarmNativeOutcomeIsPrivateClosedAndIncompleteFails(t *testing.T) {
	t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", "")
	if r, err := beginWarmNativeOutcome(); err != nil || r != nil {
		t.Fatal("disabled bookkeeping accessed private evidence")
	}
	var absent *warmNativeOutcome
	if absent.finish(false, [2]bool{true, true}) != nil {
		t.Fatal("disabled bookkeeping wrote a result")
	}
	for _, tc := range []struct {
		failed   bool
		complete [2]bool
		state    string
	}{
		{false, [2]bool{true, true}, "children-passed"}, {true, [2]bool{true, true}, "children-failed"},
		{false, [2]bool{true, false}, "children-incomplete"}, {false, [2]bool{false, true}, "children-incomplete"},
		{false, [2]bool{}, "children-incomplete"}, {true, [2]bool{}, "children-failed"},
	} {
		base := t.TempDir()
		if os.Chmod(base, 0700) != nil {
			t.Fatal("protected bookkeeping ancestor unavailable")
		}
		dir := filepath.Join(base, "PRIVATE-PATH-CANARY")
		if os.Mkdir(dir, 0700) != nil {
			t.Fatal("protected bookkeeping directory unavailable")
		}
		check, err := privatefs.Open(dir, false)
		if err != nil {
			t.Fatal("test bookkeeping directory is unsafe")
		}
		if check.Close() != nil {
			t.Fatal("test bookkeeping descriptor cleanup failed")
		}
		t.Setenv("ARCADECTL_TEST_NATIVE_FIXTURE_SHAPES", dir)
		r, err := beginWarmNativeOutcome()
		if err != nil {
			t.Fatal("closed bookkeeping unavailable")
		}
		if r.finish(tc.failed, tc.complete) != nil {
			t.Fatal("closed bookkeeping failed")
		}
		body, id, err := r.files.Read("warm-controllers-result.json", 4096)
		if err != nil || r.files.ConfirmDurable("warm-controllers-result.json", id) != nil || strings.Contains(string(body), "PRIVATE-PATH-CANARY") {
			t.Fatal("bookkeeping durability/privacy failed")
		}
		var got map[string]any
		if json.Unmarshal(body, &got) != nil || len(got) != 7 || got["state"] != tc.state || got["binarySHA256"] != r.binary || got["format"] != "warm-native-child-outcome-v1" || got["scope"] != "native-child-checks-and-cleanup" || len(r.binary) != 64 {
			t.Fatal("bookkeeping escaped closed fields/state")
		}
		for _, name := range []string{"warm-controllers-start.json", "warm-controllers-result.json"} {
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("bookkeeping file is not private")
			}
		}
		if r.finish(false, [2]bool{true, true}) != ErrFixtures {
			t.Fatal("terminal bookkeeping was overwritten")
		}
		if r.files.Close() != nil {
			t.Fatal("bookkeeping descriptor cleanup failed")
		}
		if _, err := beginWarmNativeOutcome(); !errors.Is(err, ErrFixtures) {
			t.Fatal("stale result accepted by a new run")
		}
	}
}
