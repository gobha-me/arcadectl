// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

// Intentionally NOT valid authentication material. The opening owner must
// hold private file identities but cannot claim authenticated activation from
// them. Later joint binding and actual HTTPS must independently validate bytes.
func testActivationEpochOptions(t *testing.T) ActivationOptions {
	t.Helper()
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private epoch fixture directory unavailable")
	}
	options := ActivationOptions{CredentialFile: filepath.Join(directory, "epoch-client.json"), CAFile: filepath.Join(directory, "epoch-ca.pem")}
	for _, path := range []string{options.CredentialFile, options.CAFile} {
		if os.WriteFile(path, []byte("synthetic descriptor witness; not authentication material\n"), 0600) != nil {
			t.Fatal("epoch fixture file unavailable")
		}
	}
	return options
}

func testActivationEpochWholeOpening(t *testing.T, inspect func(*activationEpoch)) {
	t.Helper()
	testBaselineBehaviorWholeProviderWithProtocol(t, "healthy", func(engine *Engine, snapshot *installstate.Snapshot, baseline *ClusterSecurityBaseline, requestCount func() int) error {
		p, err := NewClusterPrerequisites(engine, baseline.access)
		if err != nil {
			t.Fatal("actual epoch prerequisites unavailable")
		}
		target, err := NewClusterTargetAuthenticated(p)
		if err != nil {
			t.Fatal("actual epoch target unavailable")
		}
		request := LifecycleCheck{Checkpoint: TargetAuthenticated, Snapshot: snapshot, Mode: snapshot.Document().Mode, Target: engine.plans[snapshot.Document().TargetPackage], Options: LifecycleOptions{Now: time.Now().UTC(), Activation: testActivationEpochOptions(t)}}
		if snapshot.Document().Installed {
			t.Fatal("opening test lost fresh Install=false coverage")
		}
		before := requestCount()
		for _, change := range []string{"nil-context", "canceled-context", "nil-snapshot", "wrong-checkpoint", "nil-target", "wrong-mode", "zero-time", "missing-client-file"} {
			trial := request
			ctx := t.Context()
			switch change {
			case "nil-context":
				ctx = nil
			case "canceled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-snapshot":
				trial.Snapshot = nil
			case "wrong-checkpoint":
				trial.Checkpoint = Prerequisites
			case "nil-target":
				trial.Target = nil
			case "wrong-mode":
				trial.Mode = installstate.Uninstall
			case "zero-time":
				trial.Options.Now = time.Time{}
			case "missing-client-file":
				trial.Options.Activation.CredentialFile += ".missing"
			}
			owner, err := target.openActivationEpoch(ctx, trial)
			if owner != nil || err != ErrActivation || requestCount() != before {
				t.Fatal("invalid epoch scope acquired a proof or made a wire request", change)
			}
			if testBaselineReceiptDescriptors(t, "epoch-client.json") != 0 || testBaselineReceiptDescriptors(t, "epoch-ca.pem") != 0 {
				t.Fatal("refused or partially acquired epoch leaked its descriptors", change)
			}
		}
		owner, err := target.openActivationEpoch(t.Context(), request)
		if err != nil || owner == nil || owner.confirmLocal(t.Context()) != nil || owner.baseline != baseline || owner.behavior == nil || owner.source != nil || owner.phase.Load() != activationEpochOpen {
			t.Fatal("actual complete original opening proof did not acquire the private owner")
		}
		defer owner.release()
		if requestCount() <= before || testBaselineReceiptDescriptors(t, "epoch-client.json") != 1 || testBaselineReceiptDescriptors(t, "epoch-ca.pem") != 1 {
			t.Fatal("opening proof omitted wire verification or original file descriptors")
		}
		inspect(owner)
		owner.release()
		if owner.confirmLocal(t.Context()) != ErrActivation || owner.fence(t.Context()) != ErrActivation || testBaselineReceiptDescriptors(t, "epoch-client.json") != 0 || testBaselineReceiptDescriptors(t, "epoch-ca.pem") != 0 {
			t.Fatal("released owner revived evidence or leaked a descriptor")
		}
		return nil // The enclosing fixture independently checks all 97 rows.
	})
}

func TestActivationEpochWholeOpeningProofAndOwnerLifetime(t *testing.T) {
	testActivationEpochWholeOpening(t, func(owner *activationEpoch) {
		// Construct a copy without copying atomic noCopy fields. The sealed
		// self pointer still names the original; it must not close its pins.
		copied := &activationEpoch{self: owner, target: owner.target, request: owner.request, baseline: owner.baseline, behavior: owner.behavior, clientPin: owner.clientPin, caPin: owner.caPin, clientID: owner.clientID, caID: owner.caID}
		copied.phase.Store(activationEpochOpen)
		copied.release()
		if copied.confirmLocal(t.Context()) != ErrActivation || copied.fence(t.Context()) != ErrActivation || owner.confirmLocal(t.Context()) != nil {
			t.Fatal("copied owner confirmed evidence or released original ownership")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if owner.confirmLocal(ctx) != ErrActivation {
			t.Fatal("canceled owner observation was accepted")
		}
		var workers sync.WaitGroup
		for range 8 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				owner.release()
			}()
		}
		workers.Wait()
	})
}

func testActivationEpochIdenticalReplacement(t *testing.T, credential bool) {
	t.Helper()
	testActivationEpochWholeOpening(t, func(owner *activationEpoch) {
		path := owner.request.Options.Activation.CAFile
		if credential {
			path = owner.request.Options.Activation.CredentialFile
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("original epoch bytes unavailable")
		}
		for range 2 {
			if os.WriteFile(path+".replacement", body, 0600) != nil || os.Rename(path+".replacement", path) != nil {
				t.Fatal("identical fixture replacement unavailable")
			}
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(body, after) || testBaselineReceiptDescriptors(t, filepath.Base(path)) != 1 {
			t.Fatal("replacement changed bytes or opening inode was not held")
		}
		if owner.confirmLocal(t.Context()) != ErrActivation || owner.fence(t.Context()) != ErrActivation {
			t.Fatal("identical-byte replacement revived original file identity")
		}
	})
}

func TestActivationEpochCredentialReplacementRefusesOriginalOwner(t *testing.T) {
	testActivationEpochIdenticalReplacement(t, true)
}

func TestActivationEpochCAReplacementRefusesOriginalOwner(t *testing.T) {
	testActivationEpochIdenticalReplacement(t, false)
}
