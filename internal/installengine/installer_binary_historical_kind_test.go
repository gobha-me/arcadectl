//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

func buildHistoricalInstallerBinary(t *testing.T, ctx context.Context, root, base string) string {
	t.Helper()
	identity := exec.CommandContext(ctx, "git", "rev-parse", binaryHistoricalInstallerSource+"^{tree}")
	identity.Dir = root
	tree, err := identity.Output()
	if err != nil || strings.TrimSpace(string(tree)) != binaryHistoricalInstallerTree {
		t.Fatal("exact historical installer tree unavailable; acquire its preserved PR history before testing")
	}
	sourceRoot := filepath.Join(base, "historical-installer-source")
	archive := filepath.Join(base, "historical-installer-source.tar")
	if os.Mkdir(sourceRoot, 0700) != nil {
		t.Fatal("private historical installer source directory unavailable")
	}
	run := func(dir, executable string, args ...string) {
		command := exec.CommandContext(ctx, executable, args...)
		command.Dir = dir
		command.Env = append(os.Environ(), "GOMAXPROCS=2", "GOMEMLIMIT=1GiB")
		if _, err := command.CombinedOutput(); err != nil {
			t.Fatal("exact historical installer archive/build refused")
		}
	}
	run(root, "git", "archive", "--format=tar", "--output="+archive, binaryHistoricalInstallerSource)
	run(root, "tar", "--extract", "--file", archive, "--directory", sourceRoot, "--no-same-owner")
	binary := filepath.Join(base, "arcadectl-installer-historical")
	run(sourceRoot, "go", "build", "-p", "1", "-trimpath", "-o", binary, "./cmd/arcadectl-installer")
	return binary
}

// Separate historical checkpoint. Post-enrollment checkComplete must keep its
// strict complete-baseline requirements; nil is legitimate only HERE after the
// exact older executable completed the authentic predecessor install.
func checkBinaryHistoricalInstall(t *testing.T, ctx context.Context, access *HTTPAccess, journal *installstate.Store, state string, original *installrender.Plan, baseline *installbaseline.Plan) (*installstate.Snapshot, map[string][]byte) {
	t.Helper()
	files, err := privatefs.Open(state, false)
	if err != nil {
		t.Fatal("historical protected state unavailable")
	}
	defer files.Close()
	receipt, err := installstate.LoadBootstrap(files, "bootstrap.json", original)
	if err != nil {
		t.Fatal("authentic no-baseline bootstrap receipt unavailable")
	}
	anchor, err := receipt.PinnedAnchor(ctx)
	if err != nil {
		t.Fatal("historical original Namespace ACK unavailable")
	}
	snapshot, err := journal.Load(ctx, anchor)
	if err != nil {
		t.Fatal("authentic no-baseline journal unavailable")
	}
	d := snapshot.Document()
	if d.Mode != installstate.Install || d.Stage != installstate.Complete || !d.Installed || d.Pending != nil || d.SecurityBaseline != nil || d.ActivePackage != original.Digest() || d.TargetPackage != original.Digest() {
		t.Fatal("older executable did not complete the exact no-baseline install")
	}
	for _, resource := range baseline.Resources() {
		if _, err := access.Get(ctx, baselineObjectKey(resource.Object)); !apierrors.IsNotFound(err) {
			t.Fatal("historical setup silently preinstalled a new baseline object")
		}
	}
	verifyBinaryOriginalRuntime(t, ctx, access, original, snapshot)
	inputs := map[string][]byte{}
	for _, name := range []string{"bootstrap.json", "admin-client-" + anchor.InstallationID + ".json", "api-ca-" + anchor.InstallationID + ".pem"} {
		body, _, err := files.Read(name, installstate.MaxBytes)
		if err != nil {
			t.Fatal("original historical recovery input unavailable")
		}
		inputs[name] = bytes.Clone(body)
	}
	return snapshot, inputs
}

func verifyBinaryOriginalRuntime(t *testing.T, ctx context.Context, access *HTTPAccess, plan *installrender.Plan, snapshot *installstate.Snapshot) {
	t.Helper()
	contract, err := installcontract.New(plan)
	if err != nil {
		t.Fatal("historical signed runtime contract unavailable")
	}
	for _, resource := range plan.Resources() {
		key := resourceKey(resource)
		var entry *installstate.Resource
		for _, row := range snapshot.Document().Resources {
			if row.Key == key {
				copy := row
				entry = &copy
			}
		}
		template, templateErr := contract.Template(key, false)
		live, readErr := access.Get(ctx, key)
		if entry == nil || templateErr != nil || readErr != nil || entry.TemplateSHA256 != template.Hash() {
			t.Fatal("historical original signed inventory unavailable")
		}
		if key.Kind == "Namespace" {
			if template.MatchNamespace(live, snapshot) != nil {
				t.Fatal("historical original Namespace changed")
			}
		} else if template.MatchLive(live, entry.UID) != nil {
			t.Fatal("historical original runtime identity or signed shape changed")
		}
	}
}

func checkBinaryHistoricalEnrollment(t *testing.T, ctx context.Context, access *HTTPAccess, state string, original *installrender.Plan, before, after *installstate.Snapshot, inputs map[string][]byte, claims []fixtureWorldRow) ([]byte, string) {
	t.Helper()
	d := after.Document()
	baseline := d.SecurityBaseline
	if baseline == nil || baseline.Enrollment == nil || before.Anchor() != after.Anchor() || baseline.Enrollment.SourceRevision != before.Document().Revision || baseline.Enrollment.SourceJournalSHA256 != fixtureWorldDigest(before.Bytes()) {
		t.Fatal("enrollment lost exact original source provenance")
	}
	d.SecurityBaseline, d.Revision = nil, before.Document().Revision
	if !reflect.DeepEqual(d, before.Document()) {
		t.Fatal("historical enrollment changed authentic runtime history")
	}
	verifyBinaryOriginalRuntime(t, ctx, access, original, after)
	files, err := privatefs.Open(state, false)
	if err != nil {
		t.Fatal("protected enrollment audit inputs unavailable")
	}
	defer files.Close()
	for name, originalBody := range inputs {
		body, _, err := files.Read(name, installstate.MaxBytes)
		if err != nil || !bytes.Equal(body, originalBody) {
			t.Fatal("enrollment rewrote an original bootstrap/client/CA input")
		}
	}
	name, err := baselineEnrollmentSourceName(before.Anchor().InstallationID, before.Document().Revision)
	body, _, readErr := files.ReadEvidence(name, privatefs.MaxEvidenceFileBytes)
	if err != nil || readErr != nil || fixtureWorldDigest(body) != baseline.Enrollment.SourceEvidenceSHA256 {
		t.Fatal("enrollment omitted original protected source envelope")
	}
	// Independent envelope decode, not the production source confirmer.
	var source baselineEnrollmentSourceReceipt
	if json.Unmarshal(body, &source) != nil || source.Version != "arcadectl.install-baseline-enrollment-source/v1" || source.BaselineSHA256 != baseline.ArtifactDigest || source.JournalResourceVersion != before.ResourceVersion() || !bytes.Equal(source.Journal, before.Bytes()) || source.Bootstrap.ReceiptName != "bootstrap.json" || source.Bootstrap.PackageSHA256 != original.Digest() || source.Bootstrap.SHA256 != fixtureWorldDigest(inputs["bootstrap.json"]) || source.CASHA256 != fixtureWorldDigest(inputs["api-ca-"+before.Anchor().InstallationID+".pem"]) || !reflect.DeepEqual(source.Worlds, claims) {
		t.Fatal("enrollment source lost original input hashes or retained claim floor")
	}
	return body, name
}

func binaryPackageFileDigests(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 32*1024*1024 {
			return fmt.Errorf("invalid owned package fixture file")
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[name] = fixtureWorldDigest(body)
		return nil
	})
	if err != nil || len(result) == 0 {
		t.Fatal("authentic predecessor file census unavailable")
	}
	return result
}
