// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Permission-only fixtures never become sealed snapshots or ownership proof.
// The real API-server tests exercise the constructor and actual bound Verify.
func permissionInventory(t *testing.T, f *fixture, plan *installrender.Plan) installstate.Document {
	t.Helper()
	d := f.snapshot.Document()
	d.Stage, d.Mode, d.Installed = installstate.Complete, installstate.Install, true
	d.TargetPackage, d.ActivePackage, d.Resources = plan.Digest(), plan.Digest(), nil
	for _, resource := range plan.Resources() {
		key := resourceKey(resource)
		template, err := f.engine.contracts[plan.Digest()].Template(key, false)
		if err != nil {
			t.Fatal(err)
		}
		d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: types.UID("fixture-" + key.Name), TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
	}
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		d.Resources = append(d.Resources, installstate.Resource{Key: secretKey(d.Namespace, name), UID: types.UID("fixture-" + name), TemplateSHA256: strings.Repeat("a", 64), Retained: true})
	}
	return d
}

func assertPermissionBoundary(t *testing.T, namespace string, permissions []proofPermission) {
	t.Helper()
	seen := map[authv1.ResourceAttributes]bool{}
	for _, permission := range permissions {
		a := permission.spec.ResourceAttributes
		if a == nil {
			if permission.spec.NonResourceAttributes == nil || permission.spec.NonResourceAttributes.Verb != "get" {
				t.Fatal("unexpected nonresource authority")
			}
			continue
		}
		// ResourceAttributes contains selector pointers, but all of those must
		// be absent. They remain comparable and cannot escape the namespace.
		if a.FieldSelector != nil || a.LabelSelector != nil || a.Namespace != "" && a.Namespace != namespace || seen[*a] || a.Resource == "*" || a.Name == "*" || a.Verb == "*" || a.Verb == "patch" || a.Verb == "watch" || a.Verb == "deletecollection" {
			t.Fatal("unbounded or duplicate resource authority")
		}
		seen[*a] = true
		if a.Verb == "create" && a.Name != "" || a.Verb == "list" && a.Name != "" {
			t.Fatal("collection authorization incorrectly restricted by candidate name")
		}
		if a.Resource == "namespaces" && a.Verb != "get" && a.Verb != "update" || a.Resource == "persistentvolumeclaims" && a.Verb == "delete" || a.Resource == "secrets" && a.Verb != "get" && a.Verb != "list" && a.Verb != "create" {
			t.Fatal("retained-world or secret mutation authority")
		}
	}
}

func containsPermission(permissions []proofPermission, resource, subresource, name, verb string) bool {
	for _, permission := range permissions {
		if a := permission.spec.ResourceAttributes; a != nil && a.Resource == resource && a.Subresource == subresource && a.Name == name && a.Verb == verb {
			return true
		}
	}
	return false
}

func TestPrerequisitesOperationPermissionsAreExactAndDropSettledEffects(t *testing.T) {
	previous, target := lifecycleTransitionPlans(t)
	f := newFixtureWithPlans(t, false, previous, target)
	proof := &ClusterPrerequisites{engine: f.engine}
	d := permissionInventory(t, f, previous)
	derive := func(d installstate.Document, mode installstate.Mode, plan *installrender.Plan) []proofPermission {
		t.Helper()
		permissions, err := proof.documentPermissions(d, mode, plan)
		if err != nil {
			t.Fatal(err)
		}
		assertPermissionBoundary(t, d.Namespace, permissions)
		return permissions
	}
	uninstall := derive(d, installstate.Uninstall, previous)
	if d.Mode != installstate.Install || !containsPermission(uninstall, "deployments", "", "arcadectl-api", "delete") || !containsPermission(uninstall, "deployments", "", "arcadectl-controller", "update") || containsPermission(uninstall, "secrets", "", "", "create") || containsPermission(uninstall, "pods", "portforward", "", "create") {
		t.Fatal("requested uninstall did not override old completed-install mode")
	}
	for _, permission := range uninstall {
		a := permission.spec.ResourceAttributes
		if a == nil {
			continue
		}
		if a.Verb == "create" && a.Resource != "pods" && a.Resource != "persistentvolumeclaims" && a.Resource != "gamedestroys" {
			t.Fatal("uninstall requested persistent install/reinstall CREATE")
		}
		if (a.Resource == "customresourcedefinitions" || a.Resource == "validatingadmissionpolicies" || a.Resource == "validatingadmissionpolicybindings") && a.Verb != "get" && a.Verb != "list" {
			t.Fatal("uninstall requested retained admission/CRD mutation")
		}
	}
	partial := d
	partial.Stage = installstate.RecoveryRequired
	partial.Resources = nil
	for _, r := range d.Resources {
		if r.Key.Kind != "Deployment" {
			partial.Resources = append(partial.Resources, r)
		}
	}
	partialPermissions := derive(partial, installstate.Uninstall, previous)
	for _, permission := range partialPermissions {
		if a := permission.spec.ResourceAttributes; a != nil && a.Resource == "deployments" && a.Verb != "get" && a.Verb != "list" {
			t.Fatal("uninstall reauthorized a settled deployment effect")
		}
	}
	upgrade := derive(d, installstate.Upgrade, target)
	if !containsPermission(upgrade, "deployments", "", "arcadectl-api", "delete") || !containsPermission(upgrade, "deployments", "", "", "create") || !containsPermission(upgrade, "deployments", "", "arcadectl-controller", "update") || !containsPermission(upgrade, "pods", "portforward", "", "create") {
		t.Fatal("upgrade lacks API replacement/controller pause/activation union")
	}
	ready := permissionInventory(t, f, target)
	ready.Stage, ready.ActivePackage, ready.PreviousPackage = installstate.Applying, previous.Digest(), previous.Digest()
	settled := derive(ready, installstate.Upgrade, target)
	for _, permission := range settled {
		if a := permission.spec.ResourceAttributes; a != nil && a.Resource == "deployments" && a.Verb != "get" && a.Verb != "list" {
			t.Fatal("settled target deployments retained mutation authority")
		}
	}
	rollbackDocument := permissionInventory(t, f, target)
	rollbackDocument.PreviousPackage = previous.Digest()
	rollback := derive(rollbackDocument, installstate.Rollback, previous)
	if !containsPermission(rollback, "deployments", "", "arcadectl-api", "delete") || !containsPermission(rollback, "deployments", "", "", "create") || !containsPermission(rollback, "deployments", "", "arcadectl-controller", "update") {
		t.Fatal("rollback lacks predecessor replacement/pause authority")
	}
	reinstall := d
	reinstall.Installed, reinstall.Resources = false, nil
	for _, r := range d.Resources {
		if r.Retained {
			reinstall.Resources = append(reinstall.Resources, r)
		}
	}
	retaining := derive(reinstall, installstate.Install, previous)
	if !containsPermission(retaining, "deployments", "", "", "create") || containsPermission(retaining, "secrets", "", "", "create") || containsPermission(retaining, "customresourcedefinitions", "", "", "create") || containsPermission(retaining, "validatingadmissionpolicies", "", "", "create") {
		t.Fatal("retaining reinstall reauthorized retained creates")
	}
	fresh := f.snapshot.Document()
	fresh.Mode, fresh.Stage = installstate.Install, installstate.Preparing
	freshPermissions := derive(fresh, installstate.Install, previous)
	if !containsPermission(freshPermissions, "secrets", "", "", "create") || !containsPermission(freshPermissions, "customresourcedefinitions", "", "", "create") || containsPermission(freshPermissions, "namespaces", "", "", "create") {
		t.Fatal("fresh bound proof omitted initial creates or authorized namespace re-creation")
	}
}

func TestPrerequisitesRejectForeignPlansAndInvalidRequests(t *testing.T) {
	f := newFixture(t, false)
	proof := &ClusterPrerequisites{engine: f.engine}
	d := f.snapshot.Document()
	if _, err := proof.documentPermissions(d, installstate.Uninstall, f.plan); err == nil {
		t.Fatal("uninstall authorized without installed active package")
	}
	foreign := fixturePlanProfile(t, "other-install", installrender.Profile135)
	if _, err := proof.documentPermissions(d, installstate.Install, foreign); err == nil {
		t.Fatal("foreign namespace plan authorized")
	}
	if _, err := proof.permissions(LifecycleCheck{}); err == nil {
		t.Fatal("missing sealed snapshot accepted")
	}
	if err := proof.Verify(context.Background(), LifecycleCheck{}); err == nil {
		t.Fatal("incomplete checkpoint accepted")
	}
	if _, err := NewClusterPrerequisites(f.engine, &HTTPAccess{}); err == nil {
		t.Fatal("different access/journal identity accepted")
	}
}

func TestPrerequisitesInitialIssuanceRejectsInvalidLifetimeBeforeEffects(t *testing.T) {
	now := time.Date(2026, 10, 5, 21, 0, 0, 0, time.UTC)
	tls := fixtureTLS(t, "isolated-install", now)
	options := LifecycleOptions{Now: now, Credentials: tls, Activation: ActivationOptions{CAFile: tls.CAFile}}
	if err := verifyInitialTLS("isolated-install", options); err != nil {
		t.Fatal("valid protected issuance inputs refused")
	}
	for _, lifetime := range []time.Duration{0, -time.Second} {
		options.Credentials.AdminLifetime = lifetime
		if err := verifyInitialTLS("isolated-install", options); err == nil {
			t.Fatal("impossible administrator issuance passed preflight")
		}
	}
}
