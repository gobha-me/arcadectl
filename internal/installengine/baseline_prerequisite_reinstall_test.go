// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

// The legacy uninstall is genuinely completed; baseline enrollment/health is
// explicitly synthetic. Real source→Preparing→Applying journal CAS is used,
// but this fixture supplies no production guard or access recreation proof.
func retainedPrerequisiteFixture(t *testing.T) (*fixture, *installstate.Snapshot, string, string) {
	t.Helper()
	v, current, sourceName, retirementName := retainedPrerequisiteLifecycleFixture(t)
	return v.f, current, sourceName, retirementName
}

func retainedPrerequisiteLifecycleFixture(t *testing.T) (*lifecycleFixture, *installstate.Snapshot, string, string) {
	t.Helper()
	v, source := reinstallReceiptLifecycleFixture(t)
	f := v.f
	published, err := f.engine.saveReinstallSource(source)
	t.Cleanup(published.release)
	if err != nil {
		t.Fatal("original retained source publication unavailable")
	}
	provenance, sourceName, retirementName := published.provenance, published.name, published.retirement.name
	published.release() // no external descriptor safety net for the tested owner
	d := source.Document()
	d.Mode, d.Stage, d.AdmissionRetirementRevision = installstate.Install, installstate.Preparing, 0
	d.Revision++
	d.AdmissionReinstall = &provenance
	current, err := f.store.Commit(t.Context(), source, d)
	if err != nil {
		t.Fatal("retained source Begin journal CAS failed")
	}
	current, err = (&Lifecycle{engine: f.engine}).stage(t.Context(), current, installstate.Applying)
	if err != nil {
		t.Fatal("original retained Applying journal CAS failed")
	}
	f.snapshot = current
	if testBaselineReceiptDescriptors(t, sourceName) != 0 || testBaselineReceiptDescriptors(t, retirementName) != 0 {
		t.Fatal("retained fixture kept a publication descriptor alive")
	}
	return v, current, sourceName, retirementName
}

func TestBaselinePrerequisiteRetainedContextClosesSignedInventoryUnion(t *testing.T) {
	f, current, _, _ := retainedPrerequisiteFixture(t)
	d := current.Document()
	writes, namespaceWrites := f.access.writes, f.nsUpdates
	var eligible []installstate.Key
	kinds := map[string]bool{}
	for _, resource := range f.plan.ResourceMetadata() {
		key := installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
		op, err := f.engine.prerequisiteOperation(current, key, d.TargetPackage)
		// Independent protocol oracle, not the predicates under test.
		eligibleKey := false
		switch key.APIVersion + "/" + key.Kind {
		case "v1/ServiceAccount", "rbac.authorization.k8s.io/v1/Role", "rbac.authorization.k8s.io/v1/RoleBinding":
			eligibleKey = key.Namespace == d.Namespace && !resource.Retained
		case "rbac.authorization.k8s.io/v1/ClusterRole", "rbac.authorization.k8s.io/v1/ClusterRoleBinding":
			eligibleKey = key.Namespace == "" && !resource.Retained
		}
		if eligibleKey {
			if err != nil || op == nil || op.key != key || op.digest != d.TargetPackage {
				t.Fatal("original signed retained-bootstrap access key refused")
			}
			eligible = append(eligible, key)
			kinds[key.Kind] = true
		} else if err != ErrSecurityBaseline || op != nil {
			t.Fatal("retained root, credential, service or executor became a bootstrap target")
		}
	}
	if len(kinds) != 5 || f.access.writes != writes || f.nsUpdates != namespaceWrites {
		t.Fatal("retained context did not cover all five access kinds without effects")
	}
	// A synthetic protected ACK is settled through the real Store transition,
	// not bulk injected. This is context coverage, not remote effect authority.
	first, next := eligible[0], eligible[1]
	template, err := f.engine.contracts[d.TargetPackage].Template(first, false)
	if err != nil {
		t.Fatal("original first access template unavailable")
	}
	d.Revision++
	d.Pending = &installstate.Pending{Action: installstate.Create, Key: first, CreateNonce: strings.Repeat("c", 32), AfterSHA256: template.Hash()}
	intent, err := f.store.Commit(t.Context(), current, d)
	if err != nil || f.engine.prepareCreateReceipt(d) != nil || f.engine.saveCreateUID(d, "synthetic-original-access") != nil {
		t.Fatal("original access intent/ACK fixture unavailable")
	}
	d = intent.Document()
	d.Revision++
	d.Pending = nil
	d.Resources = append(d.Resources, installstate.Resource{Key: first, UID: "synthetic-original-access", TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: false})
	installstate.SortResources(d.Resources)
	settled, err := f.store.Commit(t.Context(), intent, d)
	if err != nil {
		t.Fatal("original ACK-shaped access settlement journal CAS failed")
	}
	if _, err := f.engine.prerequisiteOperation(settled, next, d.TargetPackage); err != nil {
		t.Fatal("exact source plus settled original access could not consider the next key")
	}
	if _, err := f.engine.prerequisiteOperation(settled, first, d.TargetPackage); err != ErrSecurityBaseline {
		t.Fatal("already settled access acquired CREATE authority again")
	}
	if f.access.writes != writes || f.engine.baseline.runtimeGuard != nil {
		t.Fatal("context validation performed remote effects or enabled runtime enforcement")
	}
}

func TestBaselinePrerequisiteRetainedContextRefusesUnrelatedState(t *testing.T) {
	f, current, sourceName, retirementName := retainedPrerequisiteFixture(t)
	base := current.Document()
	op, err := f.engine.prerequisiteOperation(current, f.key, base.TargetPackage)
	if err != nil {
		t.Fatal("retained context operation unavailable")
	}
	contextRefusals := 0
	for _, scenario := range []string{"preparing", "verifying", "recovery", "upgrade", "uninstall", "installed", "missing-source-pin", "foreign-source-sha", "foreign-source-revision", "source-row-omitted", "source-uid", "source-hash", "source-phase", "source-retention", "extra-service", "extra-deployment", "owned-target", "pending-update", "pending-delete", "pending-before", "pending-hash", "pending-nonce"} {
		t.Run(scenario, func(t *testing.T) {
			d := current.Document()
			candidate := *op
			if strings.HasPrefix(scenario, "pending-") {
				d.Pending = &installstate.Pending{Action: installstate.Create, Key: f.key, AfterSHA256: op.hash, CreateNonce: strings.Repeat("c", 32)}
				candidate.nonce = d.Pending.CreateNonce
				valid := prerequisiteSnapshotFixture(t, f, d)
				if _, err := f.engine.prerequisiteContext(valid, &candidate); err != nil {
					t.Fatal("healthy pending context refused before the independent fault")
				}
				d = valid.Document()
			}
			switch scenario {
			case "preparing":
				d.Stage = installstate.Preparing
			case "verifying":
				d.Stage = installstate.Verifying
			case "recovery":
				d.Stage = installstate.RecoveryRequired
			case "upgrade":
				d.Mode = installstate.Upgrade
			case "uninstall":
				d.Mode = installstate.Uninstall
			case "installed":
				d.Installed = true
			case "missing-source-pin":
				d.AdmissionReinstall = nil
			case "foreign-source-sha":
				d.AdmissionReinstall.SourceJournalSHA256 = strings.Repeat("e", 64)
			case "foreign-source-revision":
				d.AdmissionReinstall.SourceRevision--
			case "source-row-omitted":
				d.Resources = d.Resources[1:]
			case "source-uid", "source-hash", "source-phase", "source-retention":
				for i := range d.Resources {
					if d.Resources[i].Key.Kind != "CustomResourceDefinition" {
						continue
					}
					switch scenario {
					case "source-uid":
						d.Resources[i].UID = "same-name-replacement"
					case "source-hash":
						d.Resources[i].TemplateSHA256 = strings.Repeat("e", 64)
					case "source-phase":
						d.Resources[i].Phase = "access"
					case "source-retention":
						d.Resources[i].Retained = false
					}
					break
				}
			case "extra-service", "extra-deployment", "owned-target":
				key := f.key
				if scenario != "owned-target" {
					kind := "Service"
					if scenario == "extra-deployment" {
						kind = "Deployment"
					}
					for _, resource := range f.plan.ResourceMetadata() {
						if resource.Kind == kind {
							key = installstate.Key{APIVersion: resource.APIVersion, Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
							break
						}
					}
				}
				template, err := f.engine.contracts[d.TargetPackage].Template(key, false)
				if err != nil {
					t.Fatal("signed prohibited-extra fixture unavailable")
				}
				d.Resources = append(d.Resources, installstate.Resource{Key: key, UID: "prohibited-extra", TemplateSHA256: template.Hash(), Phase: template.Phase(), Retained: template.Retained()})
			case "pending-update", "pending-delete", "pending-before", "pending-hash", "pending-nonce":
				switch scenario {
				case "pending-update":
					d.Pending.Action = installstate.Update
				case "pending-delete":
					d.Pending.Action = installstate.Delete
				case "pending-before":
					d.Pending.BeforeUID = "foreign-before"
				case "pending-hash":
					d.Pending.AfterSHA256 = strings.Repeat("e", 64)
				case "pending-nonce":
					candidate.nonce = strings.Repeat("b", 32)
				}
			}
			installstate.SortResources(d.Resources)
			if _, err := installstate.EncodeWithBaseline(d, f.engine.baselinePlan(), f.plan); err != nil {
				t.Log("invalid context refused by the genuine journal schema before prerequisite dispatch")
				return
			}
			snapshot := prerequisiteSnapshotFixture(t, f, d)
			if _, err := f.engine.prerequisiteContext(snapshot, &candidate); err != ErrSecurityBaseline {
				t.Fatal("unrelated state acquired retained-bootstrap context")
			}
			contextRefusals++
			if testBaselineReceiptDescriptors(t, sourceName) != 0 || testBaselineReceiptDescriptors(t, retirementName) != 0 {
				t.Fatal("retained context refusal leaked source evidence descriptors")
			}
		})
	}
	if contextRefusals < 10 {
		t.Fatal("schema refusals masked direct closed-context coverage")
	}
}

func TestBaselinePrerequisiteRetainedReceiptOwnsSourceBeforeAndDuringIntent(t *testing.T) {
	for _, mode := range []string{"no-pending", "prepared-empty", "acknowledged"} {
		t.Run(mode, func(t *testing.T) {
			f, current, sourceName, retirementName := retainedPrerequisiteFixture(t)
			d := current.Document()
			names := []string{sourceName, retirementName}
			if mode != "no-pending" {
				template, err := f.engine.contracts[d.TargetPackage].Template(f.key, false)
				if err != nil {
					t.Fatal("original retained access template unavailable")
				}
				d.Pending = &installstate.Pending{Action: installstate.Create, Key: f.key, AfterSHA256: template.Hash(), CreateNonce: strings.Repeat("c", 32)}
				d.Revision++
				var errCommit error
				current, errCommit = f.store.Commit(t.Context(), current, d)
				if errCommit != nil || f.engine.prepareCreateReceipt(d) != nil {
					t.Fatal("genuine retained CREATE-intent journal CAS failed")
				}
				if mode == "acknowledged" && f.engine.saveCreateUID(d, "original-retained-access") != nil {
					t.Fatal("protected original retained access ACK fixture unavailable")
				}
				names = append(names, "create-"+d.Pending.CreateNonce+".json")
			}
			op, err := f.engine.prerequisiteOperation(current, f.key, d.TargetPackage)
			if err != nil {
				t.Fatal("original retained prerequisite operation unavailable")
			}
			assertDescriptors := func(want int) {
				t.Helper()
				for _, name := range names {
					if testBaselineReceiptDescriptors(t, name) != want {
						t.Fatal("retained prerequisite descriptor count did not match its sole owner")
					}
				}
			}
			for range 8 {
				owner, err := f.engine.openPrerequisiteReceipt(current, op)
				t.Cleanup(owner.release)
				if err != nil || owner == nil || owner.source == nil || (owner.uid != "") != (mode == "acknowledged") || (owner.receipt != nil) != (mode != "no-pending") || f.engine.confirmPrerequisiteReceipt(current, op, owner) != nil {
					t.Fatal("retained source ownership failed before/during CREATE preparation")
				}
				assertDescriptors(1)
				owner.release()
				owner.release()
				if f.engine.confirmPrerequisiteReceipt(current, op, owner) != ErrSecurityBaseline {
					t.Fatal("released source witness retained prerequisite authority")
				}
				assertDescriptors(0)
			}
			for _, name := range names {
				owner, err := f.engine.openPrerequisiteReceipt(current, op)
				t.Cleanup(owner.release)
				if err != nil || owner == nil {
					t.Fatal("retained original replacement bracket unavailable")
				}
				body, identity, err := f.engine.files.Read(name, retirementMaxBytes)
				if err != nil {
					t.Fatal("original protected evidence unavailable")
				}
				for range 2 {
					identity, err = f.engine.files.AtomicWrite(name, bytes.Clone(body), &identity)
					if err != nil || f.engine.confirmPrerequisiteReceipt(current, op, owner) != ErrSecurityBaseline {
						t.Fatal("identical replacement revived original retained prerequisite evidence")
					}
					assertDescriptors(1)
				}
				owner.release()
				assertDescriptors(0)
			}
			for _, name := range names {
				body, identity, err := f.engine.files.Read(name, retirementMaxBytes)
				if err != nil {
					t.Fatal("protected refusal fixture unavailable")
				}
				identity, err = f.engine.files.AtomicWrite(name, []byte("{}"), &identity)
				if err != nil {
					t.Fatal("test-owned malformed receipt seed failed")
				}
				for range 8 {
					rejected, err := f.engine.openPrerequisiteReceipt(current, op)
					t.Cleanup(rejected.release)
					if err != ErrSecurityBaseline || rejected != nil {
						t.Fatal("malformed retained evidence supplied prerequisite authority")
					}
					assertDescriptors(0)
				}
				if _, err := f.engine.files.AtomicWrite(name, body, &identity); err != nil {
					t.Fatal("test-owned original evidence restoration failed")
				}
			}
		})
	}
}
