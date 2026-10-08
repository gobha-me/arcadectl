// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	fixtureBackupJob = iota
	fixtureBackupPod
	fixtureRestoreJob
	fixtureRestorePod
	fixtureDestroyJob
	fixtureDestroyPod
	fixturePlainPod
	fixtureRetainedPVC
	fixturePlainPVC
	fixtureCancelledDestroy
	fixtureVerifiedCancelledDestroy
)

// Pure, closed construction from the protected original recipe. This does not
// authorize CREATE, validate an acknowledgement or adopt a matching live name.
// Only the future ledger-bound transport may send these objects, after proving
// the original namespace/access/policies, exact absence and whole dry-run shape.
// In particular, no ordinary installer effect is exempted from the WAL fence.
func (f *fixtureLedger) object(slot int) (*unstructured.Unstructured, error) {
	if f == nil || f.engine == nil || f.lock == nil || slot < 0 || slot >= len(fixtureCatalogFor(f.document)) {
		return nil, ErrFixtures
	}
	d, err := f.decodeCurrentWAL(f.body)
	if err != nil || !reflect.DeepEqual(d, f.document) {
		return nil, ErrFixtures
	}
	journal, err := f.decodeCurrentJournal(d.Journal)
	if err != nil {
		return nil, ErrFixtures
	}
	plan := f.engine.plans[journal.TargetPackage]
	if !plan.IsTrusted() || plan.Namespace() != journal.Namespace {
		return nil, ErrFixtures
	}
	entry, recipe := d.Entries[slot], fixtureCatalogFor(d)[slot]
	meta := map[string]any{"name": entry.Key.Name, "namespace": entry.Key.Namespace}
	o := &unstructured.Unstructured{Object: map[string]any{"apiVersion": recipe.version, "kind": recipe.kind, "metadata": meta}}
	switch slot {
	case fixtureBackupJob, fixtureRestoreJob, fixtureDestroyJob, fixtureBackupPod, fixtureRestorePod, fixtureDestroyPod, fixturePlainPod:
		worker, account := "backup", ordinaryControllerActor.account()
		if slot == fixtureRestoreJob || slot == fixtureRestorePod {
			worker = "restore"
		}
		if slot == fixtureDestroyJob || slot == fixtureDestroyPod {
			worker, account = "destroy", destroyControllerActor.account()
		}
		policy := ""
		stem := "arcadectl-" + worker + "-worker-gate"
		for _, resource := range plan.ResourceMetadata() {
			if resource.Kind == "ValidatingAdmissionPolicy" && (resource.Name == stem || strings.HasPrefix(resource.Name, stem+"-")) {
				if policy != "" {
					return nil, ErrFixtures
				}
				policy = resource.Name
			}
		}
		pod, _, _, err := admissionCreateProbe(plan, policy, account, "arcadectl-probe-"+d.RunID)
		if err != nil {
			return nil, ErrFixtures
		}
		labels := pod.Object["metadata"].(map[string]any)["labels"]
		spec := pod.Object["spec"]
		if recipe.kind == "Job" {
			// Both suspend and zero parallelism independently prevent Job
			// execution. Manual selector avoids server-generated UID selector
			// adoption; the manually created child retains its scheduling gate.
			selector := map[string]any{"arcade.gobha.me/admission-fixture": entry.Key.Name}
			labels.(map[string]any)["arcade.gobha.me/admission-fixture"] = entry.Key.Name
			meta["labels"] = map[string]any{"arcade.gobha.me/admission-fixture": entry.Key.Name}
			o.Object["spec"] = map[string]any{
				"suspend": true, "parallelism": int64(0), "completions": int64(1), "backoffLimit": int64(0),
				"manualSelector": true, "selector": map[string]any{"matchLabels": selector},
				"completionMode": "NonIndexed", "podReplacementPolicy": "TerminatingOrFailed",
				"template": map[string]any{"metadata": map[string]any{"labels": labels}, "spec": spec},
			}
		} else {
			o.Object["spec"] = spec
			if slot == fixturePlainPod {
				// A separate plain Pod exercises policy classification. It is
				// still scheduling-gated, tokenless and has no storage or target.
				_ = unstructured.SetNestedSlice(o.Object, []any{map[string]any{"name": "arcade.gobha.me/admission-fixture"}}, "spec", "schedulingGates")
			} else {
				owner := d.Entries[recipe.owner]
				if owner.State != fixtureOriginal || owner.OriginalUID == "" {
					return nil, ErrFixtures // never fabricate/adopt a Job UID
				}
				meta["labels"] = labels
				// Non-controlling reference plus selector mismatch keeps the
				// Job controller from adopting/releasing/deleting the manual
				// probe. It is still an exact original UID GC dependency.
				meta["ownerReferences"] = []any{map[string]any{"apiVersion": "batch/v1", "kind": "Job", "name": owner.Key.Name, "uid": string(owner.OriginalUID), "controller": false, "blockOwnerDeletion": true}}
			}
		}
	case fixtureRetainedPVC, fixturePlainPVC:
		// Certified only on the declared pinned native PV controllers. Empty
		// class or a random selector alone would not prevent static/prebinding.
		// This synthetic annotation MUST NEVER be applied to a real/adopted PVC.
		meta["annotations"] = map[string]any{"pv.kubernetes.io/bind-completed": "yes"}
		o.Object["spec"] = map[string]any{"accessModes": []any{"ReadWriteOnce"}, "resources": map[string]any{"requests": map[string]any{"storage": "1Mi"}}, "storageClassName": "", "volumeMode": "Filesystem"}
		if slot == fixtureRetainedPVC {
			meta["labels"] = map[string]any{"app.kubernetes.io/managed-by": "arcadectl", "app.kubernetes.io/instance": entry.Key.Name, "arcade.gobha.me/data-identity": "synthetic-proof", "arcade.gobha.me/data-policy": "retain", "arcade.gobha.me/data-path": "data"}
		}
	case fixtureCancelledDestroy:
		// Already cancelled BEFORE CREATE, never confirmed and never referring
		// to a retained fixture/world. The UID strings are deliberately invalid
		// as native UUIDs and contain this run's nonce, not any observed identity.
		// This constructor alone does NOT establish changed-spec UPDATE proof.
		name := "arcadectl-probe-" + d.RunID
		meta["annotations"] = map[string]any{"arcade.gobha.me/unsafe-requested-by": "system:serviceaccount:" + journal.Namespace + ":" + destroyAdministratorActor.account()}
		o.Object["spec"] = map[string]any{
			"target": map[string]any{"gameServer": map[string]any{"name": name, "uid": "synthetic-server-" + d.RunID}, "game": "admission-probe", "data": map[string]any{"identity": "synthetic-" + d.RunID, "claims": []any{map[string]any{"path": "data", "claimRef": map[string]any{"name": name, "uid": "synthetic-claim-" + d.RunID}}}}},
			"mode":   "UnsafeNoBackup", "unsafeReason": "isolated cancelled admission fixture", "cancelRequested": true,
		}
	case fixtureVerifiedCancelledDestroy:
		// Separate fictional identities, cancelled before CREATE and never
		// confirmed. These are not the unsafe original's world references and
		// cannot target native UUIDs or any acknowledged fixture/storage UID.
		name := "arcadectl-verified-probe-" + d.RunID
		o.Object["spec"] = map[string]any{
			"target": map[string]any{"gameServer": map[string]any{"name": name, "uid": "synthetic-verified-server-" + d.RunID}, "game": "admission-probe", "data": map[string]any{"identity": "synthetic-verified-" + d.RunID, "claims": []any{map[string]any{"path": "data", "claimRef": map[string]any{"name": name, "uid": "synthetic-verified-claim-" + d.RunID}}}}},
			"mode":   "VerifiedBackup", "cancelRequested": true,
			"backupRef":           map[string]any{"name": name, "uid": "synthetic-verified-backup-" + d.RunID},
			"repositorySecretRef": map[string]any{"name": name, "uid": "synthetic-verified-repository-" + d.RunID, "resourceVersion": "1"},
		}
	default:
		return nil, ErrFixtures
	}
	return o, nil
}
