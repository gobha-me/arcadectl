// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"fmt"
	"strings"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// The case number is private and has exactly one meaning. No external caller
// can select a case, actor, object, denial, endpoint or completion bit.
type fixtureAdmissionCase uint8

const fixtureAdmissionCaseCount fixtureAdmissionCase = 55
const fixtureAdmissionAllCases uint64 = (1 << fixtureAdmissionCaseCount) - 1

type fixtureAdmissionRequest struct {
	object    *unstructured.Unstructured
	operation admissionProbeOperation
	actor     admissionActor
	slot      int // -1 means a constructor-derived nonpersistent counterpart
	policy    string
	index     int
}

var fixtureAdmissionPolicyStems = [...]string{
	"arcadectl-backup-worker-gate", "arcadectl-destroy-worker-gate",
	"arcadectl-destroy-unsafe-admin", "arcadectl-restore-candidate-pvc-create",
	"arcadectl-restore-worker-gate", "arcadectl-retained-world-pvc-delete",
}

func (w *fixtureWire) admissionPolicy(stem string) (string, error) {
	if w == nil || w.actors == nil || w.actors.policies == nil {
		return "", ErrFixtures
	}
	name := ""
	for candidate := range w.actors.policies.policies {
		if candidate == stem || strings.HasPrefix(candidate, stem+"-") {
			if name != "" {
				return "", ErrFixtures
			}
			name = candidate
		}
	}
	if name == "" {
		return "", ErrFixtures
	}
	return name, nil
}

func fixtureObjectKey(o *unstructured.Unstructured) installstate.Key {
	return installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
}

// Constructors derive CREATE bodies from the signed package, not from a live
// original's generated metadata. Named candidates start from an independently
// whole-validated original and change ONLY their fixed case's declared fields.
func (w *fixtureWire) admissionRequest(number fixtureAdmissionCase, phase *fixturePhaseObservation) (fixtureAdmissionRequest, error) {
	r := fixtureAdmissionRequest{slot: -1, operation: probeCreateOperation}
	if w == nil || w.ledger == nil || w.actors == nil || phase == nil || number >= fixtureAdmissionCaseCount || w.ledger.document.Recipe != fixtureRecipeV2 {
		return r, ErrFixtures
	}
	f := w.ledger
	if number < 12 || number == 38 || number == 49 || number == 50 {
		family := int(number / 2)
		if number == 38 {
			family, r.actor = 3, ordinaryControllerActor
		} else if number == 49 || number == 50 {
			family, r.actor = 2, destroyAdministratorActor
		}
		policy, err := w.admissionPolicy(fixtureAdmissionPolicyStems[family])
		if err != nil {
			return r, err
		}
		positive, negative, index, err := admissionCreateProbe(w.actors.request.Target, policy, ordinaryControllerActor.account(), "arcadectl-probe-"+f.document.RunID)
		if err != nil {
			return r, ErrFixtures
		}
		r.object = positive
		if number < 12 && number%2 != 0 {
			r.object, r.policy, r.index = negative, policy, index
		}
		if number == 38 {
			r.object = negative
		}
		if number == 49 || number == 50 {
			r.object = negative
			if number == 50 {
				r.object.SetAnnotations(map[string]string{"arcade.gobha.me/unsafe-requested-by": "foreign-admin"})
				r.policy, r.index = policy, 1
			}
		}
		// Preserve the restore-candidate policy's name prefix, but give EVERY
		// counterpart its own fixed run/case address. No address is adopted.
		r.object.SetName(r.object.GetName() + fmt.Sprintf("-case-%02d", number))
		return r, nil
	}
	r.operation = probeUpdateOperation
	if number < 36 {
		worker := int((number - 12) / 8)
		r.slot = [...]int{fixtureBackupPod, fixtureRestorePod, fixtureDestroyPod}[worker]
		r.object = phase.objects[r.slot]
		if r.object == nil {
			return r, ErrFixtures
		}
		r.object = r.object.DeepCopy()
		family := [...]string{"backup", "restore", "destroy"}[worker]
		policy, err := w.admissionPolicy("arcadectl-" + family + "-worker-gate")
		if err != nil {
			return r, err
		}
		gate := "arcade.gobha.me/" + family + "-pod-authorized"
		switch (number - 12) % 8 {
		case 0: // exact no-op
		case 1:
			containers, found, err := unstructured.NestedSlice(r.object.Object, "spec", "containers")
			if err != nil || !found || len(containers) != 1 {
				return r, ErrFixtures
			}
			container, ok := containers[0].(map[string]any)
			if !ok {
				return r, ErrFixtures
			}
			container["image"] = "registry.example/foreign:test"
			if unstructured.SetNestedSlice(r.object.Object, containers, "spec", "containers") != nil {
				return r, ErrFixtures
			}
			r.policy, r.index = policy, 2
		case 2:
			unstructured.RemoveNestedField(r.object.Object, "spec", "schedulingGates")
			r.policy, r.index = policy, 3
		case 3:
			fixtureSetAnnotation(r.object, gate, "foreign-uid")
			r.policy, r.index = policy, 3
		case 4, 5:
			unstructured.RemoveNestedField(r.object.Object, "spec", "schedulingGates")
			fixtureSetAnnotation(r.object, gate, string(r.object.GetUID()))
			r.actor = ordinaryControllerActor
			if worker == 2 {
				r.actor = destroyControllerActor
			}
			if (number-12)%8 == 5 {
				if r.actor == ordinaryControllerActor {
					r.actor = destroyControllerActor
				} else {
					r.actor = ordinaryControllerActor
				}
				r.policy, r.index = policy, 3
			}
		case 6:
			r.operation, r.policy = probeEphemeralOperation, policy
		case 7:
			r.operation, r.policy = probeResizeOperation, policy
		}
		return r, nil
	}
	switch number {
	case 36, 37:
		r.slot, r.operation = fixturePlainPod, probeEphemeralOperation
		if number == 37 {
			r.operation = probeResizeOperation
		}
	case 39, 40, 41, 42, 43, 44, 45, 46:
		r.slot = fixtureRetainedPVC
	case 47:
		r.slot, r.operation = fixturePlainPVC, probeDeletePVCOperation
	case 48:
		r.slot = fixtureVerifiedCancelledDestroy
	case 51, 52, 53, 54:
		r.slot, r.actor = fixtureCancelledDestroy, destroyControllerActor
	default:
		return r, ErrFixtures
	}
	if phase.objects[r.slot] == nil {
		return r, ErrFixtures
	}
	r.object = phase.objects[r.slot].DeepCopy()
	if number >= 39 && number <= 46 {
		policy, err := w.admissionPolicy("arcadectl-retained-world-pvc-delete")
		if err != nil {
			return r, err
		}
		switch number {
		case 40:
			labels := r.object.GetLabels()
			delete(labels, "arcade.gobha.me/data-policy")
			r.object.SetLabels(labels)
			r.policy, r.index = policy, 3
		case 41, 42:
			fixtureSetAnnotation(r.object, "arcade.gobha.me/cold-backup-uid", f.document.RunID)
			if number == 41 {
				r.policy, r.index = policy, 1
			} else {
				r.actor = ordinaryControllerActor
			}
		case 43, 44:
			r.operation = probeDeletePVCOperation
			if number == 43 {
				r.policy, r.index = policy, 2
			} else {
				r.actor = destroyControllerActor
			}
		case 45, 46:
			annotations := r.object.GetAnnotations()
			delete(annotations, "arcade.gobha.me/cold-backup-uid")
			r.object.SetAnnotations(annotations)
			if number == 45 {
				r.policy, r.index = policy, 1
			} else {
				r.actor = ordinaryControllerActor
			}
		}
	}
	if number >= 52 {
		policy, err := w.admissionPolicy("arcadectl-destroy-unsafe-admin")
		if err != nil {
			return r, err
		}
		switch number {
		case 52, 53:
			if unstructured.SetNestedField(r.object.Object, f.document.RunID, "spec", "confirmationChallenge") != nil {
				return r, ErrFixtures
			}
			if number == 52 {
				r.policy = policy
			} else {
				r.actor = destroyAdministratorActor
			}
		case 54:
			r.actor = destroyAdministratorActor
			fixtureSetAnnotation(r.object, "arcade.gobha.me/unsafe-requested-by", "foreign-admin")
			r.policy, r.index = policy, 1
		}
	}
	return r, nil
}

func fixtureSetAnnotation(o *unstructured.Unstructured, name, value string) {
	annotations := o.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[name] = value
	o.SetAnnotations(annotations)
}
