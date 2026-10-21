// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installsafety

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestCSIDetachmentLostEmptyClaimIsNotOrdinaryColdWaiver(t *testing.T) {
	f := newColdFixture(t, false)
	// Whole WAL fixture identity/inertness is a SEPARATE phase obligation.
	// Physical proof alone neither certifies this object nor exempts Cold.
	claim := corev1.PersistentVolumeClaim{ObjectMeta: objectMeta("synthetic-lost"), Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: ptr.To("")}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimLost}}
	f.s.Claims.Items = append(f.s.Claims.Items, claim)
	before, attachments, volume := f.s.Claims.DeepCopy(), f.r.Attachments.DeepCopy(), f.volumes[0].DeepCopy()
	if ValidateCSIDetachment(f.s.Claims, f.r.Attachments, f.volumes) != nil {
		t.Fatal("empty nonbinding claim should not invent a physical source")
	}
	if f.validate() == nil {
		t.Fatal("physical component became a Lost-claim ordinary cold waiver")
	}
	if !reflect.DeepEqual(before, f.s.Claims) || !reflect.DeepEqual(attachments, f.r.Attachments) || !reflect.DeepEqual(volume, f.volumes[0]) {
		t.Fatal("physical validation mutated complete evidence")
	}
}

func TestCSIDetachmentFullSourceClosure(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*coldFixture)
		pass   bool
	}{
		{"detached", func(*coldFixture) {}, true},
		{"unrelated-named", func(f *coldFixture) {
			foreign := f.volumes[0].DeepCopy()
			foreign.Name, foreign.UID, foreign.Spec.CSI.VolumeHandle = "foreign", "foreign-uid", "foreign-handle"
			f.volumes = append(f.volumes, foreign)
			f.attachment("foreign", false)
		}, true},
		{"unrelated-inline", func(f *coldFixture) { f.attachment("foreign-handle", true) }, true},
		{"direct-attached-false", func(f *coldFixture) { f.attachment(f.volumes[0].Name, false) }, false},
		{"named-alias-attached-false", func(f *coldFixture) {
			alias := f.volumes[0].DeepCopy()
			alias.Name, alias.UID = "alias", "alias-uid"
			f.volumes = append(f.volumes, alias)
			f.attachment(alias.Name, false)
		}, false},
		{"inline-alias", func(f *coldFixture) { f.attachment(f.volumes[0].Spec.CSI.VolumeHandle, true) }, false},
		{"deleting-error-alias", func(f *coldFixture) {
			f.attachment(f.volumes[0].Spec.CSI.VolumeHandle, true)
			now := metav1.Now()
			f.r.Attachments.Items[0].DeletionTimestamp = &now
			f.r.Attachments.Items[0].Status = storagev1.VolumeAttachmentStatus{Attached: false, AttachError: &storagev1.VolumeError{Message: "private message is irrelevant"}}
		}, false},
		{"incomplete-named-closure", func(f *coldFixture) { f.attachment("foreign", false) }, false},
		{"unexpected-pv", func(f *coldFixture) {
			foreign := f.volumes[0].DeepCopy()
			foreign.Name, foreign.UID = "foreign", "foreign-uid"
			f.volumes = append(f.volumes, foreign)
		}, false},
		{"missing-world-pv", func(f *coldFixture) { f.volumes = nil }, false},
		{"duplicate-pv-uid", func(f *coldFixture) {
			foreign := f.volumes[0].DeepCopy()
			foreign.Name, foreign.Spec.CSI.VolumeHandle = "foreign", "foreign-handle"
			f.volumes = append(f.volumes, foreign)
			f.attachment("foreign", false)
		}, false},
		{"non-csi", func(f *coldFixture) {
			f.volumes[0].Spec.CSI = nil
			f.volumes[0].Spec.HostPath = &corev1.HostPathVolumeSource{Path: "/never-permitted"}
		}, false},
		{"double-source", func(f *coldFixture) {
			f.attachment("foreign", true)
			f.r.Attachments.Items[0].Spec.Source.PersistentVolumeName = ptr.To(f.volumes[0].Name)
		}, false},
		{"empty-source", func(f *coldFixture) { f.attachment("", false) }, false},
		{"invalid-inline", func(f *coldFixture) {
			f.attachment("foreign-handle", true)
			f.r.Attachments.Items[0].Spec.Source.InlineVolumeSpec.ClaimRef = &corev1.ObjectReference{Name: "hidden"}
		}, false},
		{"unlabelled-lost-bound-name-protected", func(f *coldFixture) {
			f.s.Claims.Items[0].Labels = nil
			f.s.Claims.Items[0].Status.Phase = corev1.ClaimLost
			f.attachment(f.volumes[0].Name, false)
		}, false},
		{"duplicate-claim-backing", func(f *coldFixture) {
			claim := f.s.Claims.Items[0].DeepCopy()
			claim.Name, claim.UID = "other-claim", "other-uid"
			f.s.Claims.Items = append(f.s.Claims.Items, *claim)
		}, false},
		{"nil-claims", func(f *coldFixture) { f.s.Claims = nil }, false},
		{"nil-attachments", func(f *coldFixture) { f.r.Attachments = nil }, false},
		{"paged-claims", func(f *coldFixture) { f.s.Claims.Continue = "next" }, false},
		{"paged-attachments", func(f *coldFixture) { f.r.Attachments.Continue = "next" }, false},
		{"unread-attachments", func(f *coldFixture) { f.r.Attachments.ResourceVersion = "" }, false},
		{"remaining-attachments", func(f *coldFixture) { f.r.Attachments.RemainingItemCount = ptr.To(int64(1)) }, false},
		{"unidentified-attachment", func(f *coldFixture) { f.attachment("foreign-handle", true); f.r.Attachments.Items[0].UID = "" }, false},
		{"namespaced-attachment", func(f *coldFixture) {
			f.attachment("foreign-handle", true)
			f.r.Attachments.Items[0].Namespace = f.plan.Namespace()
		}, false},
		{"duplicate-attachment", func(f *coldFixture) {
			f.attachment("foreign-handle", true)
			f.r.Attachments.Items = append(f.r.Attachments.Items, f.r.Attachments.Items[0])
		}, false},
		{"cross-namespace-claim", func(f *coldFixture) {
			claim := f.s.Claims.Items[0].DeepCopy()
			claim.Name, claim.UID, claim.Namespace, claim.Spec.VolumeName = "foreign", "foreign-claim-uid", "other", ""
			f.s.Claims.Items = append(f.s.Claims.Items, *claim)
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newColdFixture(t, false)
			test.change(f)
			if (ValidateCSIDetachment(f.s.Claims, f.r.Attachments, f.volumes) == nil) != test.pass {
				t.Fatal("complete physical-source obligation differs")
			}
		})
	}
}
