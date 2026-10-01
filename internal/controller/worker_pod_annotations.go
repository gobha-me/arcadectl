// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import "k8s.io/apimachinery/pkg/api/equality"

// Network plugins add these annotations after a gated worker Pod is admitted
// and scheduled. They are not part of the controller-owned execution contract.
// Other additions, including any arcade.gobha.me key, remain a mismatch.
func workerPodAnnotationsMatch(actual, template map[string]string, authorizationKey string) bool {
	annotations := cloneStringMap(actual)
	if annotations[authorizationKey] != "" {
		delete(annotations, "cni.projectcalico.org/containerID")
		delete(annotations, "cni.projectcalico.org/podIP")
		delete(annotations, "cni.projectcalico.org/podIPs")
		delete(annotations, "k8s.v1.cni.cncf.io/network-status")
	}
	delete(annotations, authorizationKey)
	return equality.Semantic.DeepEqual(annotations, template)
}
