// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion identifies the first Arcadectl API version.
var GroupVersion = schema.GroupVersion{Group: "arcade.gobha.me", Version: "v1alpha1"}

var schemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme registers Arcadectl API types with a Kubernetes scheme.
var AddToScheme = schemeBuilder.AddToScheme

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion, &GameServer{}, &GameServerList{})
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
