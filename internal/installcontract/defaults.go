// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

// These are independently reviewed defaults for the signed 1.35/1.37 profiles,
// not defaults inferred from admission output. Additions require corresponding
// profile/runtime evidence. Pod-only admission defaults must not be accepted on
// Deployment templates (token mounts, enableServiceLinks, sidecars, requests).
func defaults(object runtime.Object) {
	switch o := object.(type) {
	case *corev1.Namespace:
		if len(o.Spec.Finalizers) == 0 {
			o.Spec.Finalizers = []corev1.FinalizerName{corev1.FinalizerKubernetes}
		}
	case *corev1.Service:
		if o.Spec.SessionAffinity == "" {
			o.Spec.SessionAffinity = corev1.ServiceAffinityNone
		}
		if o.Spec.InternalTrafficPolicy == nil {
			o.Spec.InternalTrafficPolicy = ptr.To(corev1.ServiceInternalTrafficPolicyCluster)
		}
		if o.Spec.IPFamilyPolicy == nil {
			o.Spec.IPFamilyPolicy = ptr.To(corev1.IPFamilyPolicySingleStack)
		}
	case *crdv1.CustomResourceDefinition:
		if o.Spec.Conversion == nil {
			o.Spec.Conversion = &crdv1.CustomResourceConversion{Strategy: crdv1.NoneConverter}
		}
	case *appsv1.Deployment:
		if o.Spec.RevisionHistoryLimit == nil {
			o.Spec.RevisionHistoryLimit = ptr.To[int32](10)
		}
		if o.Spec.ProgressDeadlineSeconds == nil {
			o.Spec.ProgressDeadlineSeconds = ptr.To[int32](600)
		}
		if o.Spec.Strategy.Type == "" {
			o.Spec.Strategy.Type = appsv1.RollingUpdateDeploymentStrategyType
		}
		if o.Spec.Strategy.Type == appsv1.RollingUpdateDeploymentStrategyType {
			if o.Spec.Strategy.RollingUpdate == nil {
				o.Spec.Strategy.RollingUpdate = &appsv1.RollingUpdateDeployment{}
			}
			if o.Spec.Strategy.RollingUpdate.MaxSurge == nil {
				o.Spec.Strategy.RollingUpdate.MaxSurge = ptr.To(intstr.FromString("25%"))
			}
			if o.Spec.Strategy.RollingUpdate.MaxUnavailable == nil {
				o.Spec.Strategy.RollingUpdate.MaxUnavailable = ptr.To(intstr.FromString("25%"))
			}
		}
		p := &o.Spec.Template.Spec
		if p.RestartPolicy == "" {
			p.RestartPolicy = corev1.RestartPolicyAlways
		}
		if p.DNSPolicy == "" {
			p.DNSPolicy = corev1.DNSClusterFirst
		}
		if p.SchedulerName == "" {
			p.SchedulerName = corev1.DefaultSchedulerName
		}
		if p.TerminationGracePeriodSeconds == nil {
			p.TerminationGracePeriodSeconds = ptr.To[int64](30)
		}
		for i := range p.Containers {
			c := &p.Containers[i]
			if c.TerminationMessagePath == "" {
				c.TerminationMessagePath = corev1.TerminationMessagePathDefault
			}
			if c.TerminationMessagePolicy == "" {
				c.TerminationMessagePolicy = corev1.TerminationMessageReadFile
			}
			for j := range c.Ports {
				if c.Ports[j].Protocol == "" {
					c.Ports[j].Protocol = corev1.ProtocolTCP
				}
			}
			for j := range c.Env {
				if source := c.Env[j].ValueFrom; source != nil && source.FieldRef != nil && source.FieldRef.APIVersion == "" {
					source.FieldRef.APIVersion = "v1"
				}
			}
			for _, probe := range []*corev1.Probe{c.ReadinessProbe, c.LivenessProbe, c.StartupProbe} {
				if probe == nil {
					continue
				}
				if probe.SuccessThreshold == 0 {
					probe.SuccessThreshold = 1
				}
				if probe.FailureThreshold == 0 {
					probe.FailureThreshold = 3
				}
				if probe.HTTPGet != nil && probe.HTTPGet.Scheme == "" {
					probe.HTTPGet.Scheme = corev1.URISchemeHTTP
				}
			}
		}
	}
}
