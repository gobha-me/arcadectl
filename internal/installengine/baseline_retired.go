// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// Retirement is a separate closed read-only proof, not current actor behavior
// or global revocation of ambient administrator grants. No account, token,
// probe, ownership receipt or executable is created. This method deliberately
// does not implement the whole runtime guard: live-phase behavior remains a
// separate requirement before production composition can install that guard.
func (c *ClusterSecurityBaseline) verifyRetiredRuntime(ctx context.Context, snapshot *installstate.Snapshot) error {
	if c == nil || c.engine == nil || c.engine.baseline == nil || c.engine.access != c.access || c.access == nil || !c.access.actorCompatible() || ctx == nil || snapshot == nil {
		return ErrSecurityBaseline
	}
	document := snapshot.Document()
	if document.Mode != installstate.Uninstall || document.AdmissionRetirementRevision == 0 || document.SecurityBaseline == nil || document.Stage != installstate.Applying && document.Stage != installstate.Verifying && !c.engine.baselineRetiredObservable(document) || document.Pending != nil && !retiringAccessDelete(document) {
		return ErrSecurityBaseline
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	engine := c.engine
	if engine.files == nil {
		return ErrSecurityBaseline
	}
	// Pin the original protected file BEFORE either core call. Individually
	// closed core checks cannot detect an identical-body inode replacement
	// between them during configuration, executable or cold observations.
	opening, err := engine.openRetirementEvidence(document)
	if err != nil {
		return ErrSecurityBaseline
	}
	defer opening.release()
	if engine.verifyRetiredAdmissionCore(ctx, snapshot) != nil {
		return ErrSecurityBaseline
	}
	configuredBefore, err := c.configured(ctx, snapshot)
	if err != nil {
		return ErrSecurityBaseline
	}
	executablesBefore, err := c.collectExecutables(ctx, snapshot)
	if err != nil || len(executablesBefore.guarded) != 0 || engine.baselineSoftwareFamiliesAbsent(executablesBefore.observation.Collections()) != nil {
		return ErrSecurityBaseline
	}
	prerequisites, err := NewClusterPrerequisites(engine, c.access)
	if err != nil {
		return ErrSecurityBaseline
	}
	cold, err := NewClusterCold(prerequisites)
	if err != nil {
		return ErrSecurityBaseline
	}
	request := LifecycleCheck{Checkpoint: ColdSafety, Snapshot: snapshot, Mode: document.Mode, Target: engine.plans[document.TargetPackage], Options: LifecycleOptions{Now: time.Now().UTC()}}
	var worldBefore [32]byte
	var stoppedBefore *stoppedWitness
	for pass := range 2 {
		collect := cold.collectEvidence
		if document.Stage == installstate.Complete {
			collect = cold.collectCompletedRetirementEvidence
		}
		_, observation, _, world, err := collect(ctx, request)
		// Every independently fresh cold observation participates. Its cold
		// world hash alone cannot conceal a late reserved, no-mount Pod.
		if err != nil || baselineReservedExecutablesAbsent(observation) != nil {
			return ErrSecurityBaseline
		}
		stoppedRequest := request
		stoppedRequest.Checkpoint = RuntimeStopped
		// Use the complete SAME observation, not Quiescence.Verify (which
		// re-enters current for pending access withdrawal). The broader
		// runtime classifier also rejects renamed/default-SA installation
		// image, Secret, label and descendant signals the baseline selector
		// intentionally does not claim to identify.
		stopped, err := engine.stopped(ctx, stoppedRequest, observation)
		if err != nil || stopped == nil || pass != 0 && (world != worldBefore || !reflect.DeepEqual(stoppedBefore, stopped)) {
			return ErrSecurityBaseline
		}
		worldBefore, stoppedBefore = world, stopped
	}
	executablesAfter, err := c.collectExecutables(ctx, snapshot)
	if err != nil || len(executablesAfter.guarded) != 0 || !sameBaselineExecutables(executablesBefore, executablesAfter) || engine.baselineSoftwareFamiliesAbsent(executablesAfter.observation.Collections()) != nil {
		return ErrSecurityBaseline
	}
	configuredAfter, err := c.configured(ctx, snapshot)
	if err != nil || !reflect.DeepEqual(configuredBefore, configuredAfter) || engine.verifyRetiredAdmissionCore(ctx, snapshot) != nil || ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	if engine.closeRetirementEvidence(opening) != nil || ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

// Every raw-executable observation participates in broader software-process
// absence too. A known image/Secret/family signal may not be ignored merely
// because an independently obtained cold collection happened to omit it.
func (e *Engine) baselineSoftwareFamiliesAbsent(objects *installobserve.ExecutableCollections) error {
	if e == nil || len(e.plans) == 0 || objects == nil || objects.Pods == nil || objects.Jobs == nil || objects.Deployments == nil || objects.ReplicaSets == nil || objects.StatefulSets == nil || objects.DaemonSets == nil || objects.ReplicationControllers == nil || objects.CronJobs == nil {
		return ErrSecurityBaseline
	}
	lists := [...]runtime.Object{objects.Pods, objects.Jobs, objects.Deployments, objects.ReplicaSets, objects.StatefulSets, objects.DaemonSets, objects.ReplicationControllers, objects.CronJobs}
	for _, list := range lists {
		items, err := meta.ExtractList(list)
		if err != nil {
			return ErrSecurityBaseline
		}
		for _, item := range items {
			var metadata metav1.ObjectMeta
			var template *corev1.PodTemplateSpec
			var spec *corev1.PodSpec
			switch object := item.(type) {
			case *corev1.Pod:
				metadata, spec = object.ObjectMeta, &object.Spec
			case *batchv1.Job:
				metadata, template = object.ObjectMeta, &object.Spec.Template
			case *appsv1.Deployment:
				metadata, template = object.ObjectMeta, &object.Spec.Template
			case *appsv1.ReplicaSet:
				metadata, template = object.ObjectMeta, &object.Spec.Template
			case *appsv1.StatefulSet:
				metadata, template = object.ObjectMeta, &object.Spec.Template
			case *appsv1.DaemonSet:
				metadata, template = object.ObjectMeta, &object.Spec.Template
			case *corev1.ReplicationController:
				metadata, template = object.ObjectMeta, object.Spec.Template
				if template == nil {
					return ErrSecurityBaseline
				}
			case *batchv1.CronJob:
				metadata, template = object.ObjectMeta, &object.Spec.JobTemplate.Spec.Template
			default:
				return ErrSecurityBaseline
			}
			if template != nil {
				spec = &template.Spec
			}
			for _, family := range []string{apiFamily, "arcadectl-controller", "arcadectl-destroy-controller"} {
				if e.familySignal(family, metadata, spec) || template != nil && e.familySignal(family, template.ObjectMeta, spec) {
					return ErrSecurityBaseline
				}
			}
		}
	}
	return nil
}

// These are strictly decoded complete native lists from the sealed cold
// observer. Set only the fixed catalog TypeMeta on disposable typed copies;
// no dynamic ownership graph, adoption or namespace-wide zero-workload rule.
func baselineReservedExecutablesAbsent(observation *installobserve.Observation) error {
	if observation == nil || observation.Snapshot() == nil || observation.Runtime() == nil {
		return ErrSecurityBaseline
	}
	s, r := observation.Snapshot(), observation.Runtime()
	return baselineReservedCollectionsAbsent(&installobserve.ExecutableCollections{Pods: s.Pods, Jobs: s.Jobs, Deployments: r.Deployments, ReplicaSets: r.ReplicaSets, StatefulSets: r.StatefulSets, DaemonSets: r.DaemonSets, ReplicationControllers: r.ReplicationControllers, CronJobs: r.CronJobs})
}

func baselineReservedCollectionsAbsent(objects *installobserve.ExecutableCollections) error {
	if objects == nil || objects.Pods == nil || objects.Jobs == nil || objects.Deployments == nil || objects.ReplicaSets == nil || objects.StatefulSets == nil || objects.DaemonSets == nil || objects.ReplicationControllers == nil || objects.CronJobs == nil {
		return ErrSecurityBaseline
	}
	lists := [...]runtime.Object{objects.Pods, objects.Jobs, objects.Deployments, objects.ReplicaSets, objects.StatefulSets, objects.DaemonSets, objects.ReplicationControllers, objects.CronJobs}
	for index, list := range lists {
		items, err := meta.ExtractList(list)
		if err != nil {
			return ErrSecurityBaseline
		}
		collection := baselineExecutableCollections[index]
		for _, item := range items {
			fields, err := runtime.DefaultUnstructuredConverter.ToUnstructured(item)
			if err != nil {
				return ErrSecurityBaseline
			}
			object := &unstructured.Unstructured{Object: fields}
			object.SetAPIVersion(collection.gv)
			object.SetKind(collection.kind)
			key := installstate.Key{APIVersion: collection.gv, Kind: collection.kind, Namespace: object.GetNamespace(), Name: object.GetName()}
			guarded, err := baselineGuardedExecutable(key, object)
			if err != nil || guarded {
				return ErrSecurityBaseline
			}
		}
	}
	return nil
}
