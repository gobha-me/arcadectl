// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package kube translates validated game-server intent into deterministic
// Kubernetes resources. It does not read from or mutate a cluster.
package kube

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

const (
	LabelManagedBy              = "app.kubernetes.io/managed-by"
	LabelName                   = "app.kubernetes.io/name"
	LabelInstance               = "app.kubernetes.io/instance"
	LabelGame                   = "arcade.gobha.me/game"
	LabelDataPolicy             = "arcade.gobha.me/data-policy"
	LabelDataPath               = "arcade.gobha.me/data-path"
	AnnotationConfigurationHash = "arcade.gobha.me/configuration-sha256"
	ManagerName                 = "arcadectl"
	maxSettingsLen              = 64 * 1024
	configurationVolumeName     = "arcadectl-configuration"
	configurationSourcePath     = "/arcadectl/configuration"
	privateReadinessPath        = "/arcadectl/readiness"
	configurationMaterializer   = "busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"
)

//go:embed materialize.sh
var materializeConfigurationScript string

// Plan is the complete resource intent for one GameServer generation.
// DataClaims always remain present. Configuration, Workload, and PlayerService
// are nil while stopped, so stop removes runtime state without touching data.
type Plan struct {
	DataClaims    []*corev1.PersistentVolumeClaim
	Configuration *corev1.ConfigMap
	Workload      *appsv1.Deployment
	PlayerService *corev1.Service
}

// ValidationCategory identifies the bounded part of desired state that made a
// plan invalid. The underlying error remains internal so status can be
// actionable without reflecting user values or adapter diagnostics.
type ValidationCategory string

const (
	ValidationIdentity     ValidationCategory = "identity"
	ValidationGame         ValidationCategory = "game"
	ValidationImage        ValidationCategory = "image"
	ValidationDesiredState ValidationCategory = "desiredState"
	ValidationCompute      ValidationCategory = "compute"
	ValidationStorage      ValidationCategory = "storage"
	ValidationSettings     ValidationCategory = "settings"
)

// ValidationError wraps a detailed planner error with a safe public category.
type ValidationError struct {
	Category ValidationCategory
	cause    error
}

func (err *ValidationError) Error() string { return err.cause.Error() }
func (err *ValidationError) Unwrap() error { return err.cause }

func invalid(category ValidationCategory, err error) error {
	return &ValidationError{Category: category, cause: err}
}

// Build validates server intent against a curated adapter and creates a plan.
func Build(server *arcadev1alpha1.GameServer, definition game.Definition) (Plan, error) {
	if err := validateIntent(server, definition); err != nil {
		return Plan{}, err
	}

	labels := workloadLabels(server)
	claims := make([]*corev1.PersistentVolumeClaim, 0, len(definition.PersistentPaths))
	for _, persistentPath := range definition.PersistentPaths {
		claimName, err := dataClaimName(server.Name, definition.ID, persistentPath.Name)
		if err != nil {
			return Plan{}, err
		}
		claims = append(claims, buildDataClaim(server, definition, persistentPath.Name, claimName))
	}
	files, err := definition.RenderSettingsFiles(server.Spec.Settings.Raw)
	if err != nil {
		return Plan{}, invalid(ValidationSettings, fmt.Errorf("render configuration: %w", err))
	}
	plan := Plan{DataClaims: claims}
	if server.Spec.DesiredState == arcadev1alpha1.DesiredStateStopped {
		return plan, nil
	}
	configuration := buildConfiguration(server, labels, files)
	plan.Configuration = configuration

	image, err := game.ResolvedImage(definition.ImageRepository, server.Spec.ImageDigest)
	if err != nil {
		return Plan{}, invalid(ValidationImage, fmt.Errorf("resolve image: %w", err))
	}
	plan.Workload = buildWorkload(server, definition, labels, image, files, configuration.Name)
	plan.PlayerService = buildPlayerService(server, definition, labels)
	return plan, nil
}

func validateIntent(server *arcadev1alpha1.GameServer, definition game.Definition) error {
	if server == nil {
		return invalid(ValidationIdentity, errors.New("game server is required"))
	}
	if problems := validation.IsDNS1123Label(server.Name); len(problems) > 0 {
		return invalid(ValidationIdentity, fmt.Errorf("invalid game server name: %s", strings.Join(problems, "; ")))
	}
	if problems := validation.IsDNS1123Label(server.Namespace); len(problems) > 0 {
		return invalid(ValidationIdentity, fmt.Errorf("invalid game server namespace: %s", strings.Join(problems, "; ")))
	}
	if server.UID == "" && server.Spec.DesiredState == arcadev1alpha1.DesiredStateRunning {
		return invalid(ValidationIdentity, errors.New("running game server requires a Kubernetes UID"))
	}
	if err := definition.Validate(); err != nil {
		return invalid(ValidationGame, fmt.Errorf("invalid game definition: %w", err))
	}
	if server.Spec.Game != definition.ID {
		return invalid(ValidationGame, fmt.Errorf("game %q does not match adapter %q", server.Spec.Game, definition.ID))
	}
	if _, err := game.ResolvedImage(definition.ImageRepository, server.Spec.ImageDigest); err != nil {
		return invalid(ValidationImage, fmt.Errorf("invalid image: %w", err))
	}
	switch server.Spec.DesiredState {
	case arcadev1alpha1.DesiredStateRunning, arcadev1alpha1.DesiredStateStopped:
	default:
		return invalid(ValidationDesiredState, fmt.Errorf("unsupported desired state %q", server.Spec.DesiredState))
	}
	if err := validateCompute(server.Spec.Compute); err != nil {
		return invalid(ValidationCompute, err)
	}
	if server.Spec.Storage.Size.Sign() <= 0 {
		return invalid(ValidationStorage, errors.New("storage size must be positive"))
	}
	if className := server.Spec.Storage.StorageClassName; className != nil && *className != "" {
		if problems := validation.IsDNS1123Subdomain(*className); len(problems) > 0 {
			return invalid(ValidationStorage, fmt.Errorf("invalid storage class name: %s", strings.Join(problems, "; ")))
		}
	}
	if err := validateSettings(definition.SettingsSchema, server.Spec.Settings.Raw); err != nil {
		return invalid(ValidationSettings, err)
	}
	for _, persistentPath := range definition.PersistentPaths {
		if persistentPath.Name == configurationVolumeName {
			return invalid(ValidationGame, fmt.Errorf("persistent path name %q is reserved by the platform", persistentPath.Name))
		}
		if _, err := dataClaimName(server.Name, definition.ID, persistentPath.Name); err != nil {
			return invalid(ValidationIdentity, err)
		}
	}
	return nil
}

func validateCompute(compute arcadev1alpha1.ComputeSpec) error {
	quantities := []struct {
		name  string
		value *resource.Quantity
	}{
		{"CPU request", &compute.CPURequest},
		{"CPU limit", &compute.CPULimit},
		{"memory request", &compute.MemoryRequest},
		{"memory limit", &compute.MemoryLimit},
	}
	for _, quantity := range quantities {
		if quantity.value.Sign() <= 0 {
			return fmt.Errorf("%s must be positive", quantity.name)
		}
	}
	if compute.CPURequest.Cmp(compute.CPULimit) > 0 {
		return errors.New("CPU request cannot exceed CPU limit")
	}
	if compute.MemoryRequest.Cmp(compute.MemoryLimit) > 0 {
		return errors.New("memory request cannot exceed memory limit")
	}
	return nil
}

func validateSettings(schemaBytes, settings []byte) error {
	if len(settings) == 0 {
		return errors.New("settings are required")
	}
	if len(settings) > maxSettingsLen {
		return errors.New("settings exceed the 64 KiB limit")
	}
	schemaDocument, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		return fmt.Errorf("decode settings schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("arcadectl://adapter/settings.json", schemaDocument); err != nil {
		return fmt.Errorf("load settings schema: %w", err)
	}
	schema, err := compiler.Compile("arcadectl://adapter/settings.json")
	if err != nil {
		return fmt.Errorf("compile settings schema: %w", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(settings))
	if err != nil {
		return fmt.Errorf("settings must be valid JSON: %w", err)
	}
	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("settings do not satisfy adapter schema: %w", err)
	}
	return nil
}

func workloadLabels(server *arcadev1alpha1.GameServer) map[string]string {
	return map[string]string{
		LabelManagedBy: ManagerName,
		LabelName:      "game-server",
		LabelInstance:  server.Name,
		LabelGame:      server.Spec.Game,
	}
}

func dataClaimName(serverName, gameID, pathName string) (string, error) {
	name := serverName + "-" + gameID + "-" + pathName
	if problems := validation.IsDNS1123Subdomain(name); len(problems) > 0 {
		return "", fmt.Errorf("data claim name %q is invalid: %s", name, strings.Join(problems, "; "))
	}
	return name, nil
}

func buildDataClaim(server *arcadev1alpha1.GameServer, definition game.Definition, pathName, name string) *corev1.PersistentVolumeClaim {
	labels := map[string]string{
		LabelManagedBy:  ManagerName,
		LabelName:       "game-data",
		LabelInstance:   server.Name,
		LabelGame:       definition.ID,
		LabelDataPolicy: "retain",
		LabelDataPath:   pathName,
	}
	var storageClassName *string
	if server.Spec.Storage.StorageClassName != nil {
		storageClassName = ptr.To(*server.Spec.Storage.StorageClassName)
	}
	return &corev1.PersistentVolumeClaim{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: server.Namespace,
			Labels:    cloneMap(labels),
			// Intentionally no owner reference: deleting a GameServer must not
			// make its world data eligible for Kubernetes garbage collection.
			OwnerReferences: nil,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: storageClassName,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: server.Spec.Storage.Size.DeepCopy()},
			},
		},
	}
}

func controllerReference(server *arcadev1alpha1.GameServer) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: arcadev1alpha1.GroupVersion.String(),
		Kind:       "GameServer",
		Name:       server.Name,
		UID:        server.UID,
		Controller: ptr.To(true),
	}
}

func buildConfiguration(server *arcadev1alpha1.GameServer, labels map[string]string, files []game.ConfigurationFile) *corev1.ConfigMap {
	configurationLabels := cloneMap(labels)
	configurationLabels[LabelName] = "game-configuration"
	data := make(map[string][]byte, len(files))
	for _, file := range files {
		data[file.Name] = append([]byte(nil), file.Contents...)
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            server.Name + "-configuration",
			Namespace:       server.Namespace,
			Labels:          configurationLabels,
			OwnerReferences: []metav1.OwnerReference{controllerReference(server)},
		},
		BinaryData: data,
	}
}

func buildWorkload(server *arcadev1alpha1.GameServer, definition game.Definition, labels map[string]string, image string, files []game.ConfigurationFile, configurationName string) *appsv1.Deployment {
	containerPorts := make([]corev1.ContainerPort, 0, len(definition.Endpoints))
	for _, endpoint := range definition.Endpoints {
		if endpoint.Scope != game.ScopePlayer {
			continue
		}
		containerPorts = append(containerPorts, corev1.ContainerPort{
			Name:          endpoint.Name,
			ContainerPort: int32(endpoint.ContainerPort),
			Protocol:      corev1.Protocol(endpoint.Protocol),
		})
	}

	volumeMounts := make([]corev1.VolumeMount, 0, len(definition.PersistentPaths))
	materializerMounts := make([]corev1.VolumeMount, 0, len(definition.PersistentPaths)+1)
	volumes := make([]corev1.Volume, 0, len(definition.PersistentPaths)+1)
	for _, persistentPath := range definition.PersistentPaths {
		claimName, _ := dataClaimName(server.Name, definition.ID, persistentPath.Name)
		mount := corev1.VolumeMount{Name: persistentPath.Name, MountPath: persistentPath.MountPath}
		volumeMounts = append(volumeMounts, mount)
		materializerMounts = append(materializerMounts, mount)
		volumes = append(volumes, corev1.Volume{
			Name: persistentPath.Name,
			VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: claimName,
			}},
		})
	}
	materializerMounts = append(materializerMounts, corev1.VolumeMount{
		Name:      configurationVolumeName,
		MountPath: configurationSourcePath,
		ReadOnly:  true,
	})
	volumes = append(volumes, corev1.Volume{
		Name: configurationVolumeName,
		VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: configurationName},
		}},
	})

	container := corev1.Container{
		Name:            "game",
		Image:           image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Ports:           containerPorts,
		VolumeMounts:    volumeMounts,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    server.Spec.Compute.CPURequest.DeepCopy(),
				corev1.ResourceMemory: server.Spec.Compute.MemoryRequest.DeepCopy(),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    server.Spec.Compute.CPULimit.DeepCopy(),
				corev1.ResourceMemory: server.Spec.Compute.MemoryLimit.DeepCopy(),
			},
		},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: ptr.To(false),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
	}
	materializerArgs := []string{materializeConfigurationScript, "arcadectl-configuration-materializer"}
	for _, file := range files {
		materializerArgs = append(materializerArgs, persistentRootForTarget(definition.PersistentPaths, file.MountPath), configurationSourcePath+"/"+file.Name, file.MountPath)
	}
	materializer := corev1.Container{
		Name:            "configuration-materializer",
		Image:           configurationMaterializer,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"/bin/sh", "-ec"},
		Args:            materializerArgs,
		VolumeMounts:    materializerMounts,
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: ptr.To(false),
			ReadOnlyRootFilesystem:   ptr.To(true),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
	}
	if definition.ReadinessEndpoint != "" {
		switch definition.ReadinessMode {
		case game.ReadinessTCP:
			container.ReadinessProbe = &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{
					Port: intstr.FromString(definition.ReadinessEndpoint),
				}},
			}
		case game.ReadinessPrivateExec:
			container.ReadinessProbe = &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{privateReadinessPath}}},
			}
		}
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            server.Name,
			Namespace:       server.Namespace,
			Labels:          cloneMap(labels),
			OwnerReferences: []metav1.OwnerReference{controllerReference(server)},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
			Selector: &metav1.LabelSelector{MatchLabels: cloneMap(labels)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: cloneMap(labels),
					Annotations: map[string]string{
						AnnotationConfigurationHash: configurationHash(files),
					},
				},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: ptr.To(false),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:        ptr.To(true),
						RunAsUser:           ptr.To(definition.RuntimeIdentity.UserID),
						RunAsGroup:          ptr.To(definition.RuntimeIdentity.GroupID),
						FSGroup:             ptr.To(definition.RuntimeIdentity.FSGroup),
						FSGroupChangePolicy: ptr.To(corev1.FSGroupChangeOnRootMismatch),
						SeccompProfile:      &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					InitContainers: []corev1.Container{materializer},
					Containers:     []corev1.Container{container},
					Volumes:        volumes,
				},
			},
		},
	}
}

func persistentRootForTarget(paths []game.PersistentPath, target string) string {
	for _, persistentPath := range paths {
		if strings.HasPrefix(target, persistentPath.MountPath+"/") {
			return persistentPath.MountPath
		}
	}
	return ""
}

func configurationHash(files []game.ConfigurationFile) string {
	hash := sha256.New()
	for _, file := range files {
		_, _ = fmt.Fprintf(hash, "%d:%s:%d:%s:%d:", len(file.Name), file.Name, len(file.MountPath), file.MountPath, len(file.Contents))
		_, _ = hash.Write(file.Contents)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func buildPlayerService(server *arcadev1alpha1.GameServer, definition game.Definition, labels map[string]string) *corev1.Service {
	ports := make([]corev1.ServicePort, 0, len(definition.Endpoints))
	for _, endpoint := range definition.Endpoints {
		if endpoint.Scope != game.ScopePlayer {
			continue
		}
		ports = append(ports, corev1.ServicePort{
			Name:       endpoint.Name,
			Protocol:   corev1.Protocol(endpoint.Protocol),
			Port:       int32(endpoint.ContainerPort),
			TargetPort: intstr.FromString(endpoint.Name),
		})
	}

	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            server.Name,
			Namespace:       server.Namespace,
			Labels:          cloneMap(labels),
			OwnerReferences: []metav1.OwnerReference{controllerReference(server)},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeLoadBalancer,
			Selector: cloneMap(labels),
			Ports:    ports,
		},
	}
}

func cloneMap(source map[string]string) map[string]string {
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
