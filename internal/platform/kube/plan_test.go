// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/games/factorio"
	"github.com/gobha-me/arcadectl/internal/games/synthetic"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestBuildRunningFactorioPlan(t *testing.T) {
	t.Parallel()

	server := testServer("factory", "factorio", arcadev1alpha1.DesiredStateRunning)
	plan, err := Build(server, factorio.Definition())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(plan.DataClaims) != 1 {
		t.Fatalf("data claims = %d, want 1", len(plan.DataClaims))
	}
	claim := plan.DataClaims[0].Desired
	if claim.Name != "factory-factorio-world" {
		t.Errorf("claim name = %q, want factory-factorio-world", claim.Name)
	}
	if len(claim.OwnerReferences) != 0 {
		t.Fatalf("retained data claim has owner references: %#v", claim.OwnerReferences)
	}
	if claim.Labels[LabelDataPolicy] != "retain" {
		t.Errorf("data policy label = %q, want retain", claim.Labels[LabelDataPolicy])
	}
	if claim.Labels[LabelDataPath] != "world" {
		t.Errorf("data path label = %q, want world", claim.Labels[LabelDataPath])
	}
	wantIdentity, err := DataIdentity(server.UID)
	if err != nil {
		t.Fatalf("DataIdentity() error = %v", err)
	}
	if got := claim.Labels[LabelDataIdentity]; got != wantIdentity || plan.DataIdentity != wantIdentity {
		t.Errorf("data identity = claim %q plan %q, want %q", got, plan.DataIdentity, wantIdentity)
	}
	if plan.Workload == nil || plan.PlayerService == nil {
		t.Fatalf("running plan = %#v, want workload and service", plan)
	}
	if plan.Configuration == nil || plan.Configuration.Name != "factory-configuration" {
		t.Fatalf("configuration = %#v, want owned factory-configuration ConfigMap", plan.Configuration)
	}
	assertControlledByServer(t, plan.Configuration.OwnerReferences, server)
	if got := string(plan.Configuration.BinaryData["server-settings"]); !strings.Contains(got, `"public": false`) || !strings.Contains(got, `"lan": false`) {
		t.Errorf("rendered Factorio settings = %q, want private visibility", got)
	}
	if plan.Workload.Spec.Strategy.Type != "Recreate" {
		t.Errorf("deployment strategy = %q, want Recreate", plan.Workload.Spec.Strategy.Type)
	}
	if got := *plan.Workload.Spec.Replicas; got != 1 {
		t.Errorf("replicas = %d, want 1", got)
	}
	container := plan.Workload.Spec.Template.Spec.Containers[0]
	if container.Image != "ghcr.io/gobha-me/arcadectl-factorio@"+testDigest {
		t.Errorf("image = %q, want a digest-pinned Factorio image", container.Image)
	}
	if container.ReadinessProbe == nil || container.ReadinessProbe.Exec == nil ||
		!reflect.DeepEqual(container.ReadinessProbe.Exec.Command, []string{privateReadinessPath}) ||
		container.ReadinessProbe.TCPSocket != nil {
		t.Errorf("Factorio readiness probe = %#v, want fixed private exec helper", container.ReadinessProbe)
	}
	encodedPod, err := json.Marshal(plan.Workload.Spec.Template.Spec)
	if err != nil {
		t.Fatalf("marshal Factorio Pod spec: %v", err)
	}
	if strings.Contains(string(encodedPod), "rcon") || strings.Contains(string(encodedPod), "27015") {
		t.Fatalf("Factorio Pod spec exposes private readiness endpoint: %s", encodedPod)
	}
	if len(container.Ports) != 1 || container.Ports[0].Name != "game" {
		t.Fatalf("Factorio container ports = %#v, want player endpoints only", container.Ports)
	}
	if plan.Workload.Spec.Template.Spec.AutomountServiceAccountToken == nil || *plan.Workload.Spec.Template.Spec.AutomountServiceAccountToken {
		t.Error("game pod must not mount a Kubernetes service-account token")
	}
	if got := plan.Workload.Spec.Template.Annotations[AnnotationConfigurationHash]; len(got) != 64 {
		t.Errorf("configuration hash = %q, want sha256 hex", got)
	}
	if len(container.VolumeMounts) != 1 || container.VolumeMounts[0].MountPath != "/factorio" {
		t.Errorf("game volume mounts = %#v, want only persistent data", container.VolumeMounts)
	}
	if len(plan.Workload.Spec.Template.Spec.InitContainers) != 1 {
		t.Fatalf("init containers = %#v, want one configuration materializer", plan.Workload.Spec.Template.Spec.InitContainers)
	}
	materializer := plan.Workload.Spec.Template.Spec.InitContainers[0]
	if materializer.Image != configurationMaterializer || len(materializer.Command) != 2 || materializer.Command[0] != "/bin/sh" {
		t.Errorf("configuration materializer = %#v, want pinned constrained helper", materializer)
	}
	if len(materializer.Args) != 5 || materializer.Args[2] != "/factorio" || materializer.Args[3] != "/arcadectl/configuration/server-settings" || materializer.Args[4] != "/factorio/config/server-settings.json" {
		t.Errorf("configuration materializer args = %#v", materializer.Args)
	}
	if len(materializer.VolumeMounts) != 2 || materializer.VolumeMounts[0].MountPath != "/factorio" || materializer.VolumeMounts[1].MountPath != configurationSourcePath || !materializer.VolumeMounts[1].ReadOnly {
		t.Errorf("configuration materializer mounts = %#v", materializer.VolumeMounts)
	}
	if materializer.SecurityContext == nil || materializer.SecurityContext.ReadOnlyRootFilesystem == nil || !*materializer.SecurityContext.ReadOnlyRootFilesystem || materializer.SecurityContext.AllowPrivilegeEscalation == nil || *materializer.SecurityContext.AllowPrivilegeEscalation {
		t.Errorf("configuration materializer security context = %#v", materializer.SecurityContext)
	}
	securityContext := plan.Workload.Spec.Template.Spec.SecurityContext
	if securityContext == nil || securityContext.RunAsUser == nil || *securityContext.RunAsUser != 845 || securityContext.RunAsGroup == nil || *securityContext.RunAsGroup != 845 || securityContext.FSGroup == nil || *securityContext.FSGroup != 845 || securityContext.RunAsNonRoot == nil || !*securityContext.RunAsNonRoot {
		t.Errorf("pod security context = %#v, want certified non-root Factorio identity", securityContext)
	}
	assertControlledByServer(t, plan.Workload.OwnerReferences, server)
	assertControlledByServer(t, plan.PlayerService.OwnerReferences, server)

	ports := plan.PlayerService.Spec.Ports
	if len(ports) != 1 || ports[0].Name != "game" || ports[0].Protocol != corev1.ProtocolUDP {
		t.Errorf("public ports = %#v, want only the UDP player endpoint", ports)
	}
	for _, port := range ports {
		if port.Name == "rcon" {
			t.Fatal("administrator endpoint must not be published by the player service")
		}
	}
	plan.Workload.Labels[LabelInstance] = "changed"
	if plan.PlayerService.Labels[LabelInstance] != "factory" || plan.Workload.Spec.Selector.MatchLabels[LabelInstance] != "factory" {
		t.Fatal("planned resource label maps alias one another")
	}
}

func TestBuildCopiesStorageClass(t *testing.T) {
	t.Parallel()

	server := testServer("factory", "factorio", arcadev1alpha1.DesiredStateStopped)
	className := "fast-storage"
	server.Spec.Storage.StorageClassName = &className
	plan, err := Build(server, factorio.Definition())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	*server.Spec.Storage.StorageClassName = "changed"
	if got := *plan.DataClaims[0].Desired.Spec.StorageClassName; got != "fast-storage" {
		t.Fatalf("planned storage class changed through input alias: %q", got)
	}
}

func TestBuildStoppedPlanRetainsOnlyData(t *testing.T) {
	t.Parallel()

	server := testServer("factory", "factorio", arcadev1alpha1.DesiredStateStopped)
	plan, err := Build(server, factorio.Definition())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(plan.DataClaims) != 1 || len(plan.DataClaims[0].Desired.OwnerReferences) != 0 {
		t.Fatalf("stopped data claims = %#v, want one independently retained claim", plan.DataClaims)
	}
	if plan.Configuration != nil || plan.Workload != nil || plan.PlayerService != nil {
		t.Fatalf("stopped plan has active resources: %#v", plan)
	}
}

func TestBuildExactRetainedDataPlan(t *testing.T) {
	t.Parallel()

	server := testServer("factory", "factorio", arcadev1alpha1.DesiredStateRunning)
	server.Spec.Storage.Reattach = &arcadev1alpha1.RetainedDataReference{
		Identity: "data-retained-factory",
		Claims: []arcadev1alpha1.RetainedDataClaimReference{{
			Path: "world",
			ClaimRef: arcadev1alpha1.ExactLocalReference{
				Name: "factory-factorio-world-retained",
				UID:  "pvc-uid-retained",
			},
		}},
	}
	plan, err := Build(server, factorio.Definition())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !plan.Reattach || plan.DataIdentity != "data-retained-factory" || len(plan.DataClaims) != 1 {
		t.Fatalf("retained plan = %#v", plan)
	}
	claim := plan.DataClaims[0]
	if claim.Desired.Name != "factory-factorio-world-retained" || claim.RequiredUID != "pvc-uid-retained" {
		t.Fatalf("retained claim plan = %#v", claim)
	}
	if got := claim.Desired.Labels[LabelDataIdentity]; got != plan.DataIdentity {
		t.Fatalf("retained claim identity = %q, want %q", got, plan.DataIdentity)
	}
	volumes := plan.Workload.Spec.Template.Spec.Volumes
	if len(volumes) != 2 || volumes[0].PersistentVolumeClaim == nil || volumes[0].PersistentVolumeClaim.ClaimName != claim.Desired.Name {
		t.Fatalf("workload volumes = %#v, want exact retained claim name", volumes)
	}
}

func TestDataIdentity(t *testing.T) {
	t.Parallel()

	first, err := DataIdentity("server-one")
	if err != nil {
		t.Fatalf("DataIdentity() error = %v", err)
	}
	again, err := DataIdentity("server-one")
	if err != nil || again != first {
		t.Fatalf("DataIdentity() repeat = %q, %v; want %q", again, err, first)
	}
	second, err := DataIdentity("server-two")
	if err != nil || second == first {
		t.Fatalf("DataIdentity() second = %q, %v; want distinct identity", second, err)
	}
	if len(first) != 53 || !strings.HasPrefix(first, "data-") {
		t.Fatalf("DataIdentity() = %q, want 53-character label-safe identity", first)
	}
	if _, err := DataIdentity(""); err == nil {
		t.Fatal("DataIdentity() accepted empty UID")
	}
}

func TestBuildRejectsInvalidRetainedDataSelection(t *testing.T) {
	t.Parallel()

	localNamespace := "games"
	tests := []struct {
		name   string
		claims []arcadev1alpha1.RetainedDataClaimReference
		mutate func(*arcadev1alpha1.RetainedDataReference)
		want   string
	}{
		{name: "missing identity", claims: exactClaims(), mutate: func(ref *arcadev1alpha1.RetainedDataReference) { ref.Identity = "" }, want: "identity is required"},
		{name: "incomplete", claims: exactClaims()[:1], want: "cover every persistent path"},
		{name: "unknown path", claims: exactClaims(), mutate: func(ref *arcadev1alpha1.RetainedDataReference) { ref.Claims[1].Path = "unknown" }, want: "not declared"},
		{name: "duplicate path", claims: exactClaims(), mutate: func(ref *arcadev1alpha1.RetainedDataReference) { ref.Claims[1].Path = "state" }, want: "duplicated"},
		{name: "cross namespace", claims: exactClaims(), mutate: func(ref *arcadev1alpha1.RetainedDataReference) { ref.Claims[0].ClaimRef.Namespace = &localNamespace }, want: "exact local"},
		{name: "empty UID", claims: exactClaims(), mutate: func(ref *arcadev1alpha1.RetainedDataReference) { ref.Claims[0].ClaimRef.UID = "" }, want: "exact local"},
		{name: "duplicate name", claims: exactClaims(), mutate: func(ref *arcadev1alpha1.RetainedDataReference) {
			ref.Claims[1].ClaimRef.Name = ref.Claims[0].ClaimRef.Name
		}, want: "reuse one claim name"},
		{name: "duplicate UID", claims: exactClaims(), mutate: func(ref *arcadev1alpha1.RetainedDataReference) {
			ref.Claims[1].ClaimRef.UID = ref.Claims[0].ClaimRef.UID
		}, want: "reuse one claim UID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := testServer("echo", "conformance-echo", arcadev1alpha1.DesiredStateStopped)
			server.Spec.Settings = structJSON(`{}`)
			server.Spec.Storage.Reattach = &arcadev1alpha1.RetainedDataReference{Identity: "data-retained", Claims: test.claims}
			if test.mutate != nil {
				test.mutate(server.Spec.Storage.Reattach)
			}
			_, err := Build(server, twoPathSyntheticDefinition())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Build() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func exactClaims() []arcadev1alpha1.RetainedDataClaimReference {
	return []arcadev1alpha1.RetainedDataClaimReference{
		{Path: "state", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "echo-state", UID: "state-uid"}},
		{Path: "logs", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "echo-logs", UID: "logs-uid"}},
	}
}

func twoPathSyntheticDefinition() game.Definition {
	definition := synthetic.Definition()
	definition.PersistentPaths = append(definition.PersistentPaths, game.PersistentPath{Name: "logs", MountPath: "/srv/logs"})
	return definition
}

func TestBuildIsGameNeutral(t *testing.T) {
	t.Parallel()

	server := testServer("echo", "conformance-echo", arcadev1alpha1.DesiredStateRunning)
	server.Spec.Settings = structJSON(`{}`)
	plan, err := Build(server, synthetic.Definition())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if got := plan.DataClaims[0].Desired.Name; got != "echo-conformance-echo-state" {
		t.Errorf("claim name = %q, want echo-conformance-echo-state", got)
	}
	container := plan.Workload.Spec.Template.Spec.Containers[0]
	if len(container.VolumeMounts) != 1 || container.VolumeMounts[0].MountPath != "/srv/world" {
		t.Errorf("game volume mounts = %#v, want synthetic persistent path", container.VolumeMounts)
	}
	if container.ReadinessProbe == nil || container.ReadinessProbe.TCPSocket == nil ||
		container.ReadinessProbe.TCPSocket.Port.String() != "players" || container.ReadinessProbe.Exec != nil {
		t.Errorf("synthetic readiness probe = %#v, want named player TCP probe", container.ReadinessProbe)
	}
	materializer := plan.Workload.Spec.Template.Spec.InitContainers[0]
	if len(materializer.Args) != 11 || materializer.Args[2] != "/srv/world" || materializer.Args[3] != "/arcadectl/configuration/echo-config" || materializer.Args[4] != "/srv/world/config/echo.conf" || materializer.Args[5] != "/srv/world" || materializer.Args[6] != "/arcadectl/configuration/motd" || materializer.Args[7] != "/srv/world/config/motd.txt" || materializer.Args[8] != "/srv/world" || materializer.Args[9] != "/arcadectl/configuration/seed" || materializer.Args[10] != "/srv/world/config/seed.txt" {
		t.Errorf("configuration materializer args = %#v, want synthetic adapter paths", materializer.Args)
	}
	if len(plan.PlayerService.Spec.Ports) != 1 || plan.PlayerService.Spec.Ports[0].Protocol != corev1.ProtocolTCP {
		t.Errorf("service ports = %#v, want synthetic TCP endpoint", plan.PlayerService.Spec.Ports)
	}
}

func TestBuildConfigurationHashUsesRenderedMeaning(t *testing.T) {
	t.Parallel()

	first := testServer("factory", "factorio", arcadev1alpha1.DesiredStateRunning)
	first.Spec.Settings = structJSON(`{"name":"same","maxPlayers":16,"visibility":"private"}`)
	second := first.DeepCopy()
	second.Spec.Settings = structJSON("{\n  \"visibility\": \"private\",\n  \"maxPlayers\": 16,\n  \"name\": \"same\"\n}")
	firstPlan, err := Build(first, factorio.Definition())
	if err != nil {
		t.Fatalf("first Build() error = %v", err)
	}
	secondPlan, err := Build(second, factorio.Definition())
	if err != nil {
		t.Fatalf("second Build() error = %v", err)
	}
	firstHash := firstPlan.Workload.Spec.Template.Annotations[AnnotationConfigurationHash]
	secondHash := secondPlan.Workload.Spec.Template.Annotations[AnnotationConfigurationHash]
	if firstHash == "" || firstHash != secondHash {
		t.Fatalf("equivalent settings hashes differ: %q != %q", firstHash, secondHash)
	}
}

func TestBuildRejectsInvalidIntent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*arcadev1alpha1.GameServer)
		want     string
		category ValidationCategory
	}{
		{"game mismatch", func(server *arcadev1alpha1.GameServer) { server.Spec.Game = "other" }, "does not match", ValidationGame},
		{"mutable image", func(server *arcadev1alpha1.GameServer) { server.Spec.ImageDigest = "latest" }, "image digest", ValidationImage},
		{"unknown state", func(server *arcadev1alpha1.GameServer) { server.Spec.DesiredState = "Paused" }, "unsupported desired state", ValidationDesiredState},
		{"zero CPU", func(server *arcadev1alpha1.GameServer) { server.Spec.Compute.CPURequest = resource.Quantity{} }, "CPU request must be positive", ValidationCompute},
		{"CPU request over limit", func(server *arcadev1alpha1.GameServer) { server.Spec.Compute.CPURequest = resource.MustParse("3") }, "CPU request cannot exceed", ValidationCompute},
		{"memory request over limit", func(server *arcadev1alpha1.GameServer) { server.Spec.Compute.MemoryRequest = resource.MustParse("3Gi") }, "memory request cannot exceed", ValidationCompute},
		{"zero storage", func(server *arcadev1alpha1.GameServer) { server.Spec.Storage.Size = resource.Quantity{} }, "storage size must be positive", ValidationStorage},
		{"invalid storage class", func(server *arcadev1alpha1.GameServer) {
			className := "Not Valid"
			server.Spec.Storage.StorageClassName = &className
		}, "invalid storage class name", ValidationStorage},
		{"invalid settings", func(server *arcadev1alpha1.GameServer) { server.Spec.Settings.Raw = []byte(`{"maxPlayers":0}`) }, "do not satisfy adapter schema", ValidationSettings},
		{"public visibility", func(server *arcadev1alpha1.GameServer) {
			server.Spec.Settings.Raw = []byte(`{"name":"test","visibility":"public"}`)
		}, "do not satisfy adapter schema", ValidationSettings},
		{"credential setting", func(server *arcadev1alpha1.GameServer) {
			server.Spec.Settings.Raw = []byte(`{"name":"test","visibility":"private","token":"secret"}`)
		}, "do not satisfy adapter schema", ValidationSettings},
		{"oversized settings", func(server *arcadev1alpha1.GameServer) {
			server.Spec.Settings.Raw = []byte(strings.Repeat(" ", maxSettingsLen+1))
		}, "64 KiB", ValidationSettings},
		{"missing UID while running", func(server *arcadev1alpha1.GameServer) { server.UID = "" }, "requires a Kubernetes UID", ValidationIdentity},
		{"invalid namespace", func(server *arcadev1alpha1.GameServer) { server.Namespace = "Not Valid" }, "invalid game server namespace", ValidationIdentity},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := testServer("factory", "factorio", arcadev1alpha1.DesiredStateRunning)
			test.mutate(server)
			_, err := Build(server, factorio.Definition())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Build() error = %v, want substring %q", err, test.want)
			}
			validationErr := &ValidationError{}
			if !errors.As(err, &validationErr) || validationErr.Category != test.category {
				t.Fatalf("Build() validation error = %#v, want category %q", validationErr, test.category)
			}
		})
	}
}

func TestBuildRejectsReservedPersistentVolumeName(t *testing.T) {
	t.Parallel()

	server := testServer("factory", "factorio", arcadev1alpha1.DesiredStateRunning)
	definition := factorio.Definition()
	definition.PersistentPaths[0].Name = configurationVolumeName
	_, err := Build(server, definition)
	if err == nil || !strings.Contains(err.Error(), "reserved by the platform") {
		t.Fatalf("Build() error = %v, want reserved volume-name refusal", err)
	}
}

func testServer(name, gameID string, desiredState arcadev1alpha1.DesiredState) *arcadev1alpha1.GameServer {
	return &arcadev1alpha1.GameServer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "games", UID: types.UID("test-uid")},
		Spec: arcadev1alpha1.GameServerSpec{
			Game:         gameID,
			ImageDigest:  testDigest,
			DesiredState: desiredState,
			Compute: arcadev1alpha1.ComputeSpec{
				CPURequest:    resource.MustParse("500m"),
				CPULimit:      resource.MustParse("2"),
				MemoryRequest: resource.MustParse("1Gi"),
				MemoryLimit:   resource.MustParse("2Gi"),
			},
			Storage:  arcadev1alpha1.StorageSpec{Size: resource.MustParse("10Gi")},
			Settings: structJSON(`{"name":"test","maxPlayers":16,"visibility":"private"}`),
		},
	}
}

func structJSON(raw string) runtime.RawExtension {
	return runtime.RawExtension{Raw: []byte(raw)}
}

func assertControlledByServer(t *testing.T, references []metav1.OwnerReference, server *arcadev1alpha1.GameServer) {
	t.Helper()
	if len(references) != 1 {
		t.Fatalf("owner references = %#v, want exactly one", references)
	}
	reference := references[0]
	if reference.Name != server.Name || reference.UID != server.UID || reference.Controller == nil || !*reference.Controller {
		t.Errorf("owner reference = %#v, want controlling GameServer reference", reference)
	}
	if reference.BlockOwnerDeletion != nil && *reference.BlockOwnerDeletion {
		t.Errorf("owner reference = %#v, must not require finalizer update permission", reference)
	}
}
