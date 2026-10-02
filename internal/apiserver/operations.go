// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/operations"
	platformgame "github.com/gobha-me/arcadectl/internal/platform/game"
	platformimage "github.com/gobha-me/arcadectl/internal/platform/image"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const maxOperationBody = operations.MaxJSONBytes

// ReceiptStore deliberately exposes no native-resource write, status, Secret,
// Pod or PVC capability. Its only write is an immutable admission receipt.
type ReceiptStore interface {
	client.Reader
	CreateReceipt(context.Context, *arcadev1.ArcadeOperation) error
}

type kubernetesReceiptStore struct {
	client.Reader
	creator client.Writer
}

func NewKubernetesReceiptStore(reader client.Reader, creator client.Writer) ReceiptStore {
	return &kubernetesReceiptStore{Reader: reader, creator: creator}
}
func (store *kubernetesReceiptStore) CreateReceipt(ctx context.Context, receipt *arcadev1.ArcadeOperation) error {
	return store.creator.Create(ctx, receipt)
}

type OperationsConfig struct {
	Store    ReceiptStore
	Catalog  *catalog.Catalog
	Resolver platformimage.VersionResolver
}
type operationAPI struct {
	server   *Server
	store    ReceiptStore
	catalog  *catalog.Catalog
	resolver platformimage.VersionResolver
}

// RegisterOperations must run before serving. Every route comes from the same
// typed table used by OpenAPI and passes the existing guarded registration.
func (server *Server) RegisterOperations(config OperationsConfig) error {
	if config.Store == nil || config.Catalog == nil || config.Resolver == nil {
		return errors.New("invalid operation API configuration")
	}
	api := &operationAPI{server: server, store: config.Store, catalog: config.Catalog, resolver: config.Resolver}
	for _, route := range adminv1.Routes() {
		if route.Action == string(ActionAuthSelf) {
			continue
		} // already guarded by New
		if route.RequestSchema == "" {
			if err := server.HandleAuthenticatedRead(route.Method, route.Path, Action(route.Action), http.HandlerFunc(api.read)); err != nil {
				return err
			}
		} else {
			route := route
			if err := server.HandleMutation(route.Method, route.Path, Action(route.Action), func(w http.ResponseWriter, r *http.Request, c AuthorizedMutation) { api.mutate(w, r, c, route) }); err != nil {
				return err
			}
		}
	}
	return nil
}

var operationName = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
var exactUID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var snapshotDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var challengeSyntax = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func singleHeader(header http.Header, name string) (string, bool) {
	var values []string
	for key, candidates := range header {
		if strings.EqualFold(key, name) {
			values = append(values, candidates...)
		}
	}
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && len(returnValue) > 0
}
func headerPresent(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}
func serverETag(server *arcadev1.GameServer) string {
	return fmt.Sprintf(`"server:%s:%d"`, server.UID, server.Generation)
}
func operationETag(receipt *arcadev1.ArcadeOperation) string {
	return fmt.Sprintf(`"operation:%s:%d"`, receipt.UID, receipt.Generation)
}
func retainedETag(receipt *arcadev1.ArcadeOperation) string {
	return fmt.Sprintf(`"retained:%s:%s"`, receipt.UID, receipt.Status.RetainedWorld.SnapshotDigest)
}

func parseETag(value, kind string) (string, string, bool) {
	parsed, err := operations.ParsePrecondition(value)
	if err != nil || parsed.Kind != kind {
		return "", "", false
	}
	return parsed.UID, parsed.SnapshotDigest, true
}

func decodeOperationBody(w http.ResponseWriter, r *http.Request, target any) bool {
	value, ok := singleHeader(r.Header, "Content-Type")
	media, _, err := mime.ParseMediaType(value)
	if !ok || err != nil || media != "application/json" {
		operationError(w, http.StatusUnsupportedMediaType, "invalid_content_type", "")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxOperationBody))
	if err != nil {
		operationError(w, http.StatusRequestEntityTooLarge, "invalid_body", "")
		return false
	}
	canonical, err := operations.CanonicalJSON(raw)
	if err != nil || len(canonical) == 0 || canonical[0] != '{' {
		operationError(w, http.StatusBadRequest, "invalid_body", "")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		operationError(w, http.StatusBadRequest, "invalid_body", "")
		return false
	}
	return true
}
func exactReference(ref adminv1.ExactReference) arcadev1.ExactLocalReference {
	return arcadev1.ExactLocalReference{Name: ref.Name, UID: ref.UID}
}
func retainedSelector(selector *adminv1.RetainedSelector) *arcadev1.OperationRetainedWorldSelector {
	if selector == nil {
		return nil
	}
	return &arcadev1.OperationRetainedWorldSelector{DecommissionOperationRef: exactReference(selector.DecommissionOperationRef), SnapshotDigest: selector.SnapshotDigest}
}
func computeInput(input adminv1.Compute) (arcadev1.ComputeSpec, error) {
	var result arcadev1.ComputeSpec
	for _, field := range []struct {
		input  string
		output *resource.Quantity
	}{{input.CPURequest, &result.CPURequest}, {input.CPULimit, &result.CPULimit}, {input.MemoryRequest, &result.MemoryRequest}, {input.MemoryLimit, &result.MemoryLimit}} {
		if len(field.input) > 64 {
			return result, errors.New("invalid compute")
		}
		quantity, err := resource.ParseQuantity(field.input)
		if err != nil {
			return result, errors.New("invalid compute")
		}
		*field.output = quantity
	}
	return result, nil
}
func storageInput(input adminv1.Storage) (arcadev1.StorageSpec, error) {
	if len(input.Size) > 64 {
		return arcadev1.StorageSpec{}, errors.New("invalid storage")
	}
	size, err := resource.ParseQuantity(input.Size)
	if err != nil {
		return arcadev1.StorageSpec{}, errors.New("invalid storage")
	}
	return arcadev1.StorageSpec{Size: size, StorageClassName: input.StorageClassName}, nil
}

func (api *operationAPI) originalRequest(w http.ResponseWriter, r *http.Request, route adminv1.Route) (arcadev1.OperationRequest, bool) {
	request := arcadev1.OperationRequest{ServerName: r.PathValue("name")}
	var version string
	var err error
	switch route.RequestSchema {
	case "CreateRequest":
		var input adminv1.CreateRequest
		if !decodeOperationBody(w, r, &input) {
			return request, false
		}
		version = input.Version
		request.ServerName = input.Name
		compute, computeErr := computeInput(input.Compute)
		storage, storageErr := storageInput(input.Storage)
		settings, settingsErr := operations.CanonicalJSON(input.Settings)
		if computeErr != nil || storageErr != nil || settingsErr != nil || len(settings) == 0 || settings[0] != '{' {
			err = errors.New("invalid request")
		}
		request.Create = &arcadev1.OperationCreateInput{Game: input.Game, DesiredState: arcadev1.DesiredState(input.DesiredState), Compute: compute, Storage: storage, SettingsJSON: string(settings), RetainedWorld: retainedSelector(input.RetainedWorld)}
		request.Image = &arcadev1.OperationImageInput{Digest: input.Image.Digest, Version: input.Image.Version}
	case "ConfigureRequest":
		var input adminv1.ConfigureRequest
		if !decodeOperationBody(w, r, &input) {
			return request, false
		}
		version = input.Version
		request.Configure = &arcadev1.OperationConfigureInput{}
		if input.Compute != nil {
			value, e := computeInput(*input.Compute)
			if e != nil {
				err = e
			}
			request.Configure.Compute = &value
		}
		if input.Storage != nil {
			value, e := storageInput(*input.Storage)
			if e != nil {
				err = e
			}
			request.Configure.Storage = &value
		}
		if input.Settings != nil {
			value, e := operations.CanonicalJSON(input.Settings)
			if e != nil || len(value) == 0 || value[0] != '{' {
				err = errors.New("invalid settings")
			}
			text := string(value)
			request.Configure.SettingsJSON = &text
		}
	case "UpdateRequest":
		var input adminv1.UpdateRequest
		if !decodeOperationBody(w, r, &input) {
			return request, false
		}
		version = input.Version
		request.Image = &arcadev1.OperationImageInput{Digest: input.Image.Digest, Version: input.Image.Version}
	case "BackupRequest":
		var input adminv1.BackupRequest
		if !decodeOperationBody(w, r, &input) {
			return request, false
		}
		version = input.Version
		request.Backup = &arcadev1.OperationBackupInput{RepositorySecretName: input.RepositorySecretName, RestartPolicy: arcadev1.RestartPolicy(input.RestartPolicy)}
	case "RestoreRequest":
		var input adminv1.RestoreRequest
		if !decodeOperationBody(w, r, &input) {
			return request, false
		}
		version = input.Version
		request.Restore = &arcadev1.OperationRestoreInput{BackupRef: exactReference(input.BackupRef), RestartPolicy: arcadev1.RestartPolicy(input.RestartPolicy)}
	case "DestroyRequest":
		var input adminv1.DestroyRequest
		if !decodeOperationBody(w, r, &input) {
			return request, false
		}
		version = input.Version
		request.Destroy = &arcadev1.OperationDestroyInput{BackupRef: exactReference(input.BackupRef)}
	case "ConfirmRequest":
		var input adminv1.ConfirmRequest
		if !decodeOperationBody(w, r, &input) {
			return request, false
		}
		version = input.Version
		request.DestroyCommand = &arcadev1.OperationDestroyCommand{ParentOperationRef: arcadev1.ExactLocalReference{Name: r.PathValue("operationID")}, DestroyRef: exactReference(input.DestroyRef), Challenge: input.Challenge}
	case "CancelRequest":
		var input adminv1.CancelRequest
		if !decodeOperationBody(w, r, &input) {
			return request, false
		}
		version = input.Version
		request.DestroyCommand = &arcadev1.OperationDestroyCommand{ParentOperationRef: arcadev1.ExactLocalReference{Name: r.PathValue("operationID")}, DestroyRef: exactReference(input.DestroyRef)}
	case "EmptyRequest":
		var input adminv1.EmptyRequest
		if !decodeOperationBody(w, r, &input) {
			return request, false
		}
		version = input.Version
	default:
		err = errors.New("invalid request")
	}
	if version != adminv1.Version || err != nil {
		operationError(w, http.StatusBadRequest, "invalid_request", "")
		return request, false
	}
	if route.Action == string(ActionServerCreate) {
		value, ok := singleHeader(r.Header, "If-None-Match")
		if !ok || value != "*" || headerPresent(r.Header, "If-Match") {
			operationError(w, http.StatusPreconditionRequired, "precondition_required", "")
			return request, false
		}
		request.Precondition = "absent"
	} else {
		if headerPresent(r.Header, "If-None-Match") {
			operationError(w, http.StatusBadRequest, "invalid_precondition", "")
			return request, false
		}
		value, ok := singleHeader(r.Header, "If-Match")
		if !ok {
			operationError(w, http.StatusPreconditionRequired, "precondition_required", "")
			return request, false
		}
		kind := "server"
		if strings.Contains(route.Path, "retained-worlds") {
			kind = "retained"
		}
		if strings.Contains(route.Path, "destroy-operations") {
			kind = "operation"
		}
		uid, tail, valid := parseETag(value, kind)
		if !valid {
			operationError(w, http.StatusBadRequest, "invalid_precondition", "")
			return request, false
		}
		request.Precondition = value
		if kind == "retained" {
			request.Destroy.RetainedWorld = &arcadev1.OperationRetainedWorldSelector{DecommissionOperationRef: arcadev1.ExactLocalReference{Name: r.PathValue("operationID"), UID: uid}, SnapshotDigest: tail}
		}
	}
	return request, true
}

func (api *operationAPI) mutate(w http.ResponseWriter, r *http.Request, capability AuthorizedMutation, route adminv1.Route) {
	// This guarded request was authenticated and audited while its credential
	// was valid. Resolution may outlive that expiry; record the admission start,
	// not a later timestamp which would misrepresent the durable authorization.
	admittedAt := r.Context().Value(requestStateKey{}).(*requestState).started.UTC()
	if r.URL.RawQuery != "" {
		operationError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	key, ok := singleHeader(r.Header, "Idempotency-Key")
	name, err := operations.ReceiptName(api.server.namespace, capability.Principal().ID, key)
	if !ok || err != nil {
		operationError(w, http.StatusBadRequest, "invalid_idempotency_key", "")
		return
	}
	request, ok := api.originalRequest(w, r, route)
	if !ok {
		return
	}
	action := arcadev1.ArcadeOperationAction(route.Action)
	digest, err := operations.RequestDigest(action, request)
	if err != nil {
		operationError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	keyDigest, err := operations.KeyDigest(api.server.namespace, capability.Principal().ID, key)
	if err != nil {
		operationError(w, http.StatusBadRequest, "invalid_idempotency_key", "")
		return
	}
	// The winner lookup precedes current server/precondition checks and registry
	// resolution. A retry is bound to original canonical intent, not live state.
	if winner, err := api.lookup(r.Context(), name); err == nil {
		api.returnWinner(w, winner, digest, keyDigest, capability.Principal().ID)
		return
	} else if !apierrors.IsNotFound(err) {
		operationError(w, http.StatusServiceUnavailable, "api_unavailable", "")
		return
	}
	if err := api.bind(r.Context(), action, &request); err != nil {
		// Another request can win while this loser validates live state or a tag.
		// Its controller may already have advanced the generation; do not turn
		// that admitted winner into a fictional stale-precondition rejection.
		if winner, lookupErr := api.lookup(r.Context(), name); lookupErr == nil {
			api.returnWinner(w, winner, digest, keyDigest, capability.Principal().ID)
			return
		}
		var problem *operationProblem
		if errors.As(err, &problem) {
			operationError(w, problem.status, problem.code, "")
		} else {
			operationError(w, http.StatusServiceUnavailable, "api_unavailable", "")
		}
		return
	}
	if operations.ValidateRequest(action, request) != nil {
		operationError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	principal := capability.Principal()
	receipt := &arcadev1.ArcadeOperation{TypeMeta: metav1.TypeMeta{APIVersion: arcadev1.GroupVersion.String(), Kind: "ArcadeOperation"}, ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: api.server.namespace}, Spec: arcadev1.ArcadeOperationSpec{Version: "v1", Action: action, KeyDigest: keyDigest, RequestDigest: digest, Request: request, Admission: arcadev1.OperationAdmission{PrincipalID: principal.ID, CredentialID: principal.CredentialID, RequestID: capability.RequestID(), AdmittedAt: metav1.NewTime(admittedAt), CredentialExpiresAt: metav1.NewTime(principal.ExpiresAt.UTC())}}}
	err = api.server.ExecuteMutation(capability, func(ctx context.Context) error { return api.store.CreateReceipt(ctx, receipt) })
	if err == nil {
		api.accept(w, receipt, http.StatusAccepted)
		return
	}
	if errors.Is(err, ErrForbidden) {
		operationError(w, http.StatusForbidden, "forbidden", "")
		return
	}
	// Any create failure can be an ambiguous committed request. Recover by exact
	// deterministic name and immutable digest; never mint a new operation/key.
	winner, recoveryErr := api.lookup(r.Context(), name)
	if recoveryErr == nil {
		api.returnWinner(w, winner, digest, keyDigest, principal.ID)
		return
	}
	operationError(w, http.StatusServiceUnavailable, "commit_unknown", name)
}

func (api *operationAPI) lookup(ctx context.Context, name string) (*arcadev1.ArcadeOperation, error) {
	value := &arcadev1.ArcadeOperation{}
	err := api.store.Get(ctx, types.NamespacedName{Namespace: api.server.namespace, Name: name}, value)
	return value, err
}
func (api *operationAPI) returnWinner(w http.ResponseWriter, winner *arcadev1.ArcadeOperation, digest, keyDigest, principal string) {
	if winner.Spec.Version != "v1" || winner.Spec.RequestDigest != digest || winner.Spec.KeyDigest != keyDigest || winner.Spec.Admission.PrincipalID != principal || winner.Namespace != api.server.namespace {
		operationError(w, http.StatusConflict, "idempotency_conflict", "")
		return
	}
	api.accept(w, winner, http.StatusOK)
}
func (api *operationAPI) accept(w http.ResponseWriter, receipt *arcadev1.ArcadeOperation, status int) {
	w.Header().Set("Location", "/v1/operations/"+receipt.Name)
	w.Header().Set("Retry-After", "2")
	w.Header().Set("ETag", operationETag(receipt))
	operationJSON(w, status, operationOutput(receipt))
}

type operationProblem struct {
	status int
	code   string
}

func (problem *operationProblem) Error() string { return "operation request rejected" }
func rejectOperation(status int, code string) error {
	return &operationProblem{status: status, code: code}
}

func (api *operationAPI) bind(ctx context.Context, action arcadev1.ArcadeOperationAction, request *arcadev1.OperationRequest) error {
	var server *arcadev1.GameServer
	if action == arcadev1.OperationServerCreate {
		if !operationName.MatchString(request.ServerName) {
			return rejectOperation(400, "invalid_request")
		}
		server = &arcadev1.GameServer{}
		err := api.store.Get(ctx, types.NamespacedName{Namespace: api.server.namespace, Name: request.ServerName}, server)
		if err == nil {
			return rejectOperation(412, "precondition_failed")
		}
		if !apierrors.IsNotFound(err) {
			return err
		}
		server = &arcadev1.GameServer{ObjectMeta: metav1.ObjectMeta{Name: request.ServerName, Namespace: api.server.namespace, UID: "api-validation"}, Spec: arcadev1.GameServerSpec{Game: request.Create.Game, DesiredState: request.Create.DesiredState, Compute: request.Create.Compute, Storage: request.Create.Storage, Settings: jsonSettings(request.Create.SettingsJSON)}}
		if request.Create.RetainedWorld != nil {
			if err := api.checkRetained(ctx, request.Create.RetainedWorld); err != nil {
				return err
			}
		}
	} else if request.Destroy != nil && request.Destroy.RetainedWorld != nil {
		return api.checkRetained(ctx, request.Destroy.RetainedWorld)
	} else if request.DestroyCommand != nil {
		parent, err := api.lookup(ctx, request.DestroyCommand.ParentOperationRef.Name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return rejectOperation(404, "not_found")
			}
			return err
		}
		if request.Precondition != operationETag(parent) {
			return rejectOperation(412, "precondition_failed")
		}
		if parent.Spec.Action != arcadev1.OperationWorldDestroyPreview || parent.Status.Child == nil || parent.Status.Child.Kind != "GameDestroy" || parent.Status.Child.Name != request.DestroyCommand.DestroyRef.Name || parent.Status.Child.UID != request.DestroyCommand.DestroyRef.UID {
			return rejectOperation(409, "invalid_reference")
		}
		request.DestroyCommand.ParentOperationRef.UID = string(parent.UID)
		return nil
	} else {
		if !operationName.MatchString(request.ServerName) {
			return rejectOperation(400, "invalid_request")
		}
		server = &arcadev1.GameServer{}
		if err := api.store.Get(ctx, types.NamespacedName{Namespace: api.server.namespace, Name: request.ServerName}, server); err != nil {
			if apierrors.IsNotFound(err) {
				return rejectOperation(404, "not_found")
			}
			return err
		}
		if server.DeletionTimestamp != nil || request.Precondition != serverETag(server) {
			return rejectOperation(412, "precondition_failed")
		}
		request.Target = &arcadev1.ExactGameServerReference{ExactLocalReference: arcadev1.ExactLocalReference{Name: server.Name, UID: string(server.UID)}, Generation: server.Generation, DesiredState: server.Spec.DesiredState}
		server = server.DeepCopy()
		if request.Configure != nil {
			if request.Configure.Compute != nil {
				server.Spec.Compute = *request.Configure.Compute
			}
			if request.Configure.Storage != nil {
				reattach := server.Spec.Storage.Reattach
				server.Spec.Storage = *request.Configure.Storage
				server.Spec.Storage.Reattach = reattach
			}
			if request.Configure.SettingsJSON != nil {
				server.Spec.Settings = jsonSettings(*request.Configure.SettingsJSON)
			}
		}
	}
	definition, err := api.catalog.Get(server.Spec.Game)
	if err != nil {
		return rejectOperation(422, "unsupported")
	}
	if request.Image != nil {
		if (request.Image.Digest == "") == (request.Image.Version == "") {
			return rejectOperation(400, "invalid_request")
		}
		resolution := arcadev1.OperationImageResolution{Repository: definition.ImageRepository, Digest: request.Image.Digest, ResolverVersion: "digest-v1", ResolvedAt: metav1.NewTime(api.server.clock().UTC())}
		if request.Image.Version != "" {
			expectedTag, err := platformgame.ResolveVersionTag(definition, request.Image.Version)
			if err != nil {
				return rejectOperation(400, "invalid_request")
			}
			resolved, err := api.resolver.Resolve(ctx, definition, request.Image.Version)
			if err != nil {
				return rejectOperation(503, "image_unavailable")
			}
			if resolved.Repository != definition.ImageRepository || resolved.Tag != expectedTag || !snapshotDigest.MatchString(resolved.Digest) {
				return rejectOperation(503, "image_unavailable")
			}
			resolution.Repository = resolved.Repository
			resolution.Tag = resolved.Tag
			resolution.Digest = resolved.Digest
			resolution.ResolverVersion = "registry-v1"
			resolution.ResolvedAt = metav1.NewTime(api.server.clock().UTC())
		}
		request.Image.Resolution = resolution
		server.Spec.ImageDigest = resolution.Digest
	}
	if _, err := platformkube.Build(server, definition); err != nil {
		return rejectOperation(422, "validation_failed")
	}
	return nil
}

func (api *operationAPI) checkRetained(ctx context.Context, selector *arcadev1.OperationRetainedWorldSelector) error {
	if !operationName.MatchString(selector.DecommissionOperationRef.Name) {
		return rejectOperation(400, "invalid_reference")
	}
	receipt, err := api.lookup(ctx, selector.DecommissionOperationRef.Name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return rejectOperation(404, "not_found")
		}
		return err
	}
	if receipt.Spec.Action != arcadev1.OperationServerDecommission || receipt.Status.Phase != arcadev1.OperationPhaseSucceeded || receipt.Status.ObservedGeneration != receipt.Generation || receipt.Status.RetainedWorld == nil || string(receipt.UID) != selector.DecommissionOperationRef.UID || receipt.Status.RetainedWorld.SnapshotDigest != selector.SnapshotDigest {
		return rejectOperation(412, "precondition_failed")
	}
	digest, err := operations.RetainedSnapshotDigest(receipt.Status.RetainedWorld.Target)
	if err != nil || digest != selector.SnapshotDigest {
		return rejectOperation(409, "invalid_reference")
	}
	return nil
}

func operationJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func operationError(w http.ResponseWriter, status int, code, id string) {
	suggestion := "Correct the request and retry."
	retryable := status >= 500
	switch code {
	case "commit_unknown":
		suggestion = "Poll operationID or retry exactly the same request with the same Idempotency-Key."
	case "idempotency_conflict":
		suggestion = "Use the original request for this key, or a new key for a different operation."
	case "precondition_required", "invalid_precondition", "precondition_failed":
		suggestion = "Read the exact current resource ETag and submit a new intent with a new Idempotency-Key."
	case "api_unavailable", "image_unavailable":
		suggestion = "Retry the same request with the same Idempotency-Key."
	}
	operationJSON(w, status, adminv1.Error{Version: "v1", Code: code, OperationID: id, Retryable: retryable, SuggestedAction: suggestion})
}
