// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package cliattempt durably fences CLI mutation submission and explicit
// replay. It persists no bearer token or HTTP authorization header.
package cliattempt

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/cliintent"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"github.com/gobha-me/arcadectl/internal/receiptid"
)

var (
	ErrInvalid        = errors.New("invalid durable mutation attempt")
	ErrStorage        = errors.New("durable mutation attempt storage is unavailable")
	ErrPendingIntent  = errors.New("a different unresolved intent already exists")
	ErrResumeRequired = errors.New("explicit attempt resume is required")
	ErrReceiptMissing = errors.New("the admitted operation receipt is unavailable")
	ErrRejected       = errors.New("the saved mutation attempt was rejected")
	ErrResolved       = errors.New("the saved mutation attempt is already resolved")
	ErrContextChanged = errors.New("the authenticated API context changed")
	ErrPrompt         = errors.New("explicit mutation replay was not authorized")
)

const (
	recordVersion = "v1"
	maxRecordSize = int64(256 * 1024)
	ResumeHint    = "resume_required"
)

type State string

const (
	StatePrepared   State = "prepared"
	StateSubmitting State = "submitting"
	StateAdmitted   State = "admitted"
	StateUncertain  State = "uncertain"
	StateRejected   State = "rejected"
	StateResolved   State = "resolved"
)

// Result contains only non-secret attempt and receipt identity. It never
// exposes the idempotency key or frozen request body.
type Result struct {
	AttemptID           string
	ExpectedOperationID string
	State               State
	ResumeHint          string
	Action              string
	ParentOperationID   string
	ParentOperationUID  string
	DestroyRef          *adminv1.ExactReference
	FailureCode         string
	FailureHTTPStatus   int
	Operation           *adminv1.Operation
}

// Review is a safe callback view used immediately before explicit replay.
// Confirm callers must show Preview and require its same frozen challenge from
// a real TTY. The stored HTTP body and idempotency key remain private.
type Review struct {
	AttemptID          string
	Action             string
	ParentOperationID  string
	ParentOperationUID string
	Conditional        adminclient.Conditional
	DestroyPreview     *adminv1.DestroyPreview
	DestroyRef         *adminv1.ExactReference
}

type ResumePrompt func(context.Context, Review) error

type Client interface {
	Identity() adminclient.Identity
	Read(context.Context, string, any) (string, error)
	Submit(context.Context, string, string, []byte, string, adminclient.Conditional) (adminv1.Operation, error)
}

type persistedIdentity struct {
	Origin      string `json:"origin"`
	CAHash      string `json:"caHash"`
	PrincipalID string `json:"principalId"`
	Namespace   string `json:"namespace"`
}

type persistedIntent struct {
	Action            string                  `json:"action"`
	Method            string                  `json:"method"`
	Path              string                  `json:"path"`
	Body              json.RawMessage         `json:"body"`
	Conditional       adminclient.Conditional `json:"conditional"`
	ParentOperationID string                  `json:"parentOperationId,omitempty"`
	DestroyPreview    *adminv1.DestroyPreview `json:"destroyPreview,omitempty"`
	DestroyRef        *adminv1.ExactReference `json:"destroyRef,omitempty"`
}

type record struct {
	Version             string            `json:"version"`
	AttemptID           string            `json:"attemptId"`
	Scope               string            `json:"scope"`
	Fingerprint         string            `json:"fingerprint"`
	Identity            persistedIdentity `json:"identity"`
	State               State             `json:"state"`
	IdempotencyKey      string            `json:"idempotencyKey"`
	ExpectedOperationID string            `json:"expectedOperationId"`
	Intent              persistedIntent   `json:"intent"`
	OperationUID        string            `json:"operationUid,omitempty"`
	FailureCode         string            `json:"failureCode,omitempty"`
	FailureHTTPStatus   int               `json:"failureHttpStatus,omitempty"`
}

type head struct {
	Version   string `json:"version"`
	AttemptID string `json:"attemptId"`
}

type Store struct {
	files *privatefs.Store
}

var (
	attemptIDPattern     = regexp.MustCompile(`^attempt-[0-9a-f]{32}$`)
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	keyPattern           = regexp.MustCompile(`^[a-f0-9]{64}$`)
	actionPattern        = regexp.MustCompile(`^[a-z]+(?:[.][a-z]+){1,3}$`)
	failureCodePattern   = regexp.MustCompile(`^[a-z_]{1,64}$`)
	pathPattern          = regexp.MustCompile(`^/v1/[A-Za-z0-9_./-]{1,500}$`)
	uidPattern           = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	labelIDPattern       = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	receiptNamePattern   = regexp.MustCompile(`^ao-[a-z2-7]{52}$`)
	operationETagPattern = regexp.MustCompile(`^"operation:([A-Za-z0-9_.-]{1,128}):[1-9][0-9]*"$`)
	challengePattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

func OpenStore(base string, create bool) (*Store, error) {
	files, err := privatefs.Open(base, create)
	if err != nil {
		return nil, ErrStorage
	}
	return &Store{files: files}, nil
}

func (store *Store) Close() error {
	if store == nil || store.files == nil {
		return nil
	}
	if err := store.files.Close(); err != nil {
		return ErrStorage
	}
	return nil
}

func persisted(identity adminclient.Identity) persistedIdentity {
	return persistedIdentity{Origin: identity.Origin, CAHash: identity.CAHash, PrincipalID: identity.PrincipalID, Namespace: identity.Namespace}
}

func identityMatches(left persistedIdentity, right adminclient.Identity) bool {
	return left == persisted(right)
}

func validIdentity(identity adminclient.Identity) bool {
	return identity.Origin != "" && digestPattern.MatchString(identity.CAHash) && uidPattern.MatchString(identity.PrincipalID) &&
		labelIDPattern.MatchString(identity.Namespace)
}

func validScope(scope string) bool {
	if len(scope) < 1 || len(scope) > 512 || !utf8.ValidString(scope) {
		return false
	}
	for _, value := range scope {
		if value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
}

func fingerprint(input []byte) (string, error) {
	if len(input) == 0 || len(input) > canonicaljson.MaxBytes {
		return "", ErrInvalid
	}
	canonical, err := canonicaljson.CanonicalJSON(input)
	if err != nil || !bytes.Equal(canonical, input) {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(input)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func headName(identity adminclient.Identity, scope string) string {
	digest := sha256.Sum256([]byte("arcadectl/cli-attempt-head/v1\x00" + identity.Origin + "\x00" + identity.CAHash + "\x00" + identity.PrincipalID + "\x00" + identity.Namespace + "\x00" + scope))
	return "head-" + hex.EncodeToString(digest[:16]) + ".json"
}

func recordName(attemptID string) string { return attemptID + ".json" }

func newOpaque(prefix string, bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", ErrStorage
	}
	return prefix + hex.EncodeToString(value), nil
}

func newKey() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", ErrStorage
	}
	return hex.EncodeToString(value), nil
}

func strictDecode(contents []byte, target any) error {
	if len(contents) == 0 || int64(len(contents)) > maxRecordSize || !utf8.Valid(contents) {
		return ErrStorage
	}
	validator := json.NewDecoder(bytes.NewReader(contents))
	validator.UseNumber()
	if err := strictJSONValue(validator, 0); err != nil {
		return ErrStorage
	}
	if _, err := validator.Token(); err != io.EOF {
		return ErrStorage
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrStorage
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrStorage
	}
	return nil
}

func strictJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrStorage
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrStorage
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		if number, ok := token.(json.Number); ok && len(number) > 128 {
			return ErrStorage
		}
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return ErrStorage
			}
			if _, duplicate := seen[name]; duplicate {
				return ErrStorage
			}
			seen[name] = struct{}{}
			if err := strictJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrStorage
		}
		return nil
	case '[':
		for decoder.More() {
			if err := strictJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrStorage
		}
		return nil
	default:
		return ErrStorage
	}
}

func marshal(value any) ([]byte, error) {
	contents, err := json.Marshal(value)
	if err != nil || int64(len(contents)) > maxRecordSize {
		return nil, ErrStorage
	}
	return contents, nil
}

func intentFrom(value cliintent.Intent) (persistedIntent, error) {
	canonical, err := canonicaljson.CanonicalJSON(value.Body)
	if err != nil || !bytes.Equal(canonical, value.Body) || len(value.Action) > 64 || !actionPattern.MatchString(value.Action) ||
		(value.Method != "POST" && value.Method != "PATCH") || !pathPattern.MatchString(value.Path) || strings.ContainsAny(value.Path, "?#") ||
		(value.Conditional.IfNoneMatch == (value.Conditional.IfMatch != "")) {
		return persistedIntent{}, ErrInvalid
	}
	if value.ParentOperationID != "" && (!labelName(value.ParentOperationID) || !operationETagPattern.MatchString(value.Conditional.IfMatch)) {
		return persistedIntent{}, ErrInvalid
	}
	copy := persistedIntent{Action: value.Action, Method: value.Method, Path: value.Path, Body: append(json.RawMessage(nil), value.Body...), Conditional: value.Conditional,
		ParentOperationID: value.ParentOperationID, DestroyPreview: copyPreview(value.DestroyPreview), DestroyRef: copyReference(value.DestroyRef)}
	if !validIntentMetadata(copy) {
		return persistedIntent{}, ErrInvalid
	}
	return copy, nil
}

func validIntentMetadata(value persistedIntent) bool {
	switch value.Action {
	case "world.destroy.confirm":
		if value.Method != "POST" || value.ParentOperationID == "" || value.Path != "/v1/destroy-operations/"+value.ParentOperationID+"/confirm" ||
			!validStoredPreview(value.DestroyPreview) || !validStoredReference(value.DestroyRef) {
			return false
		}
		request := adminv1.ConfirmRequest{}
		return decodeBody(value.Body, &request) && request.Version == adminv1.Version && request.DestroyRef == *value.DestroyRef && request.Challenge == value.DestroyPreview.Challenge
	case "world.destroy.cancel":
		if value.Method != "POST" || value.ParentOperationID == "" || value.Path != "/v1/destroy-operations/"+value.ParentOperationID+"/cancel" || !validStoredReference(value.DestroyRef) ||
			(value.DestroyPreview != nil && !validStoredPreview(value.DestroyPreview)) {
			return false
		}
		request := adminv1.CancelRequest{}
		return decodeBody(value.Body, &request) && request.Version == adminv1.Version && request.DestroyRef == *value.DestroyRef
	default:
		return value.ParentOperationID == "" && value.DestroyPreview == nil && value.DestroyRef == nil
	}
}

func decodeBody(contents []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	return decoder.Decode(&struct{}{}) == io.EOF
}

func validStoredReference(reference *adminv1.ExactReference) bool {
	if reference == nil || len(reference.Name) == 0 || len(reference.Name) > 253 || !uidPattern.MatchString(reference.UID) {
		return false
	}
	for _, label := range strings.Split(reference.Name, ".") {
		if !labelIDPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validStoredPreview(preview *adminv1.DestroyPreview) bool {
	if preview == nil || !challengePattern.MatchString(preview.Challenge) || !validStoredReference(&preview.Target.OriginalServer) ||
		!validStoredReference(&preview.BackupRef) || !labelIDPattern.MatchString(preview.Target.Namespace) ||
		!labelIDPattern.MatchString(preview.Target.Game) || !labelIDPattern.MatchString(preview.Target.DataIdentity) ||
		len(preview.Target.Claims) == 0 || len(preview.Target.Claims) > 16 || !safeStoredText(preview.RestoreGuidance) {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, preview.ExpiresAt)
	if err != nil || expires.UTC().Format(time.RFC3339Nano) != preview.ExpiresAt {
		return false
	}
	paths, names, uids := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for index := range preview.Target.Claims {
		claim := &preview.Target.Claims[index]
		if !labelIDPattern.MatchString(claim.Path) || !validStoredReference(&claim.ClaimRef) {
			return false
		}
		if _, found := paths[claim.Path]; found {
			return false
		}
		if _, found := names[claim.ClaimRef.Name]; found {
			return false
		}
		if _, found := uids[claim.ClaimRef.UID]; found {
			return false
		}
		paths[claim.Path], names[claim.ClaimRef.Name], uids[claim.ClaimRef.UID] = struct{}{}, struct{}{}, struct{}{}
	}
	return true
}

func safeStoredText(value string) bool {
	if len(value) == 0 || len(value) > 1024 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func labelName(value string) bool {
	return receiptNamePattern.MatchString(value)
}

func (value persistedIntent) runtime() cliintent.Intent {
	return cliintent.Intent{Action: value.Action, Method: value.Method, Path: value.Path, Body: append([]byte(nil), value.Body...), Conditional: value.Conditional,
		ParentOperationID: value.ParentOperationID, DestroyPreview: copyPreview(value.DestroyPreview), DestroyRef: copyReference(value.DestroyRef)}
}

func copyReference(input *adminv1.ExactReference) *adminv1.ExactReference {
	if input == nil {
		return nil
	}
	copy := *input
	return &copy
}

func copyPreview(input *adminv1.DestroyPreview) *adminv1.DestroyPreview {
	if input == nil {
		return nil
	}
	copy := *input
	copy.Target.Claims = append([]adminv1.RetainedClaim(nil), input.Target.Claims...)
	return &copy
}

func validRecord(value *record) bool {
	if value == nil || value.Version != recordVersion || !attemptIDPattern.MatchString(value.AttemptID) || !validScope(value.Scope) ||
		!digestPattern.MatchString(value.Fingerprint) || !digestPattern.MatchString(value.Identity.CAHash) ||
		!uidPattern.MatchString(value.Identity.PrincipalID) || value.Identity.Origin == "" || value.Identity.Namespace == "" ||
		!keyPattern.MatchString(value.IdempotencyKey) || value.ExpectedOperationID == "" {
		return false
	}
	switch value.State {
	case StatePrepared, StateSubmitting, StateAdmitted, StateUncertain, StateRejected, StateResolved:
	default:
		return false
	}
	intent, err := intentFrom(value.Intent.runtime())
	if err != nil || !reflectIntentEqual(intent, value.Intent) {
		return false
	}
	expected, err := receiptid.ReceiptName(value.Identity.Namespace, value.Identity.PrincipalID, value.IdempotencyKey)
	validFailure := value.FailureCode == "" && value.FailureHTTPStatus == 0
	if value.State == StateRejected {
		validFailure = failureCodePattern.MatchString(value.FailureCode) && value.FailureHTTPStatus >= 0 && value.FailureHTTPStatus <= 599
	}
	validOperationUID := value.OperationUID == ""
	if value.State == StateAdmitted {
		validOperationUID = uidPattern.MatchString(value.OperationUID)
	} else if value.State == StateResolved {
		validOperationUID = value.OperationUID == "" || uidPattern.MatchString(value.OperationUID)
		if value.OperationUID == "" {
			validFailure = failureCodePattern.MatchString(value.FailureCode) && value.FailureHTTPStatus >= 0 && value.FailureHTTPStatus <= 599
		}
	}
	return err == nil && expected == value.ExpectedOperationID && validOperationUID && validFailure
}

func reflectIntentEqual(left, right persistedIntent) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func (store *Store) readRecord(attemptID string) (*record, privatefs.FileIdentity, error) {
	if store == nil || store.files == nil || !attemptIDPattern.MatchString(attemptID) {
		return nil, privatefs.FileIdentity{}, ErrInvalid
	}
	contents, identity, err := store.files.Read(recordName(attemptID), maxRecordSize)
	if err != nil {
		if errors.Is(err, privatefs.ErrNotFound) {
			return nil, privatefs.FileIdentity{}, ErrInvalid
		}
		return nil, privatefs.FileIdentity{}, ErrStorage
	}
	value := &record{}
	if strictDecode(contents, value) != nil || !validRecord(value) {
		return nil, privatefs.FileIdentity{}, ErrStorage
	}
	return value, identity, nil
}

func (store *Store) readHead(name string) (*head, privatefs.FileIdentity, error) {
	contents, identity, err := store.files.Read(name, 1024)
	if err != nil {
		return nil, privatefs.FileIdentity{}, err
	}
	value := &head{}
	if strictDecode(contents, value) != nil || value.Version != recordVersion || !attemptIDPattern.MatchString(value.AttemptID) {
		return nil, privatefs.FileIdentity{}, ErrStorage
	}
	return value, identity, nil
}

func (store *Store) writeRecord(value *record, expected *privatefs.FileIdentity) (privatefs.FileIdentity, error) {
	if !validRecord(value) {
		return privatefs.FileIdentity{}, ErrInvalid
	}
	contents, err := marshal(value)
	if err != nil {
		return privatefs.FileIdentity{}, err
	}
	identity, err := store.files.AtomicWrite(recordName(value.AttemptID), contents, expected)
	if err != nil {
		return privatefs.FileIdentity{}, ErrStorage
	}
	return identity, nil
}

func info(value *record) Result {
	parentUID := parentOperationUID(value.Intent.Conditional.IfMatch)
	hint := ""
	if value.State == StatePrepared || value.State == StateSubmitting || value.State == StateUncertain {
		hint = ResumeHint
	}
	return Result{AttemptID: value.AttemptID, ExpectedOperationID: value.ExpectedOperationID, State: value.State, ResumeHint: hint,
		Action: value.Intent.Action, ParentOperationID: value.Intent.ParentOperationID, ParentOperationUID: parentUID,
		DestroyRef:  copyReference(value.Intent.DestroyRef),
		FailureCode: value.FailureCode, FailureHTTPStatus: value.FailureHTTPStatus}
}

func parentOperationUID(etag string) string {
	if matches := operationETagPattern.FindStringSubmatch(etag); len(matches) == 2 {
		return matches[1]
	}
	return ""
}
