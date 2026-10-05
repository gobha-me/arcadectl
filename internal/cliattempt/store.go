// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cliattempt

import (
	"context"
	"errors"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/cliintent"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"github.com/gobha-me/arcadectl/internal/receiptid"
)

func validateClient(client Client, identity adminclient.Identity) error {
	if client == nil || !validIdentity(identity) || client.Identity() != identity {
		return ErrContextChanged
	}
	return nil
}

func operationMatches(operation *adminv1.Operation, value *record) bool {
	if operation == nil || operation.Version != adminv1.Version || operation.OperationID != value.ExpectedOperationID ||
		!uidPattern.MatchString(operation.UID) || operation.Generation < 1 || operation.Action != value.Intent.Action {
		return false
	}
	// Once a response has been durably admitted, its UID is an immutable fence.
	// A same-name replacement is not the original idempotency receipt.
	if value.OperationUID != "" && value.OperationUID != operation.UID {
		return false
	}
	if value.Intent.DestroyRef != nil && operation.Child != nil {
		return operation.Child.Kind == "GameDestroy" && operation.Child.Name == value.Intent.DestroyRef.Name && operation.Child.UID == value.Intent.DestroyRef.UID
	}
	return true
}

func notFound(err error) bool {
	var apiError *adminclient.Error
	return errors.As(err, &apiError) && apiError.Code == "not_found" && apiError.HTTPStatus == 404 && !apiError.Ambiguous
}

func ambiguous(err error) bool {
	var apiError *adminclient.Error
	if errors.As(err, &apiError) {
		return apiError.Ambiguous || apiError.Code == "commit_unknown"
	}
	return true
}

func (store *Store) updateState(value *record, identity *privatefs.FileIdentity, state State, operation *adminv1.Operation) error {
	copy := *value
	copy.State = state
	if operation != nil {
		copy.OperationUID = operation.UID
	}
	updated, err := store.writeRecord(&copy, identity)
	if err != nil {
		return err
	}
	*value = copy
	*identity = updated
	return nil
}

// discover performs only the safe exact receipt read. It never falls back to
// listing or submits a mutation.
func (store *Store) discover(ctx context.Context, client Client, value *record, fileIdentity *privatefs.FileIdentity) (Result, error) {
	result := info(value)
	var operation adminv1.Operation
	_, err := client.Read(ctx, "/v1/operations/"+value.ExpectedOperationID, &operation)
	if err != nil {
		if notFound(err) {
			if value.State == StateAdmitted {
				return result, ErrReceiptMissing
			}
			return result, ErrResumeRequired
		}
		return result, err
	}
	if !operationMatches(&operation, value) {
		return result, ErrContextChanged
	}
	if value.State != StateAdmitted || value.OperationUID != operation.UID {
		if err := store.updateState(value, fileIdentity, StateAdmitted, &operation); err != nil {
			return result, err
		}
	}
	result = info(value)
	result.Operation = &operation
	return result, nil
}

func (store *Store) submitFrozen(ctx context.Context, client Client, value *record, fileIdentity *privatefs.FileIdentity) (Result, error) {
	result := info(value)
	if err := store.updateState(value, fileIdentity, StateSubmitting, nil); err != nil {
		return result, err
	}
	intent := value.Intent.runtime()
	operation, err := client.Submit(ctx, intent.Method, intent.Path, intent.Body, value.IdempotencyKey, intent.Conditional)
	if err != nil {
		state := StateRejected
		if ambiguous(err) {
			state = StateUncertain
		}
		if state == StateRejected {
			var apiError *adminclient.Error
			if errors.As(err, &apiError) {
				value.FailureCode = apiError.Code
				value.FailureHTTPStatus = apiError.HTTPStatus
			} else {
				value.FailureCode = "client_failure"
			}
		}
		if updateErr := store.updateState(value, fileIdentity, state, nil); updateErr != nil {
			return info(value), updateErr
		}
		if state == StateUncertain {
			return info(value), ErrResumeRequired
		}
		return info(value), err
	}
	if !operationMatches(&operation, value) {
		if updateErr := store.updateState(value, fileIdentity, StateUncertain, nil); updateErr != nil {
			return info(value), updateErr
		}
		return info(value), ErrResumeRequired
	}
	if err := store.updateState(value, fileIdentity, StateAdmitted, &operation); err != nil {
		return info(value), err
	}
	result = info(value)
	result.Operation = &operation
	return result, nil
}

// Submit creates one durable attempt for a caller-known scope. If an
// unresolved head already exists, the exact expected receipt is read before
// prepare is invoked. No missing or uncertain receipt is submitted implicitly.
func (store *Store) Submit(ctx context.Context, client Client, identity adminclient.Identity, scope string, fingerprintInput []byte, prepare func() (cliintent.Intent, error)) (Result, error) {
	if store == nil || store.files == nil || ctx == nil || prepare == nil || !validScope(scope) {
		return Result{}, ErrInvalid
	}
	if err := validateClient(client, identity); err != nil {
		return Result{}, err
	}
	fingerprintDigest, err := fingerprint(fingerprintInput)
	if err != nil {
		return Result{}, err
	}
	headFile := headName(identity, scope)
	lock, err := store.files.Lock(ctx, headFile)
	if err != nil {
		return Result{}, errors.Join(ErrStorage, err, ctx.Err())
	}
	defer lock.Close()

	currentHead, headIdentity, headErr := store.readHead(headFile)
	if headErr == nil {
		current, currentIdentity, err := store.readRecord(currentHead.AttemptID)
		if err != nil {
			return Result{}, err
		}
		if current.Scope != scope || !identityMatches(current.Identity, identity) {
			return info(current), ErrContextChanged
		}
		if current.State != StateResolved {
			if current.Fingerprint != fingerprintDigest {
				return info(current), ErrPendingIntent
			}
			switch current.State {
			case StateRejected:
				return info(current), ErrRejected
			default:
				return store.discover(ctx, client, current, &currentIdentity)
			}
		}
	} else if !errors.Is(headErr, privatefs.ErrNotFound) {
		return Result{}, ErrStorage
	}

	intent, err := prepare()
	if err != nil {
		return Result{}, err
	}
	frozen, err := intentFrom(intent)
	if err != nil {
		return Result{}, err
	}
	attemptID, err := newOpaque("attempt-", 16)
	if err != nil {
		return Result{}, err
	}
	key, err := newKey()
	if err != nil {
		return Result{}, err
	}
	expected, err := receiptid.ReceiptName(identity.Namespace, identity.PrincipalID, key)
	if err != nil {
		return Result{}, ErrInvalid
	}
	value := &record{Version: recordVersion, AttemptID: attemptID, Scope: scope, Fingerprint: fingerprintDigest, Identity: persisted(identity), State: StatePrepared,
		IdempotencyKey: key, ExpectedOperationID: expected, Intent: frozen}
	fileIdentity, err := store.writeRecord(value, nil)
	if err != nil {
		return Result{}, err
	}
	newHead, err := marshal(head{Version: recordVersion, AttemptID: attemptID})
	if err != nil {
		return info(value), err
	}
	var expectedHead *privatefs.FileIdentity
	if headErr == nil {
		expectedHead = &headIdentity
	}
	if _, err := store.files.AtomicWrite(headFile, newHead, expectedHead); err != nil {
		return info(value), ErrStorage
	}
	return store.submitFrozen(ctx, client, value, &fileIdentity)
}

func review(value *record) Review {
	parentUID := parentOperationUID(value.Intent.Conditional.IfMatch)
	return Review{AttemptID: value.AttemptID, Action: value.Intent.Action, ParentOperationID: value.Intent.ParentOperationID,
		ParentOperationUID: parentUID, Conditional: value.Intent.Conditional,
		DestroyPreview: copyPreview(value.Intent.DestroyPreview), DestroyRef: copyReference(value.Intent.DestroyRef)}
}

// Resume first reads the deterministic receipt. It performs the frozen POST or
// PATCH only after this explicit call and, for destroy confirmation, after a
// fresh callback over the same immutable preview.
func (store *Store) Resume(ctx context.Context, client Client, identity adminclient.Identity, attemptID string, prompt ResumePrompt) (Result, error) {
	if store == nil || store.files == nil || ctx == nil || !attemptIDPattern.MatchString(attemptID) {
		return Result{}, ErrInvalid
	}
	if err := validateClient(client, identity); err != nil {
		return Result{}, err
	}
	initial, _, err := store.readRecord(attemptID)
	if err != nil {
		return Result{}, err
	}
	if !identityMatches(initial.Identity, identity) {
		return info(initial), ErrContextChanged
	}
	headFile := headName(identity, initial.Scope)
	lock, err := store.files.Lock(ctx, headFile)
	if err != nil {
		return info(initial), errors.Join(ErrStorage, err, ctx.Err())
	}
	defer lock.Close()
	currentHead, _, err := store.readHead(headFile)
	if err != nil {
		return info(initial), ErrStorage
	}
	if currentHead.AttemptID != attemptID {
		return info(initial), ErrContextChanged
	}
	value, fileIdentity, err := store.readRecord(attemptID)
	if err != nil {
		return Result{}, err
	}
	if !identityMatches(value.Identity, identity) || value.Scope != initial.Scope {
		return info(value), ErrContextChanged
	}
	if value.State == StateResolved {
		return info(value), ErrResolved
	}
	if value.State == StateRejected {
		return info(value), ErrRejected
	}
	if result, discoverErr := store.discover(ctx, client, value, &fileIdentity); discoverErr == nil {
		return result, nil
	} else if !errors.Is(discoverErr, ErrResumeRequired) {
		return result, discoverErr
	}
	if value.Intent.Action == "world.destroy.confirm" {
		if prompt == nil || value.Intent.DestroyPreview == nil || value.Intent.DestroyRef == nil {
			return info(value), ErrPrompt
		}
		expires, err := time.Parse(time.RFC3339Nano, value.Intent.DestroyPreview.ExpiresAt)
		if err != nil || !time.Now().UTC().Before(expires) {
			return info(value), ErrPrompt
		}
		if err := prompt(ctx, review(value)); err != nil {
			return info(value), errors.Join(ErrPrompt, err)
		}
		if !time.Now().UTC().Before(expires) {
			return info(value), ErrPrompt
		}
	} else if prompt != nil {
		if err := prompt(ctx, review(value)); err != nil {
			return info(value), errors.Join(ErrPrompt, err)
		}
	}
	return store.submitFrozen(ctx, client, value, &fileIdentity)
}

// Resolve marks an attempt locally complete after the caller has observed the
// operation-specific terminal contract. It does not delete forensic state.
func (store *Store) Resolve(ctx context.Context, identity adminclient.Identity, attemptID string) error {
	if store == nil || store.files == nil || ctx == nil || !attemptIDPattern.MatchString(attemptID) || !validIdentity(identity) {
		return ErrInvalid
	}
	initial, _, err := store.readRecord(attemptID)
	if err != nil {
		return err
	}
	if !identityMatches(initial.Identity, identity) {
		return ErrContextChanged
	}
	headFile := headName(identity, initial.Scope)
	lock, err := store.files.Lock(ctx, headFile)
	if err != nil {
		return errors.Join(ErrStorage, err, ctx.Err())
	}
	defer lock.Close()
	currentHead, _, err := store.readHead(headFile)
	if err != nil {
		return ErrStorage
	}
	if currentHead.AttemptID != attemptID {
		return ErrContextChanged
	}
	value, fileIdentity, err := store.readRecord(attemptID)
	if err != nil {
		return err
	}
	if !identityMatches(value.Identity, identity) || value.Scope != initial.Scope {
		return ErrContextChanged
	}
	if value.State == StateResolved {
		return nil
	}
	if value.State != StateAdmitted && value.State != StateRejected {
		return ErrResumeRequired
	}
	return store.updateState(value, &fileIdentity, StateResolved, nil)
}
