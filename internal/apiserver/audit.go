// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"encoding/json"
	"errors"
	"io"
	"sync"
)

// AuditEvent contains server-selected fields only. In particular, it has no
// request URI, headers, body, token verifier, or underlying error text.
type AuditEvent struct {
	Version      string `json:"version"`
	Timestamp    string `json:"timestamp"`
	RequestID    string `json:"requestId"`
	PrincipalID  string `json:"principalId,omitempty"`
	CredentialID string `json:"credentialId,omitempty"`
	Action       Action `json:"action"`
	Method       string `json:"method"`
	Route        string `json:"route"`
	Namespace    string `json:"namespace"`
	Phase        string `json:"phase"`
	Outcome      string `json:"outcome"`
	Status       int    `json:"status"`
	DurationMS   int64  `json:"durationMs"`
}

// AuditSink must synchronously accept a complete record or return an error.
// A successful stdout write is not a claim of durable external collection.
type AuditSink interface {
	Record(AuditEvent) error
}

// JSONAudit writes one bounded JSON line at a time. Partial writes are failures;
// retrying a fragment could make a collector accept a misleading record.
type JSONAudit struct {
	mu     sync.Mutex
	writer io.Writer
}

func NewJSONAudit(writer io.Writer) *JSONAudit { return &JSONAudit{writer: writer} }

func (audit *JSONAudit) Record(event AuditEvent) error {
	contents, err := json.Marshal(event)
	if err != nil || len(contents) > 4096 {
		return errors.New("audit record unavailable")
	}
	contents = append(contents, '\n')
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if audit.writer == nil {
		return errors.New("audit output unavailable")
	}
	n, err := audit.writer.Write(contents)
	if err != nil || n != len(contents) {
		return errors.New("audit output unavailable")
	}
	return nil
}
