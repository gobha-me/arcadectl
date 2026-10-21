// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"slices"
	"sync"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
)

// One successful pure decode, local to this Store. Complete exact bytes and
// the complete ordered immutable plan context must match. No Namespace, RV,
// identity/health observation, protected-file read, permission, runtime proof
// or effect capability is memoized. Load still performs its fresh GET and
// safeNamespace checks, and observe still checks the original document anchor.
type journalDecodeCache struct {
	mu       sync.Mutex
	plans    []*installrender.Plan
	baseline *installbaseline.Plan
	body     []byte
	document Document
}

func (s *Store) decodeJournal(body []byte, anchor Anchor) (Document, error) {
	c := &s.decoded
	c.mu.Lock()
	defer c.mu.Unlock()
	hit := c.body != nil && c.baseline == s.baseline && slices.Equal(c.plans, s.plans) && bytes.Equal(c.body, body)
	document := c.document
	if !hit {
		// Clear on every miss; refusals never fill or retain an entry.
		c.body, c.document, c.plans, c.baseline = nil, Document{}, nil, nil
		var err error
		document, err = DecodeWithBaseline(body, s.baseline, s.plans...)
		if err != nil {
			return Document{}, err
		}
	}
	// An original anchor must still match on hits, and a mismatched decoded
	// document must never populate the pure cache for another observation.
	if document.NamespaceUID != anchor.UID || document.Namespace != anchor.Namespace || document.InstallationID != anchor.InstallationID {
		c.body, c.document, c.plans, c.baseline = nil, Document{}, nil, nil
		return Document{}, ErrOwnership
	}
	if !hit {
		c.body, c.document = bytes.Clone(body), document
		c.plans, c.baseline = slices.Clone(s.plans), s.baseline
	}
	return cloneDocument(document), nil
}
