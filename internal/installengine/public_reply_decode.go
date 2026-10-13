// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"sync"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	strictjson "sigs.k8s.io/json"
)

const (
	publicReplyEntries = 64
	publicReplyBytes   = 1024 * 1024
	publicReplySize    = 64 * 1024
)

type publicReplyEntry struct {
	key    installstate.Key
	body   []byte
	object *unstructured.Unstructured
}

// Owned by one HTTPAccess constructor, not shared with derived actor clients.
// Limits bound retained raw bytes and entry count, not total Go heap/RSS.
// Only exact named public GET routes may call this from requestAt. A complete
// fresh response is mandatory; there are no UID/RV/hash-only hits or verdicts.
type publicReplyMemo struct {
	mu      sync.Mutex
	entries []publicReplyEntry
	bytes   int
}

func strictPublicReply(raw []byte) (*unstructured.Unstructured, error) {
	result := &unstructured.Unstructured{}
	problems, err := strictjson.UnmarshalStrict(raw, &result.Object)
	if err != nil || len(problems) != 0 {
		return nil, ErrRead
	}
	return result, nil
}

func (m *publicReplyMemo) remove(index int) {
	m.bytes -= len(m.entries[index].body)
	copy(m.entries[index:], m.entries[index+1:])
	m.entries[len(m.entries)-1] = publicReplyEntry{}
	m.entries = m.entries[:len(m.entries)-1]
}

func (m *publicReplyMemo) clear(key installstate.Key) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, entry := range m.entries {
		if entry.key == key {
			m.remove(i)
			return
		}
	}
}

func (m *publicReplyMemo) decode(key installstate.Key, raw []byte) (*unstructured.Unstructured, error) {
	if m == nil {
		return strictPublicReply(raw)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, entry := range m.entries {
		if entry.key != key {
			continue
		}
		if bytes.Equal(entry.body, raw) {
			return entry.object.DeepCopy(), nil
		}
		m.remove(i) // changed bytes never inherit a prior conversion
		break
	}
	result, err := strictPublicReply(raw)
	if err != nil {
		return nil, err
	}
	if result.GetAPIVersion() != key.APIVersion || result.GetKind() != key.Kind || result.GetName() != key.Name || result.GetNamespace() != key.Namespace {
		return nil, ErrRead
	}
	if len(raw) > publicReplySize {
		return result, err // large valid replies remain uncached
	}
	for len(m.entries) >= publicReplyEntries || m.bytes+len(raw) > publicReplyBytes {
		m.remove(0)
	}
	m.entries = append(m.entries, publicReplyEntry{key, bytes.Clone(raw), result.DeepCopy()})
	m.bytes += len(raw)
	return result, nil
}
