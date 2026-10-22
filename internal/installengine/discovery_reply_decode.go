// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	discoveryReplyEntries = 11
	discoveryReplyBytes   = 512 * 1024
	discoveryReplySize    = 64 * 1024
)

type discoveryReplyEntry struct {
	group  string
	body   []byte
	list   *metav1.APIResourceList
	fields map[string]any
}

// Per-HTTPAccess pure conversion memo. Limits bound retained raw bytes and
// entry count, not total Go heap/RSS. Each use follows a complete fresh HTTP
// response and every discovery semantic check still runs in discover.
// Neither UID/RV/hash-only hits nor cached authority/verdicts are supported.
type discoveryReplyMemo struct {
	mu      sync.Mutex
	entries []discoveryReplyEntry
	bytes   int
}

func strictDiscoveryReply(raw []byte) (*metav1.APIResourceList, map[string]any, error) {
	result := &metav1.APIResourceList{}
	fields, err := strictProofReply(raw, result)
	if err != nil {
		return nil, nil, err
	}
	return result, fields, nil
}

func (m *discoveryReplyMemo) remove(index int) {
	m.bytes -= len(m.entries[index].body)
	copy(m.entries[index:], m.entries[index+1:])
	m.entries[len(m.entries)-1] = discoveryReplyEntry{}
	m.entries = m.entries[:len(m.entries)-1]
}

func (m *discoveryReplyMemo) clear(gv string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, entry := range m.entries {
		if entry.group == gv {
			m.remove(i)
			return
		}
	}
}

func (m *discoveryReplyMemo) decode(gv string, raw []byte) (*metav1.APIResourceList, map[string]any, error) {
	if _, err := discoveryPath(gv); err != nil {
		return nil, nil, err
	}
	if m == nil {
		return strictDiscoveryReply(raw)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, entry := range m.entries {
		if entry.group != gv {
			continue
		}
		if bytes.Equal(entry.body, raw) {
			return entry.list.DeepCopy(), runtime.DeepCopyJSON(entry.fields), nil
		}
		m.remove(i) // even malformed changed bytes invalidate prior conversion
		break
	}
	result, fields, err := strictDiscoveryReply(raw)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > discoveryReplySize {
		return result, fields, nil // valid larger replies retain the old path
	}
	for len(m.entries) >= discoveryReplyEntries || m.bytes+len(raw) > discoveryReplyBytes {
		m.remove(0)
	}
	m.entries = append(m.entries, discoveryReplyEntry{gv, bytes.Clone(raw), result.DeepCopy(), runtime.DeepCopyJSON(fields)})
	m.bytes += len(raw)
	return result, fields, nil
}
