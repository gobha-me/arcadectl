// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	strictjson "sigs.k8s.io/json"
)

const maxResponseBytes = 4 * 1024 * 1024

// readTransport admits only bounded reads, suppresses raw server errors and
// warnings, and (for metadata) forbids the client's full-object fallback. The
// API server legitimately returns plain application/json for transformed
// metadata: Content-Type alone cannot establish that a Secret body is absent.
type readTransport struct {
	next     http.RoundTripper
	metadata bool
}

func (t readTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.Method != http.MethodGet || t.next == nil {
		return nil, ErrRead
	}
	r := request.Clone(request.Context())
	r.Header = request.Header.Clone()
	kind := ""
	if t.metadata {
		accept := r.Header.Get("Accept")
		switch {
		case strings.Contains(accept, "as=PartialObjectMetadataList;"):
			kind = "PartialObjectMetadataList"
		case strings.Contains(accept, "as=PartialObjectMetadata;"):
			kind = "PartialObjectMetadata"
		default:
			return nil, ErrRead
		}
		r.Header.Set("Accept", "application/json;as="+kind+";g=meta.k8s.io;v=v1")
	}
	response, err := t.next.RoundTrip(r)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrRead
	}
	defer response.Body.Close()
	// Do not allow client-go to decode, log, or reflect a raw error body.
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, ErrRead
	}
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return nil, ErrRead
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxResponseBytes {
		return nil, ErrRead
	}
	if t.metadata {
		body, err = sanitizedMetadata(body, kind)
		if err != nil {
			return nil, ErrRead
		}
	} else if _, err := boundedJSON(body); err != nil {
		// Check raw syntax before a permissive SDK decoder can collapse
		// duplicate keys or replace invalid UTF-8 in public safety objects.
		return nil, ErrRead
	}
	copyResponse := *response
	copyResponse.Header = http.Header{"Content-Type": []string{"application/json"}}
	copyResponse.Trailer = nil
	copyResponse.Status = strconv.Itoa(response.StatusCode) + " " + http.StatusText(response.StatusCode)
	copyResponse.Body = io.NopCloser(bytes.NewReader(body))
	copyResponse.ContentLength = int64(len(body))
	return &copyResponse, nil
}

// Client-go may log response bytes before decoding. Remove private metadata at
// the transport boundary, not merely after the decoder. In particular, a
// last-applied annotation can contain the original full Secret manifest.
func sanitizedMetadata(body []byte, kind string) ([]byte, error) {
	if !metadataEnvelope(body, kind) {
		return nil, ErrRead
	}
	if kind == "PartialObjectMetadataList" {
		var input metav1.PartialObjectMetadataList
		if strictDecode(body, &input) != nil {
			return nil, ErrRead
		}
		output := metav1.PartialObjectMetadataList{TypeMeta: input.TypeMeta, ListMeta: metav1.ListMeta{ResourceVersion: input.ResourceVersion, Continue: input.Continue, RemainingItemCount: input.RemainingItemCount}, Items: make([]metav1.PartialObjectMetadata, len(input.Items))}
		for i := range input.Items {
			output.Items[i] = metav1.PartialObjectMetadata{TypeMeta: input.Items[i].TypeMeta, ObjectMeta: publicMetadata(&input.Items[i])}
		}
		result, err := json.Marshal(output)
		if err != nil {
			return nil, ErrRead
		}
		return result, nil
	}
	var input metav1.PartialObjectMetadata
	if strictDecode(body, &input) != nil {
		return nil, ErrRead
	}
	result, err := json.Marshal(metav1.PartialObjectMetadata{TypeMeta: input.TypeMeta, ObjectMeta: publicMetadata(&input)})
	if err != nil {
		return nil, ErrRead
	}
	return result, nil
}

// Parse before handing bytes to the metadata decoder. Besides bounding bytes,
// bound depth/nodes and reject duplicate keys, including nested ObjectMeta.
// Only the Kubernetes metadata envelope is allowed; data/stringData/spec/status
// must not be quietly discarded by a permissive PartialObjectMetadata decoder.
func metadataEnvelope(body []byte, kind string) bool {
	v, err := boundedJSON(body)
	return err == nil && metadataObject(v, kind)
}

func boundedJSON(body []byte) (any, error) {
	if !utf8.Valid(body) {
		return nil, ErrRead
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	nodes := 0
	v, err := jsonValue(d, 0, &nodes)
	if err != nil {
		return nil, ErrRead
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrRead
	}
	return v, nil
}

func strictDecode(body []byte, out any) error {
	strictErrors, err := strictjson.UnmarshalStrict(body, out)
	if err != nil || len(strictErrors) != 0 {
		return ErrRead
	}
	return nil
}

func metadataObject(value any, kind string) bool {
	o, ok := value.(map[string]any)
	if !ok || o["kind"] != kind || o["apiVersion"] != "meta.k8s.io/v1" {
		return false
	}
	if _, ok := o["metadata"].(map[string]any); !ok {
		return false
	}
	for key := range o {
		if key != "kind" && key != "apiVersion" && key != "metadata" && (kind != "PartialObjectMetadataList" || key != "items") {
			return false
		}
	}
	if kind == "PartialObjectMetadataList" {
		items, ok := o["items"].([]any)
		// Empty Kubernetes lists may serialize items:null.
		if o["items"] == nil {
			_, ok = o["items"]
		}
		if !ok || len(items) > 10000 {
			return false
		}
		for _, item := range items {
			if !metadataObject(item, "PartialObjectMetadata") {
				return false
			}
		}
	}
	return true
}

func jsonValue(d *json.Decoder, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > 64 || *nodes > 200000 {
		return nil, ErrRead
	}
	t, err := d.Token()
	if err != nil {
		return nil, ErrRead
	}
	switch t {
	case json.Delim('{'):
		result := map[string]any{}
		for d.More() {
			k, err := d.Token()
			key, ok := k.(string)
			if err != nil || !ok {
				return nil, ErrRead
			}
			if _, exists := result[key]; exists {
				return nil, ErrRead
			}
			v, err := jsonValue(d, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result[key] = v
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrRead
		}
		return result, nil
	case json.Delim('['):
		result := []any{}
		for d.More() {
			v, err := jsonValue(d, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result = append(result, v)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrRead
		}
		return result, nil
	default:
		switch t.(type) {
		case string, json.Number, bool, nil:
			return t, nil
		}
		return nil, ErrRead
	}
}
