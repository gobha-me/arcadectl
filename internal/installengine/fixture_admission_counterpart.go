// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-logr/logr"
	"github.com/gobha-me/arcadectl/internal/installstate"
	strictjson "sigs.k8s.io/json"
)

// A bare 404 from a proxy, wrapper or another route is not absence evidence.
func fixtureCounterpartNotFound(response *http.Response, key installstate.Key) bool {
	if response == nil || response.StatusCode != http.StatusNotFound || response.Body == nil {
		return false
	}
	typ, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) == 0 || len(body) > 65536 || !utf8.Valid(body) || !boundedJSON(body) {
		return false
	}
	var fields map[string]any
	strict, err := strictjson.UnmarshalStrict(body, &fields)
	_, plural, pathErr := fixturePath(key, false)
	if err != nil || len(strict) != 0 || pathErr != nil {
		return false
	}
	group, _, grouped := strings.Cut(key.APIVersion, "/")
	details := map[string]any{"name": key.Name, "kind": plural}
	resource := plural
	if grouped {
		details["group"] = group
		resource += "." + group
	}
	want := map[string]any{
		"apiVersion": "v1", "kind": "Status", "metadata": map[string]any{},
		"status": "Failure", "reason": "NotFound", "code": int64(404),
		"message": fmt.Sprintf("%s %q not found", resource, key.Name), "details": details,
	}
	return reflect.DeepEqual(fields, want)
}

// Caller holds wireMu. The address can ONLY be derived from the closed case
// constructor. Full phase LIST/GC observations bracket these named reads in the
// driver; neither a GET alone nor matching generated metadata can confer a bit.
func (w *fixtureWire) counterpartAbsentLocked(ctx context.Context, number fixtureAdmissionCase, phase *fixturePhaseObservation) error {
	r, err := w.admissionRequest(number, phase)
	if err != nil || r.slot != -1 || r.operation != probeCreateOperation || w.current(ctx) != nil {
		return ErrFixtures
	}
	key := fixtureObjectKey(r.object)
	permission, err := fixturePermission(key, "get")
	parent := w.actors.admission.prerequisites.access
	discovery, discoveryErr := parent.discover(ctx, key.APIVersion)
	if err != nil || discoveryErr != nil || !discoveredPermission(discovery, permission) || parent.authorize(ctx, permission.spec) != nil || w.current(ctx) != nil {
		return ErrFixtures
	}
	a := w.clients[0]
	if a == nil || a.base == nil || a.client == nil || parent.frozen == nil {
		return ErrFixtures
	}
	path, _, err := fixturePath(key, false)
	if err != nil {
		return ErrFixtures
	}
	identity := fixtureWireIdentity{namespace: key.Namespace}
	c := parent.frozen
	if c.BearerToken != "" {
		identity.authorization = "Bearer " + c.BearerToken
	} else if c.Username != "" || c.Password != "" {
		identity.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
	}
	u := *a.base
	u.Path, u.RawQuery = strings.TrimRight(u.Path, "/")+path, ""
	capture := &fixtureCapture{identity: identity, method: http.MethodGet, url: u.String(), key: key, strictNotFound: true}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = logr.NewContext(ctx, logr.Discard())
	ctx = context.WithValue(ctx, attemptKey{}, &requestAttempt{method: http.MethodGet, fixture: capture})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), bytes.NewReader(nil))
	if err != nil {
		return ErrFixtures
	}
	request.GetBody = nil
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, requestErr := a.client.Do(request)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if requestErr != nil || !capture.success || !capture.notFound || capture.result != nil || w.current(ctx) != nil {
		return ErrFixtures
	}
	return nil
}
