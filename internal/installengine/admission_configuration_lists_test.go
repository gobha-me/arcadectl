// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var admissionConfigurationTestPaths = [][]string{
	{"/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies"},
	{"/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings"},
}

type admissionConfigurationGateBody struct {
	io.ReadCloser
	ctx              context.Context
	entered, release chan struct{}
	once             sync.Once
	closed           *atomic.Int32
}

func (b *admissionConfigurationGateBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-b.release:
		return b.ReadCloser.Read(p)
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	}
}

func (b *admissionConfigurationGateBody) Close() error {
	b.closed.Add(1)
	return b.ReadCloser.Close()
}

func TestAdmissionConfigurationListsKeepMembershipAndClosingJoin(t *testing.T) {
	f, _, _, _, invoke := testAdmissionReadCatalog(t, "configuration")
	access := f.admission.prerequisites.access
	next := access.client.Transport
	var calls [2]atomic.Int32
	var fences, closed atomic.Int32
	var entered, release [2]chan struct{}
	var once [2]sync.Once
	for i := range 2 {
		entered[i], release[i] = make(chan struct{}), make(chan struct{})
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan error, 1)
	joined := false
	defer func() {
		cancel()
		for i := range 2 {
			once[i].Do(func() { close(release[i]) })
		}
		if !joined {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("configuration readers leaked")
			}
		}
	}()
	access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		group := -1
		for i, paths := range admissionConfigurationTestPaths {
			if r.URL.Path == paths[0] {
				group = i
			}
		}
		if group < 0 {
			if fences.Add(1) > 2 && closed.Load() != 2 {
				t.Error("closing original fence escaped a body reader")
			}
			return next.RoundTrip(r)
		}
		if !testRuntimeConfigurationRequest(r) || calls[group].Add(1) != 1 {
			t.Error("configuration replayed or changed its collection")
		}
		response, err := next.RoundTrip(r)
		if err == nil && response != nil && response.Body != nil {
			response.Body = &admissionConfigurationGateBody{ReadCloser: response.Body, ctx: r.Context(), entered: entered[group], release: release[group], closed: &closed}
		}
		return response, err
	})
	go func() { done <- invoke(ctx) }()
	for _, ready := range entered {
		select {
		case <-ready:
		case <-done:
			joined = true
			t.Fatal("configuration returned before both body reads")
		case <-ctx.Done():
			t.Fatal("configuration bodies did not overlap")
		}
	}
	once[0].Do(func() { close(release[0]) })
	select {
	case <-done:
		joined = true
		t.Fatal("configuration escaped delayed second body")
	case <-time.After(100 * time.Millisecond):
	}
	once[1].Do(func() { close(release[1]) })
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("complete original membership refused", err)
		}
	case <-ctx.Done():
		t.Fatal("configuration did not join")
	}
	if calls[0].Load() != 1 || calls[1].Load() != 1 || fences.Load() != 4 || closed.Load() != 2 {
		t.Fatal("configuration changed reads, body ownership or original fences")
	}
}

func TestAdmissionConfigurationListsCancelAndJoinEveryReader(t *testing.T) {
	for _, mode := range []string{"request", "body", "caller"} {
		for refused := range 2 {
			if mode == "caller" && refused != 0 {
				continue
			}
			t.Run(mode+"/"+strconv.Itoa(refused), func(t *testing.T) {
				f, _, _, _, invoke := testAdmissionReadCatalog(t, "configuration")
				refusedLane := refused
				if mode == "caller" {
					refusedLane = -1
				}
				testNamedReadLaneRefusal(t, f.admission.prerequisites.access, admissionConfigurationTestPaths, mode, refusedLane, 2, ErrAdmission, invoke)
			})
		}
	}
}

func TestAdmissionConfigurationListsFreezeEveryTemplateBeforeReads(t *testing.T) {
	f, _, _, _, invoke := testAdmissionReadCatalog(t, "configuration")
	removed := false
	for _, resource := range f.request.Snapshot.Document().Resources {
		if resource.Key.Kind == "ValidatingAdmissionPolicyBinding" {
			delete(f.admission.prerequisites.engine.templates[resource.Key], resource.TemplateSHA256)
			removed = true
			break
		}
	}
	if !removed {
		t.Fatal("original binding fixture absent")
	}
	var lists atomic.Int32
	access := f.admission.prerequisites.access
	next := access.client.Transport
	access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if testRuntimeConfigurationRequest(r) {
			lists.Add(1)
		}
		return next.RoundTrip(r)
	})
	if err := invoke(t.Context()); err != ErrAdmission || lists.Load() != 0 {
		t.Fatal("incomplete signed catalog reached a LIST")
	}
}

func TestAdmissionConfigurationListsRejectUnboundPurposeActorAndRoutes(t *testing.T) {
	access, expected, requests := testConfigurationListFixture(t, "ValidatingAdmissionPolicy", runtimeConfigurationList, func(w http.ResponseWriter, _ *http.Request, page map[string]any, _ int) {
		_ = json.NewEncoder(w).Encode(page)
	})
	for _, kind := range []string{"Secret", "Deployment", "", "ValidatingAdmissionPolicyList", "../validatingadmissionpolicies"} {
		if result, err := access.listRuntimeConfiguration(t.Context(), kind, expected); err != ErrInvalid || result != nil {
			t.Fatal("unbound runtime route accepted")
		}
	}
	if result, err := access.listConfiguration(t.Context(), "ValidatingAdmissionPolicy", expected, configurationListPurpose(255)); err != ErrInvalid || result != nil {
		t.Fatal("unbound purpose accepted")
	}
	access.actor = &actorWireIdentity{}
	if result, err := access.listRuntimeConfiguration(t.Context(), "ValidatingAdmissionPolicy", expected); err != ErrInvalid || result != nil {
		t.Fatal("actor gained runtime LIST")
	}
	access.actor = nil
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := access.listRuntimeConfiguration(ctx, "ValidatingAdmissionPolicy", expected); err != ErrRead || result != nil {
		t.Fatal("cancelled LIST accepted")
	}
	parent, err := NewHTTPAccess(access.frozen)
	if err != nil {
		t.Fatal("non-direct parent constructor refused")
	}
	if result, err := parent.listBaselineConfiguration(t.Context(), "ValidatingAdmissionPolicy", expected); err != ErrInvalid || result != nil {
		t.Fatal("baseline lost direct-parent guard")
	}
	for _, absent := range []string{"client", "base"} {
		copy := *parent
		if absent == "client" {
			copy.client = nil
		} else {
			copy.base = nil
		}
		if result, err := copy.listRuntimeConfiguration(t.Context(), "ValidatingAdmissionPolicy", expected); err != ErrRead || result != nil {
			t.Fatal("missing parent transport produced evidence")
		}
	}
	if requests.Load() != 0 {
		t.Fatal("refused route attempted HTTP")
	}
	if result, err := parent.listRuntimeConfiguration(t.Context(), "ValidatingAdmissionPolicy", expected); err != nil || len(result) != 6 || requests.Load() != 1 {
		t.Fatal("non-direct runtime observer compatibility lost")
	}
}
