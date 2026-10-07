// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/transport"
	"k8s.io/klog/v2"
)

const runtimeLogCanary = "PRIVATE-RUNTIME-LOG-CANARY"
const runtimeSaveNameSignature = "If $GENERATE_NEW_SAVE is true, you must specify $SAVE_NAME"

func TestKindRuntimeLogSignature(t *testing.T) {
	for _, test := range []struct{ body, want string }{
		{runtimeSaveNameSignature + "\n", "save-name-required"},
		{runtimeSaveNameSignature + "\r\n", "save-name-required"},
		{runtimeLogCanary + "\n" + runtimeSaveNameSignature + "\n" + runtimeLogCanary, "save-name-required"},
		{runtimeSaveNameSignature, "unknown"},
		{"prefix " + runtimeSaveNameSignature + "\n", "unknown"},
		{runtimeSaveNameSignature + " suffix\n", "unknown"},
		{" " + runtimeSaveNameSignature + "\n", "unknown"},
		{strings.ToLower(runtimeSaveNameSignature) + "\n", "unknown"},
		{"", "unknown"},
		{runtimeSaveNameSignature + "\n" + strings.Repeat("x", kindRuntimeLogLimit), "truncated"},
	} {
		if got := kindRuntimeLogSignature([]byte(test.body)); got != test.want || strings.Contains(got, runtimeLogCanary) {
			t.Fatal("runtime signature classification differs")
		}
	}
}

type runtimeLogRoundTripFunc func(*http.Request) (*http.Response, error)

func (f runtimeLogRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type runtimeLogTestBody struct {
	reader     io.Reader
	closed     bool
	closeError bool
}

type runtimeLogErrorReader struct{}

func (runtimeLogErrorReader) Read(p []byte) (int, error) {
	return copy(p, runtimeSaveNameSignature+"\n"+runtimeLogCanary), errors.New(runtimeLogCanary)
}

func (b *runtimeLogTestBody) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (b *runtimeLogTestBody) Close() error {
	b.closed = true
	if b.closeError {
		return errors.New(runtimeLogCanary)
	}
	return nil
}

func runtimeLogRequest(t *testing.T) *http.Request {
	t.Helper()
	u := "http://cluster.test/api/v1/namespaces/test/pods/test-pod/log?" + (url.Values{"container": {"game"}, "previous": {"true"}, "limitBytes": {"65536"}, "timestamps": {"false"}}).Encode()
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal("cannot construct diagnostic request")
	}
	return r
}

func TestKindRuntimeLogTransportSanitizesBelowInstrumentation(t *testing.T) {
	for _, test := range []struct {
		name, body, want string
		status           int
		err, closeError  bool
	}{
		{"signature", runtimeLogCanary + "\n" + runtimeSaveNameSignature + "\n", "save-name-required", 200, false, false},
		{"unknown", runtimeLogCanary, "unknown", 200, false, false},
		{"non-200", runtimeLogCanary + "\n" + runtimeSaveNameSignature + "\n", "unavailable", 403, false, false},
		{"redirect", runtimeLogCanary, "unavailable", 307, false, false},
		{"error", runtimeLogCanary, "unavailable", 200, true, false},
		{"close-error", runtimeSaveNameSignature + "\n", "unavailable", 200, false, true},
		{"limit", strings.Repeat("x", kindRuntimeLogLimit), "truncated", 200, false, false},
		{"oversized", runtimeSaveNameSignature + "\n" + strings.Repeat("x", 2*kindRuntimeLogLimit), "truncated", 200, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &runtimeLogTestBody{reader: strings.NewReader(test.body), closeError: test.closeError}
			transport := kindRuntimeLogTransport{next: runtimeLogRoundTripFunc(func(*http.Request) (*http.Response, error) {
				var err error
				if test.err {
					err = errors.New(runtimeLogCanary)
				}
				return &http.Response{StatusCode: test.status, Status: runtimeLogCanary, Header: http.Header{"X-Private": {runtimeLogCanary}, "Location": {"http://" + runtimeLogCanary}}, Body: body}, err
			}), host: "cluster.test", path: "/api/v1/namespaces/test/pods/test-pod/log"}
			response, err := transport.RoundTrip(runtimeLogRequest(t))
			if err != nil || response == nil {
				t.Fatal("closed result missing")
			}
			public, err := io.ReadAll(response.Body)
			if err != nil || response.Body.Close() != nil || string(public) != test.want || !body.closed || strings.Contains(response.Status, runtimeLogCanary) || strings.Contains(response.Header.Get("X-Private"), runtimeLogCanary) || response.Header.Get("Location") != "" {
				t.Fatal("raw output escaped below-wrapper sanitization")
			}
		})
	}
}

func TestKindRuntimeLogTransportRejectsUnboundedRequests(t *testing.T) {
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Method = "POST" },
		func(r *http.Request) { r.URL.Host = "other.test" },
		func(r *http.Request) { r.URL.Path += "/other" },
		func(r *http.Request) { r.URL.RawQuery += "&follow=true" },
		func(r *http.Request) { r.URL.RawQuery = "container=game" },
		func(r *http.Request) { r.URL.User = url.User(runtimeLogCanary) },
	} {
		called := false
		transport := kindRuntimeLogTransport{next: runtimeLogRoundTripFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, errors.New(runtimeLogCanary) }), host: "cluster.test", path: "/api/v1/namespaces/test/pods/test-pod/log"}
		request := runtimeLogRequest(t)
		change(request)
		_, err := transport.RoundTrip(request)
		if called || err == nil || strings.Contains(err.Error(), runtimeLogCanary) {
			t.Fatal("unexpected diagnostic request escaped")
		}
	}
}

func TestKindRuntimeLogTransportPartialReadIsNotEvidence(t *testing.T) {
	body := &runtimeLogTestBody{reader: runtimeLogErrorReader{}}
	transport := kindRuntimeLogTransport{next: runtimeLogRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body}, nil
	}), host: "cluster.test", path: "/api/v1/namespaces/test/pods/test-pod/log"}
	response, err := transport.RoundTrip(runtimeLogRequest(t))
	if err != nil {
		t.Fatal("closed read error result missing")
	}
	result, err := io.ReadAll(response.Body)
	if err != nil || response.Body.Close() != nil || string(result) != "unavailable" || !body.closed {
		t.Fatal("partial read classified as evidence")
	}
}

func TestKindRuntimeLogTransportWithEnabledOuterInstrumentation(t *testing.T) {
	sink := &runtimeLogCapture{}
	request := runtimeLogRequest(t).WithContext(klog.NewContext(context.Background(), logr.New(sink)))
	next := runtimeLogRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Status: runtimeLogCanary, Header: http.Header{"X-Private": {runtimeLogCanary}}, Body: io.NopCloser(strings.NewReader(runtimeLogCanary + "\n" + runtimeSaveNameSignature + "\n"))}, nil
	})
	debug := func(next http.RoundTripper) http.RoundTripper {
		return transport.NewDebuggingRoundTripper(next, transport.DebugResponseHeaders, transport.DebugResponseStatus)
	}
	// Real outer instrumentation sees arbitrary upstream status/header values
	// without the sanitizer; this positive control proves it is enabled.
	response, err := debug(next).RoundTrip(request)
	if err != nil || response.Body.Close() != nil || !sink.containsCanary() {
		t.Fatal("outer instrumentation positive control failed")
	}
	sink.reset()
	response, err = debug(kindRuntimeLogTransport{next, "cluster.test", "/api/v1/namespaces/test/pods/test-pod/log"}).RoundTrip(request)
	if err != nil {
		t.Fatal("outer diagnostic unavailable")
	}
	result, err := io.ReadAll(response.Body)
	if err != nil || response.Body.Close() != nil || string(result) != "save-name-required" || sink.containsCanary() {
		t.Fatal("sanitizer leaked to enabled outer instrumentation")
	}
}

type runtimeLogCapture struct {
	mu   sync.Mutex
	text strings.Builder
}

func (s *runtimeLogCapture) Init(logr.RuntimeInfo) {}
func (s *runtimeLogCapture) Enabled(int) bool      { return true }
func (s *runtimeLogCapture) Info(_ int, message string, values ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = fmt.Fprint(&s.text, message, values)
}
func (s *runtimeLogCapture) Error(err error, message string, values ...any) {
	s.Info(0, message, append(values, err)...)
}
func (s *runtimeLogCapture) WithValues(...any) logr.LogSink { return s }
func (s *runtimeLogCapture) WithName(string) logr.LogSink   { return s }
func (s *runtimeLogCapture) containsCanary() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Contains(s.text.String(), runtimeLogCanary)
}
func (s *runtimeLogCapture) reset() { s.mu.Lock(); defer s.mu.Unlock(); s.text.Reset() }

func TestKindRuntimeLogDiagnosticQuietSDKAndOuterInstrumentation(t *testing.T) {
	// No parallel tests: capture/restore the global logger and verbosity. First
	// prove the real SDK instrumentation can expose our private Pod body, then
	// exercise the production diagnostic boundary under those same settings.
	state := klog.CaptureState()
	defer state.Restore()
	flags := flag.NewFlagSet("runtime-diagnostic-logging", flag.ContinueOnError)
	klog.InitFlags(flags)
	if flags.Set("v", "9") != nil {
		t.Fatal("cannot enable logging control")
	}
	klog.EnableContextualLogging(true)
	sink := &runtimeLogCapture{}
	klog.SetLoggerWithOptions(logr.New(sink), klog.ContextualLogger(true))
	original, image := runtimeLogPod()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("X-Private", runtimeLogCanary)
		if strings.HasSuffix(r.URL.Path, "/log") {
			_, _ = io.WriteString(w, runtimeLogCanary+"\n"+runtimeSaveNameSignature+"\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(original)
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal("cannot construct real SDK")
	}
	get := func(ctx context.Context) (*corev1.Pod, error) {
		return client.CoreV1().Pods("test").Get(ctx, "test-pod", metav1.GetOptions{})
	}
	if _, err := get(context.Background()); err != nil || !sink.containsCanary() {
		t.Fatal("high-verbosity private-body positive control failed")
	}
	sink.reset()
	requests.Store(0)
	result := kindRuntimeLogDiagnostic(context.Background(), config, original, image, get)
	if result != " logs=[current=save-name-required previous=save-name-required]" || sink.containsCanary() || requests.Load() != 4 {
		t.Fatalf("SDK/outer boundary failed: category=%s private=%t requests=%d", result, sink.containsCanary(), requests.Load())
	}
	// If process settings ignore context loggers, refusal is safer than making
	// private Pod GETs with a silently ineffective quiet context.
	klog.EnableContextualLogging(false)
	requests.Store(0)
	result = kindRuntimeLogDiagnostic(context.Background(), config, original, image, get)
	if result != " logs=[current=unavailable previous=unavailable]" || requests.Load() != 0 {
		t.Fatal("ignored quiet context exposed diagnostic reads")
	}
}

func TestKindRuntimeLogDiagnosticCancellation(t *testing.T) {
	original, image := runtimeLogPod()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	result := kindRuntimeLogDiagnostic(ctx, &rest.Config{Host: server.URL}, original, image, func(context.Context) (*corev1.Pod, error) { return original.DeepCopy(), nil })
	if result != " logs=[current=unavailable previous=unavailable]" || time.Since(start) > 2*time.Second {
		t.Fatal("cancelled reader was unbounded or produced evidence")
	}
}

func TestKindRuntimeLogClientRefusesExternalProviders(t *testing.T) {
	for _, config := range []*rest.Config{
		{Host: "http://cluster.test", ExecProvider: &clientcmdapi.ExecConfig{Command: runtimeLogCanary}},
		{Host: "http://cluster.test", AuthProvider: &clientcmdapi.AuthProviderConfig{Name: runtimeLogCanary}},
		{Host: "http://cluster.test", WrapTransport: func(r http.RoundTripper) http.RoundTripper { return r }},
		{Host: "http://cluster.test/private"},
	} {
		client, endpoint, err := kindRuntimeLogClient(config, "test", "test-pod")
		if err == nil || client != nil || endpoint != nil || strings.Contains(err.Error(), runtimeLogCanary) {
			t.Fatal("unsupported transport escaped quiet boundary")
		}
	}
}

func runtimeLogPod() (*corev1.Pod, string) {
	image := "ghcr.io/gobha-me/arcadectl-factorio@sha256:" + strings.Repeat("a", 64)
	now := metav1.NewTime(time.Date(2026, 10, 7, 1, 0, 0, 0, time.UTC))
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "test", UID: types.UID("original-pod"), CreationTimestamp: now}, Spec: corev1.PodSpec{NodeName: "owned-node", Containers: []corev1.Container{{Name: "game", Image: image}}}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "game", ImageID: "docker-pullable://" + image, ContainerID: runtimeLogCanary, RestartCount: 1, LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, StartedAt: now, FinishedAt: now, Message: runtimeLogCanary}}}}}}, image
}

func TestKindRuntimeLogDiagnosticCorrelatesBothReads(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*corev1.Pod)
	}{
		{"stable", nil},
		{"uid", func(p *corev1.Pod) { p.UID = "replacement" }},
		{"image", func(p *corev1.Pod) { p.Spec.Containers[0].Image = runtimeLogCanary }},
		{"image-id", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ImageID = runtimeLogCanary }},
		{"container-id", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ContainerID += "-new" }},
		{"restart", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].RestartCount++ }},
		{"termination-time", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].LastTerminationState.Terminated.FinishedAt.Time = p.Status.ContainerStatuses[0].LastTerminationState.Terminated.FinishedAt.Add(time.Second)
		}},
		{"termination-exit", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].LastTerminationState.Terminated.ExitCode++ }},
		{"node", func(p *corev1.Pod) { p.Spec.NodeName = "other-node" }},
		{"deletion", func(p *corev1.Pod) { p.DeletionTimestamp = &p.CreationTimestamp }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count := requests.Add(1)
				if r.URL.Path != "/api/v1/namespaces/test/pods/test-pod/log" || r.Method != "GET" || r.URL.Query().Get("limitBytes") != "65536" || r.URL.Query().Get("container") != "game" || r.Header.Get("Authorization") != "Bearer "+runtimeLogCanary {
					t.Error("bounded authenticated request differs")
				}
				if count == 1 && r.URL.Query().Get("previous") != "false" || count == 2 && r.URL.Query().Get("previous") != "true" {
					t.Error("current/previous sequence differs")
				}
				w.Header().Set("X-Private", runtimeLogCanary)
				_, _ = io.WriteString(w, runtimeLogCanary+"\n"+runtimeSaveNameSignature+"\n")
			}))
			defer server.Close()
			original, image := runtimeLogPod()
			gets := 0
			get := func(context.Context) (*corev1.Pod, error) {
				gets++
				fresh := original.DeepCopy()
				if gets == 2 && test.change != nil {
					test.change(fresh)
				}
				return fresh, nil
			}
			result := kindRuntimeLogDiagnostic(context.Background(), &rest.Config{Host: server.URL, BearerToken: runtimeLogCanary}, original, image, get)
			want := " logs=[current=save-name-required previous=save-name-required]"
			if test.change != nil {
				want = " logs=[current=uncorrelated previous=uncorrelated]"
			}
			if result != want || requests.Load() != 2 || gets != 2 || strings.Contains(result, runtimeLogCanary) {
				t.Fatal("uncorrelated or private runtime evidence escaped")
			}
		})
	}
}

func TestKindRuntimeLogDiagnosticRefusesBeforeRead(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, runtimeLogCanary)
	}))
	defer server.Close()
	original, image := runtimeLogPod()
	for _, test := range []struct {
		name string
		get  func(context.Context) (*corev1.Pod, error)
	}{
		{"get-error", func(context.Context) (*corev1.Pod, error) { return nil, errors.New(runtimeLogCanary) }},
		{"replacement", func(context.Context) (*corev1.Pod, error) {
			p := original.DeepCopy()
			p.UID = "replacement"
			return p, nil
		}},
		{"missing", func(context.Context) (*corev1.Pod, error) { return nil, nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := kindRuntimeLogDiagnostic(context.Background(), &rest.Config{Host: server.URL}, original, image, test.get)
			if result != " logs=[current=unavailable previous=unavailable]" || requests.Load() != 0 {
				t.Fatal("unproved original authorized log read")
			}
		})
	}
}
