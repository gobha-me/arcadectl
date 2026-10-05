// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/spdystream"
	"github.com/moby/spdystream/spdy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

// Test-only stock server proves wire compatibility independently of our frame
// state machine. Production imports only its bounded codec, not this manager.
func nativeForwardFixture(t *testing.T, x *servingFixture, mode string, onUpgrade func()) (*HTTPAccess, *atomic.Int32) {
	t.Helper()
	posts := &atomic.Int32{}
	var mu sync.Mutex
	var peers []net.Conn
	var completions []chan struct{}
	const fakeKubeToken = "TEST-ONLY-KUBE-BEARER"
	dialTarget := x.activation.dial
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		podPath := "/api/v1/namespaces/" + x.f.plan.Namespace() + "/pods/" + x.access.pod.Name
		switch mode {
		case "basic-auth":
			user, password, ok := r.BasicAuth()
			if !ok || user != "test-only-user" || password != "test-only-password" {
				t.Error("static basic authority lost")
			}
		case "client-cert":
			if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 || r.Header.Get("Authorization") != "" {
				t.Error("static client certificate lost")
			}
		default:
			if r.Header.Get("Authorization") != "Bearer "+fakeKubeToken {
				t.Error("frozen cluster authentication lost")
			}
		}
		if r.Method == http.MethodGet && r.URL.Path == podPath {
			pod := x.access.pod.DeepCopy()
			if mode == "foreign-pod" {
				pod.UID = "foreign"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pod)
			return
		}
		posts.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != podPath+"/portforward" || r.URL.RawQuery != "ports=8443" || r.Header.Get("Upgrade") != "SPDY/3.1" || r.Header.Get("X-Stream-Protocol-Version") != "portforward.k8s.io" {
			t.Error("forward request escaped fixed original Pod/port/protocol")
			w.WriteHeader(400)
			return
		}
		if onUpgrade != nil {
			onUpgrade()
		}
		switch mode {
		case "rejection":
			w.WriteHeader(503)
			_, _ = io.WriteString(w, strings.Repeat("PRIVATE-ERROR-CANARY", 4096))
			return
		case "redirect":
			w.Header().Set("Location", "https://private.invalid/PRIVATE-CANARY")
			w.WriteHeader(307)
			return
		}
		peer, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error("fixture hijack")
			return
		}
		done := make(chan struct{})
		mu.Lock()
		peers = append(peers, peer)
		completions = append(completions, done)
		mu.Unlock()
		defer close(done)
		defer peer.Close()
		protocol := "portforward.k8s.io"
		if mode == "wrong-protocol" {
			protocol = "foreign"
		}
		if mode == "stalled-header" {
			_, _ = io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\n")
			_ = rw.Flush()
			_, _ = io.Copy(io.Discard, peer)
			return
		}
		_, _ = io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Stream-Protocol-Version: "+protocol+"\r\n")
		if mode == "oversize-header" {
			_, _ = io.WriteString(rw, "X-Long: "+strings.Repeat("x", 9000)+"\r\n")
		}
		if mode == "transfer-encoding" {
			_, _ = io.WriteString(rw, "Transfer-Encoding: chunked\r\n")
		}
		if mode == "empty-content-length" {
			_, _ = io.WriteString(rw, "Content-Length: \r\n")
		}
		for key, match := range map[string]string{"Content-Length": "content-length", "Connection": "duplicate-connection", "Upgrade": "duplicate-upgrade", "X-Stream-Protocol-Version": "duplicate-protocol"} {
			if mode == match {
				_, _ = io.WriteString(rw, key+": 0\r\n")
			}
		}
		_, _ = io.WriteString(rw, "\r\n")
		if rw.Flush() != nil {
			return
		}
		if mode == "wrong-protocol" || mode == "oversize-header" || mode == "transfer-encoding" || mode == "no-ack" || strings.HasPrefix(mode, "duplicate-") || mode == "content-length" || mode == "empty-content-length" {
			_, _ = io.Copy(io.Discard, peer)
			return
		}
		backend, err := spdystream.NewConnection(peer, true)
		if err != nil {
			t.Error("fixture backend")
			return
		}
		var workers sync.WaitGroup
		var targets []net.Conn
		var targetMu sync.Mutex
		backend.Serve(func(stream *spdystream.Stream) {
			id := stream.Identifier()
			kind := stream.Headers().Get(corev1.StreamType)
			if stream.Headers().Get(corev1.PortHeader) != "8443" || stream.Headers().Get(corev1.PortForwardRequestIDHeader) != "0" || id == 1 && kind != corev1.StreamTypeError || id == 3 && kind != corev1.StreamTypeData || id != 1 && id != 3 {
				t.Error("native streams differ from reviewed pair")
				return
			}
			if stream.SendReply(http.Header{}, false) != nil {
				return
			}
			if id == 1 {
				workers.Add(1)
				go func() { defer workers.Done(); _, _ = io.Copy(io.Discard, stream) }()
				return
			}
			if mode == "data-error" {
				_ = stream.Reset()
				return
			}
			if mode == "pre-data" {
				_, _ = stream.Write([]byte("bounded-test-data"))
				return
			}
			target, err := dialTarget(context.Background(), &Serving{namespace: x.f.plan.Namespace(), podUID: "original-pod", address: "10.244.0.10"})
			if err != nil {
				t.Error("owned target")
				return
			}
			targetMu.Lock()
			targets = append(targets, target)
			targetMu.Unlock()
			workers.Add(2)
			go func() { defer workers.Done(); _, _ = io.CopyBuffer(target, stream, make([]byte, 32768)) }()
			go func() {
				defer workers.Done()
				_, _ = io.CopyBuffer(stream, target, make([]byte, 32768))
				_ = stream.Close()
			}()
		})
		_ = peer.Close()
		targetMu.Lock()
		for _, target := range targets {
			_ = target.Close()
		}
		targetMu.Unlock()
		workers.Wait()
	}))
	if mode == "client-cert" {
		server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	}
	server.StartTLS()
	t.Cleanup(func() {
		mu.Lock()
		for _, peer := range peers {
			_ = peer.Close()
		}
		finished := append([]chan struct{}{}, completions...)
		mu.Unlock()
		server.Close()
		for _, done := range finished {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("owned native backend did not drain")
			}
		}
	})
	config := serverConfig(server)
	config.BearerToken = fakeKubeToken
	if mode == "basic-auth" {
		config.BearerToken = ""
		config.Username, config.Password = "test-only-user", "test-only-password"
	}
	if mode == "client-cert" {
		var err error
		config.BearerToken = ""
		config.CertData, err = os.ReadFile(x.tls.CertificateFile)
		if err != nil {
			t.Fatal(err)
		}
		config.KeyData, err = os.ReadFile(x.tls.KeyFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	provider, err := NewHTTPAccess(config)
	if err != nil {
		t.Fatal(err)
	}
	return provider, posts
}

func TestNativeForwardingCancellationDrainsEstablishedPumps(t *testing.T) {
	for _, mode := range []string{"success", "pre-data"} {
		t.Run(mode, func(t *testing.T) {
			x := newServingFixture(t)
			requests := activationServer(t, x, x.f.plan.Namespace(), nil)
			provider, _ := nativeForwardFixture(t, x, mode, nil)
			s, err := x.f.engine.ObserveServing(context.Background(), x.f.snapshot, x.access)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn, err := provider.forwardPod(ctx, s)
			if err != nil {
				t.Fatal(err)
			}
			session := conn.(*forwardConn).session
			cancel()
			select {
			case <-session.done:
			case <-time.After(2 * time.Second):
				t.Fatal("established pump did not drain")
			}
			if err := conn.Close(); err != nil || requests.Load() != 0 {
				t.Fatal("cancel did not join or prematurely authenticated")
			}
		})
	}
}

type signaledWriteConn struct {
	net.Conn
	armed   atomic.Bool
	blocked chan struct{}
	once    sync.Once
}

func (c *signaledWriteConn) Write(p []byte) (int, error) {
	if c.armed.Load() {
		c.once.Do(func() { close(c.blocked) })
	}
	return c.Conn.Write(p)
}

func TestNativeForwardingCancellationHardClosesBlockedProtocolWrite(t *testing.T) {
	left, right := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &signaledWriteConn{Conn: left, blocked: make(chan struct{})}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer right.Close()
		codec, err := spdy.NewFramer(right, right)
		if err != nil {
			return
		}
		for _, id := range []spdy.StreamId{1, 3} {
			frame, err := codec.ReadFrame()
			if err != nil {
				return
			}
			syn, ok := frame.(*spdy.SynStreamFrame)
			if !ok || syn.StreamId != id {
				return
			}
			if codec.WriteFrame(&spdy.SynReplyFrame{StreamId: id, Headers: http.Header{}}) != nil {
				return
			}
			if id == 1 {
				if _, err := codec.ReadFrame(); err != nil {
					return
				}
			}
		}
		// Deliberately never read any data: first DATA header write blocks on
		// this net.Pipe, unlike an OS socket which might buffer megabytes.
		<-ctx.Done()
	}()
	conn, err := startForward(ctx, writer, writer)
	if err != nil {
		t.Fatal(err)
	}
	writer.armed.Store(true)
	producer := make(chan struct{})
	go func() {
		defer close(producer)
		_, _ = conn.Write([]byte("bounded-test-data"))
	}()
	select {
	case <-writer.blocked:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("fixture write never blocked")
	}
	cancel()
	for _, done := range []<-chan struct{}{conn.(*forwardConn).session.done, producer, serverDone} {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("blocked protocol worker leaked")
		}
	}
	if conn.Close() != nil {
		t.Fatal("joined connection close")
	}
}

func TestForwardedActivationUsesNativeProtocolAndRealHTTPSIdentity(t *testing.T) {
	for _, mode := range []string{"success", "basic-auth", "client-cert"} {
		t.Run(mode, func(t *testing.T) {
			x := newServingFixture(t)
			requests := activationServer(t, x, x.f.plan.Namespace(), nil)
			provider, posts := nativeForwardFixture(t, x, mode, nil)
			if err := x.activation.VerifyForwarded(context.Background(), x.f.snapshot, x.options, provider); err != nil {
				t.Fatal("forwarded activation", err)
			}
			if posts.Load() != 1 || requests.Load() != 1 || x.secrets.writes != 2 {
				t.Fatal("native route retried, skipped auth or mutated Secrets")
			}
		})
	}
}

func TestNativeForwardingRejectsSubstitutionAndUnsafeUpgrade(t *testing.T) {
	for _, mode := range []string{"foreign-pod", "rejection", "redirect", "wrong-protocol", "oversize-header", "transfer-encoding", "content-length", "empty-content-length", "duplicate-connection", "duplicate-upgrade", "duplicate-protocol", "data-error", "drift-on-upgrade"} {
		t.Run(mode, func(t *testing.T) {
			x := newServingFixture(t)
			requests := activationServer(t, x, x.f.plan.Namespace(), nil)
			var hook func()
			if mode == "drift-on-upgrade" {
				var changed atomic.Bool
				hook = func() { changed.Store(true) }
				x.access.onPod = func() {
					if changed.Load() {
						x.access.pod.ResourceVersion = "11"
					}
				}
			}
			provider, posts := nativeForwardFixture(t, x, mode, hook)
			if err := x.activation.VerifyForwarded(context.Background(), x.f.snapshot, x.options, provider); !errors.Is(err, ErrActivation) || err.Error() != ErrActivation.Error() || requests.Load() != 0 {
				t.Fatal("unsafe upgrade reached authentication")
			}
			want := int32(1)
			if mode == "foreign-pod" {
				want = 0
			}
			if posts.Load() != want {
				t.Fatal("upgrade retried or adopted replacement")
			}
		})
	}
}

func TestNativeForwardingNeverDropsConfiguredAuthorityOrTransport(t *testing.T) {
	for _, mode := range []string{"user", "uid", "groups", "extra", "wrapper", "dial", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			x := newServingFixture(t)
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
			defer server.Close()
			config := serverConfig(server)
			switch mode {
			case "user":
				config.Impersonate.UserName = "bounded-test-user"
			case "uid":
				config.Impersonate.UID = "bounded-test-uid"
			case "groups":
				config.Impersonate.Groups = []string{"bounded-test-group"}
			case "extra":
				config.Impersonate.Extra = map[string][]string{"reviewed": {"value"}}
			case "wrapper":
				config.WrapTransport = func(next http.RoundTripper) http.RoundTripper { return next }
			case "dial":
				config.Dial = (&net.Dialer{}).DialContext
			case "proxy":
				config.Proxy = http.ProxyFromEnvironment
			}
			provider, err := NewHTTPAccess(rest.CopyConfig(config))
			if err != nil {
				t.Fatal(err)
			}
			if provider.native != nil || !errors.Is(x.activation.VerifyForwarded(context.Background(), x.f.snapshot, x.options, provider), ErrActivation) || requests.Load() != 0 {
				t.Fatal("native route silently dropped configured authority/transport")
			}
		})
	}
}

func TestNativeForwardingCancellationDrainsUnacknowledgedSession(t *testing.T) {
	for _, mode := range []string{"no-ack", "stalled-header"} {
		t.Run(mode, func(t *testing.T) {
			x := newServingFixture(t)
			provider, posts := nativeForwardFixture(t, x, mode, nil)
			s, err := x.f.engine.ObserveServing(context.Background(), x.f.snapshot, x.access)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			conn, err := provider.forwardPod(ctx, s)
			if !errors.Is(err, ErrActivation) || conn != nil || posts.Load() != 1 || time.Since(start) > 2*time.Second {
				t.Fatal("cancelled acknowledgement leaked or retried")
			}
		})
	}
}
