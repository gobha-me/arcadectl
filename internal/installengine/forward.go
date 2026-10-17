// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/moby/spdystream/spdy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

type nativeTLS struct {
	tls                        *tls.Config
	bearer, username, password string
}

// TLS Close may try to send close_notify. Abort must first close the actual
// socket so cancellation cannot wait for a peer to drain protocol writes.
func hardClose(conn net.Conn) {
	if secure, ok := conn.(*tls.Conn); ok {
		_ = secure.NetConn().Close()
	}
	_ = conn.Close()
}

// Only frozen direct static auth is supported. Do not silently drop
// impersonation or trusted custom transport behavior on the raw upgrade path.
func nativeTransport(c *rest.Config) *nativeTLS {
	if c == nil || c.WrapTransport != nil || c.Proxy != nil || c.Dial != nil || c.Impersonate.UserName != "" || c.Impersonate.UID != "" || len(c.Impersonate.Groups) != 0 || len(c.Impersonate.Extra) != 0 {
		return nil
	}
	config, err := rest.TLSConfigFor(c)
	if err != nil {
		return nil
	}
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}
	config.MinVersion = tls.VersionTLS12
	config.NextProtos = []string{"http/1.1"}
	return &nativeTLS{tls: config, bearer: c.BearerToken, username: c.Username, password: c.Password}
}

// The budget precedes HTTP parser allocations. Its buffered reader preserves
// frames prefetched with the upgrade headers when the limit is disabled.
type headerBudget struct {
	reader    io.Reader
	remaining int
	enabled   bool
}

func (r *headerBudget) Read(p []byte) (int, error) {
	if r.enabled {
		if r.remaining <= 0 {
			return 0, ErrActivation
		}
		if len(p) > r.remaining {
			p = p[:r.remaining]
		}
	}
	n, err := r.reader.Read(p)
	if r.enabled {
		r.remaining -= n
	}
	return n, err
}

func (a *HTTPAccess) forwardPod(ctx context.Context, s *Serving) (net.Conn, error) {
	if a == nil || a.native == nil || a.base == nil || ctx == nil || s == nil || s.engine == nil || !addressPart(s.namespace) || !addressPart(s.podName) || !receiptUID.MatchString(string(s.podUID)) {
		return nil, ErrActivation
	}
	// Kubernetes exposes no UID precondition on PodPortForwardOptions. Pin
	// the original uncached Pod, then Activation repeats whole serving proof
	// before TLS/bearer transmission and after authentication.
	pod, err := a.Serving().GetPod(ctx, s.namespace, s.podName)
	if err != nil || pod.GetUID() != s.podUID || pod.GetDeletionTimestamp() != nil {
		return nil, ErrActivation
	}
	u := *a.base
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/namespaces/" + s.namespace + "/pods/" + s.podName + "/portforward"
	u.RawQuery = "ports=8443"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, ErrActivation
	}
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "SPDY/3.1")
	request.Header.Set("X-Stream-Protocol-Version", "portforward.k8s.io")
	if a.native.bearer != "" {
		request.Header.Set("Authorization", "Bearer "+a.native.bearer)
	} else if a.native.username != "" || a.native.password != "" {
		request.SetBasicAuth(a.native.username, a.native.password)
	}
	address := u.Host
	if u.Port() == "" {
		address = net.JoinHostPort(u.Hostname(), "443")
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: a.native.tls}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, ErrActivation
	}
	stopClose := context.AfterFunc(ctx, func() { hardClose(raw) })
	defer stopClose()
	success := false
	defer func() {
		if !success {
			hardClose(raw)
		}
	}()
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if raw.SetDeadline(deadline) != nil || request.Write(raw) != nil {
		return nil, ErrActivation
	}
	budget := &headerBudget{reader: raw, remaining: 8192, enabled: true}
	reader := bufio.NewReaderSize(budget, 4096)
	response, err := http.ReadResponse(reader, request)
	if err != nil || response == nil || response.StatusCode != http.StatusSwitchingProtocols || len(response.Header.Values("Connection")) != 1 || !strings.EqualFold(response.Header.Get("Connection"), "Upgrade") || len(response.Header.Values("Upgrade")) != 1 || !strings.EqualFold(response.Header.Get("Upgrade"), "SPDY/3.1") || len(response.Header.Values("X-Stream-Protocol-Version")) != 1 || response.Header.Get("X-Stream-Protocol-Version") != "portforward.k8s.io" || len(response.Header.Values("Content-Length")) != 0 || len(response.Header.Values("Transfer-Encoding")) != 0 || len(response.TransferEncoding) != 0 {
		// Never read, drain, log or reflect an arbitrary rejection body.
		return nil, ErrActivation
	}
	budget.enabled = false
	deadline = time.Now().Add(2 * time.Minute)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if raw.SetDeadline(deadline) != nil {
		return nil, ErrActivation
	}
	conn, err := startForward(ctx, raw, reader)
	if err != nil {
		return nil, ErrActivation
	}
	success = true
	return conn, nil
}

type wireWriter struct {
	writer    io.Writer
	remaining int
}

func (w *wireWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, ErrActivation
	}
	n, err := w.writer.Write(p)
	w.remaining -= n
	return n, err
}

// Only the frame codec is imported, not the SDK connection/queue/debug manager.
// One reader and one writer provide backpressure without buffering DATA queues.
type forwardSession struct {
	raw, client, bridge net.Conn
	framer              *spdy.Framer
	guard               *forwardFrames
	writeMu             sync.Mutex
	ack                 chan uint32
	stop, done, ready   chan struct{}
	once                sync.Once
	wg                  sync.WaitGroup
}

type forwardConn struct {
	net.Conn
	session *forwardSession
}

func (c *forwardConn) Close() error { c.session.abort(); <-c.session.done; return nil }

func (s *forwardSession) abort() {
	s.once.Do(func() {
		// Do not take the write mutex before unblocking raw socket writes.
		hardClose(s.raw)
		_ = s.client.Close()
		_ = s.bridge.Close()
		close(s.stop)
	})
}
func (s *forwardSession) write(frame spdy.Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.framer.WriteFrame(frame)
}
func (s *forwardSession) open(ctx context.Context, id uint32, kind string) error {
	s.guard.opened.Or(streamBit(id))
	headers := http.Header{}
	headers.Set(corev1.StreamType, kind)
	headers.Set(corev1.PortHeader, "8443")
	headers.Set(corev1.PortForwardRequestIDHeader, "0")
	if s.write(&spdy.SynStreamFrame{StreamId: spdy.StreamId(id), Headers: headers}) != nil {
		return ErrActivation
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case got := <-s.ack:
		if got != id {
			return ErrActivation
		}
		return nil
	case <-ctx.Done():
		return ErrActivation
	case <-s.stop:
		return ErrActivation
	case <-timer.C:
		return ErrActivation
	}
}
func startForward(ctx context.Context, raw net.Conn, reader io.Reader) (net.Conn, error) {
	client, bridge := net.Pipe()
	g := &forwardFrames{reader: reader}
	f, err := spdy.NewFramerWithOptions(&wireWriter{writer: raw, remaining: forwardWireBudget}, g, spdy.WithMaxControlFramePayloadSize(4096), spdy.WithMaxHeaderFieldSize(256), spdy.WithMaxHeaderCount(8))
	if err != nil {
		_ = client.Close()
		_ = bridge.Close()
		hardClose(raw)
		return nil, ErrActivation
	}
	s := &forwardSession{raw: raw, client: client, bridge: bridge, framer: f, guard: g, ack: make(chan uint32, 2), stop: make(chan struct{}), done: make(chan struct{}), ready: make(chan struct{})}
	s.wg.Add(3)
	go func() { defer s.wg.Done(); s.read() }()
	go func() { defer s.wg.Done(); s.pump() }()
	go func() {
		defer s.wg.Done()
		select {
		case <-ctx.Done():
			s.abort()
		case <-s.stop:
		}
	}()
	go func() { s.wg.Wait(); close(s.done) }()
	if s.open(ctx, 1, corev1.StreamTypeError) != nil || s.write(&spdy.DataFrame{StreamId: 1, Flags: spdy.DataFlagFin}) != nil || s.open(ctx, 3, corev1.StreamTypeData) != nil {
		s.abort()
		<-s.done
		return nil, ErrActivation
	}
	close(s.ready)
	return &forwardConn{Conn: client, session: s}, nil
}
func (s *forwardSession) read() {
	defer s.abort()
	for {
		frame, err := s.framer.ReadFrame()
		if err != nil {
			return
		}
		switch f := frame.(type) {
		case *spdy.SynReplyFrame:
			if len(f.Headers) != 0 || f.CFHeader.Flags != 0 {
				return
			}
			select {
			case s.ack <- uint32(f.StreamId):
			case <-s.stop:
				return
			}
		case *spdy.DataFrame:
			if f.StreamId == 1 {
				if len(f.Data) != 0 {
					return
				}
				continue
			}
			if f.StreamId != 3 {
				return
			}
			if len(f.Data) > 0 {
				if _, err := s.bridge.Write(f.Data); err != nil {
					return
				}
			}
			if f.Flags&spdy.DataFlagFin != 0 {
				return
			}
		case *spdy.PingFrame:
			if s.write(&spdy.PingFrame{Id: f.Id}) != nil {
				return
			}
		case *spdy.SettingsFrame, *spdy.WindowUpdateFrame: // native profile has no flow control
		default:
			return
		}
	}
}
func (s *forwardSession) pump() {
	defer s.abort()
	select {
	case <-s.ready:
	case <-s.stop:
		return
	}
	buffer := make([]byte, 32768)
	for {
		n, err := s.bridge.Read(buffer)
		if n > 0 && s.write(&spdy.DataFrame{StreamId: 3, Data: buffer[:n]}) != nil {
			return
		}
		if err != nil {
			return
		}
	}
}
