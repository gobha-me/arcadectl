// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
)

func startRealAdminTLSServer(t *testing.T) (string, adminauth.Credential, *x509.CertPool) {
	t.Helper()
	config, credential, roots := apiFixture(t)
	api, _, _, err := newServers(config, io.Discard)
	if err != nil {
		t.Fatalf("newServers: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- api.ServeTLS(listener, "", "")
	}()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := api.Shutdown(shutdownCtx); err != nil {
			_ = api.Close()
		}
		_ = listener.Close()
		if err := <-serveDone; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("ServeTLS shutdown error: %v", err)
		}
	})
	return listener.Addr().String(), credential, roots
}

// Test 1: An unauthenticated TLS client offering ALPN ["h2", "http/1.1"] must
// not negotiate "h2" (NegotiatedProtocol must be "http/1.1" or ""), and a
// client offering only ["h2"] must either fail the handshake or not get "h2".
func TestAdminAPIRefusesHTTP2ALPNNegotiation(t *testing.T) {
	addr, _, roots := startRealAdminTLSServer(t)
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: "api.test",
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatalf("TLS dial offering [h2, http/1.1] failed: %v", err)
	}
	negotiated := conn.ConnectionState().NegotiatedProtocol
	_ = conn.Close()
	if negotiated != "http/1.1" && negotiated != "" {
		t.Errorf("unauthenticated TLS client offering [h2, http/1.1] negotiated %q; want \"http/1.1\" or \"\"", negotiated)
	}

	h2OnlyConn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: "api.test",
		NextProtos: []string{"h2"},
	})
	if err == nil {
		h2OnlyProto := h2OnlyConn.ConnectionState().NegotiatedProtocol
		_ = h2OnlyConn.Close()
		if h2OnlyProto == "h2" {
			t.Errorf("unauthenticated TLS client offering only [h2] negotiated %q", h2OnlyProto)
		}
	}
}

// Test 2: Sending the HTTP/2 client connection preface + a SETTINGS frame over
// the TLS connection must not produce an HTTP/2 SETTINGS response; the server
// must treat it as HTTP/1.1 (400/401 error response with Connection: close) or
// close the connection.
func TestAdminAPIRefusesHTTP2ClientPrefaceOverTLS(t *testing.T) {
	addr, _, roots := startRealAdminTLSServer(t)
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: "api.test",
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	// RFC 9113 Section 3.4 client connection preface followed by an empty
	// 9-byte SETTINGS frame (length=0, type=0x04, flags=0x00, stream=0).
	prefaceAndSettings := append(
		[]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
		0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
	)
	if _, err := conn.Write(prefaceAndSettings); err != nil {
		t.Fatalf("write HTTP/2 preface: %v", err)
	}

	buf := make([]byte, 512)
	n, readErr := conn.Read(buf)
	response := buf[:n]

	// An HTTP/2 server frame header is 9 bytes with type=0x04 (SETTINGS) at byte 3
	// and stream identifier 0x00000000 in bytes 5..8.
	if len(response) >= 9 &&
		response[3] == 0x04 &&
		(response[5]&0x7f) == 0 &&
		response[6] == 0 &&
		response[7] == 0 &&
		response[8] == 0 &&
		!bytes.HasPrefix(response, []byte("HTTP/1.")) {
		t.Fatalf("server answered HTTP/2 client preface with an HTTP/2 SETTINGS frame: %x", response[:9])
	}

	if len(response) == 0 {
		if readErr == nil {
			t.Fatal("expected HTTP/1.1 error response or connection close, got empty nil-error read")
		}
		var networkError net.Error
		if errors.As(readErr, &networkError) && networkError.Timeout() {
			t.Fatal("server stalled instead of rejecting the HTTP/2 preface")
		}
		if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, syscall.ECONNRESET) {
			t.Fatalf("expected a closed connection, got read error: %v", readErr)
		}
		return
	}
	text := string(response)
	if !strings.HasPrefix(text, "HTTP/1.1 400 ") && !strings.HasPrefix(text, "HTTP/1.1 401 ") {
		t.Fatalf("expected HTTP/1.1 400/401 rejection of HTTP/2 preface, got %q", text)
	}
}

// Test 3: An HTTP/1.1 request with no Authorization header still gets 401
// Unauthorized (and an authenticated request still gets 200 OK).
func TestAdminAPIHTTP1UnauthenticatedRequestReturns401(t *testing.T) {
	addr, credential, roots := startRealAdminTLSServer(t)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    roots,
				ServerName: "api.test",
				NextProtos: []string{"http/1.1"},
			},
		},
		Timeout: 3 * time.Second,
	}
	defer client.CloseIdleConnections()

	unauthResp, err := client.Get("https://" + addr + "/v1/auth/self")
	if err != nil {
		t.Fatalf("unauthenticated HTTP/1.1 GET failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, unauthResp.Body)
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated HTTP/1.1 status = %d; want %d", unauthResp.StatusCode, http.StatusUnauthorized)
	}
	if unauthResp.Proto != "HTTP/1.1" {
		t.Fatalf("unauthenticated response proto = %q; want \"HTTP/1.1\"", unauthResp.Proto)
	}

	authReq, err := http.NewRequest(http.MethodGet, "https://"+addr+"/v1/auth/self", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	authReq.Header.Set("Authorization", "Bearer "+credential.Token)
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("authenticated HTTP/1.1 GET failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, authResp.Body)
	_ = authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated HTTP/1.1 status = %d; want %d", authResp.StatusCode, http.StatusOK)
	}
}

// Test 4: Config-level verification that newServers() disables HTTP/2 on both
// the admin API server and the private health server.
func TestNewServersConfigDisablesHTTP2(t *testing.T) {
	config, _, _ := apiFixture(t)
	api, health, _, err := newServers(config, io.Discard)
	if err != nil {
		t.Fatalf("newServers: %v", err)
	}

	if api.TLSNextProto == nil {
		t.Error("admin server TLSNextProto is nil; want non-nil empty map")
	} else if len(api.TLSNextProto) != 0 {
		t.Errorf("admin server TLSNextProto has %d entries; want 0", len(api.TLSNextProto))
	}
	if api.TLSConfig == nil {
		t.Fatal("admin server TLSConfig is nil")
	}
	if !slices.Equal(api.TLSConfig.NextProtos, []string{"http/1.1"}) {
		t.Errorf("admin server TLSConfig.NextProtos = %v; want [\"http/1.1\"]", api.TLSConfig.NextProtos)
	}
	if api.Protocols == nil || !api.Protocols.HTTP1() || api.Protocols.HTTP2() || api.Protocols.UnencryptedHTTP2() {
		t.Errorf("admin server Protocols = %+v; want HTTP1-only", api.Protocols)
	}

	if health.TLSNextProto == nil {
		t.Error("health server TLSNextProto is nil; want non-nil empty map")
	} else if len(health.TLSNextProto) != 0 {
		t.Errorf("health server TLSNextProto has %d entries; want 0", len(health.TLSNextProto))
	}
	if health.Protocols == nil || !health.Protocols.HTTP1() || health.Protocols.HTTP2() || health.Protocols.UnencryptedHTTP2() {
		t.Errorf("health server Protocols = %+v; want HTTP1-only", health.Protocols)
	}
}
