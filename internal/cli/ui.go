// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/webui"
	"github.com/spf13/cobra"
)

func (app *application) uiCommand() *cobra.Command {
	address := "127.0.0.1:0"
	command := &cobra.Command{
		Use: "ui", Short: "Serve read-only server and operation status on loopback until interrupted",
		Args: exactArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !validUIAddress(address) {
				return failure("invalid_arguments", 2)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), app.timeout)
			client, _, err := app.client(ctx)
			cancel()
			if err != nil {
				return err
			}
			defer client.Close()
			listener, err := (&net.ListenConfig{}).Listen(cmd.Context(), "tcp", address)
			if err != nil {
				return failure("local_io", 1)
			}
			defer func() { _ = listener.Close() }()
			host := listener.Addr().String()
			server := &http.Server{
				Handler:           &uiHandler{client: client, host: host, timeout: app.timeout},
				ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
				WriteTimeout: app.timeout + 5*time.Second, IdleTimeout: 30 * time.Second,
				MaxHeaderBytes: 16 * 1024, ErrorLog: log.New(io.Discard, "", 0),
				BaseContext: func(net.Listener) context.Context { return cmd.Context() },
			}
			defer func() { _ = server.Close() }()
			stopped := make(chan struct{})
			defer close(stopped)
			go func() {
				select {
				case <-cmd.Context().Done():
					_ = server.Close()
				case <-stopped:
				}
			}()
			url := "http://" + host + "/"
			if app.output == "json" {
				err = json.NewEncoder(app.options.Out).Encode(struct {
					Version string `json:"version"`
					URL     string `json:"url"`
				}{"v1", url})
			} else {
				_, err = fmt.Fprintln(app.options.Out, url)
			}
			if err != nil {
				return failure("local_io", 1)
			}
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return failure("local_io", 1)
			}
			return cmd.Context().Err()
		},
	}
	command.Flags().StringVar(&address, "listen", address, "Literal loopback IP and port; port 0 selects an available port")
	return command
}

// Do not resolve hostnames: the bind address must itself prove loopback scope.
func validUIAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || !ip.IsLoopback() {
		return false
	}
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	_, err = strconv.ParseUint(port, 10, 16)
	return err == nil
}

type uiHandler struct {
	client  uiReader
	host    string
	timeout time.Duration
}

// uiReader is the upstream read boundary. Only the verified administrator
// client is supplied by the command; the listener has no submission method.
type uiReader interface {
	Read(context.Context, string, any) (string, error)
}

func (handler *uiHandler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if request.Host != handler.host || request.URL.IsAbs() {
		writeUIError(w, request, http.StatusForbidden, "invalid_host")
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeUIError(w, request, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	path := request.URL.Path
	apiPath, allowed := uiReadRoute(path)
	if !allowed || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery {
		writeUIError(w, request, http.StatusNotFound, "not_found")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	var page bytes.Buffer
	var readErr, renderErr error
	switch path {
	case "/":
		var list adminv1.ServerList
		_, readErr = handler.client.Read(ctx, apiPath, &list)
		if readErr == nil {
			renderErr = webui.RenderServerList(&page, list)
		}
	case "/operations":
		var list adminv1.OperationList
		_, readErr = handler.client.Read(ctx, apiPath, &list)
		if readErr == nil {
			renderErr = webui.RenderOperationList(&page, list)
		}
	default:
		var operation adminv1.Operation
		_, readErr = handler.client.Read(ctx, apiPath, &operation)
		if readErr == nil && operation.OperationID != strings.TrimPrefix(path, "/operations/") {
			readErr = &adminclient.Error{Code: "invalid_response"}
		}
		if readErr == nil {
			renderErr = webui.RenderOperationDetail(&page, operation)
		}
	}
	if readErr != nil {
		code := uiReadError(readErr)
		status := http.StatusBadGateway
		if code == "not_found" {
			status = http.StatusNotFound
		}
		writeUIError(w, request, status, code)
		return
	}
	if renderErr != nil {
		writeUIError(w, request, http.StatusInternalServerError, "render_failed")
		return
	}
	if request.Method != http.MethodHead {
		_, _ = w.Write(page.Bytes())
	}
}

func uiReadRoute(path string) (string, bool) {
	switch path {
	case "/":
		return "/v1/servers", true
	case "/operations":
		return "/v1/operations", true
	default:
		if strings.HasPrefix(path, "/operations/") && receiptID.MatchString(strings.TrimPrefix(path, "/operations/")) {
			return "/v1" + path, true
		}
		return "", false
	}
}

// Error codes arriving from the remote service are also untrusted. Render a
// closed set of stable read errors, never Error(), response bodies or paths.
func uiReadError(err error) string {
	var remote *adminclient.Error
	if errors.As(err, &remote) {
		switch remote.Code {
		case "credential_expired", "credential_unavailable", "context_changed", "tls_unavailable", "request_timeout", "interrupted", "response_too_large", "invalid_response", "unauthenticated", "forbidden", "unavailable", "not_found":
			return remote.Code
		}
	}
	return "api_unavailable"
}

var uiErrorTemplate = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Arcadectl status unavailable</title></head>
<body><a href="#main-content">Skip to status error</a><main id="main-content"><h1>Status unavailable</h1><p role="alert">Error: {{.}}</p><p>Check the trusted administrator context with <code>arcadectl server status</code>, then reload this page. This page cannot submit changes.</p></main></body></html>`))

func writeUIError(w http.ResponseWriter, request *http.Request, status int, code string) {
	w.WriteHeader(status)
	if request.Method != http.MethodHead {
		_ = uiErrorTemplate.Execute(w, code)
	}
}
