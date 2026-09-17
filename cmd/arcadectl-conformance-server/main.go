// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// arcadectl-conformance-server is a deliberately tiny lifecycle fixture. It
// is not a production game server and is built only by the isolated-cluster
// harness.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	persistentRoot = "/srv/world"
	listenAddress  = ":8080"
	maxResponse    = 4096
)

type stateStore struct {
	root string
}

type stateSnapshot struct {
	Marker string
	Seed   string
	MOTD   string
	Boots  int
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "conformance fixture %s failed\n", operation(os.Args[1:]))
		os.Exit(1)
	}
}

func operation(arguments []string) string {
	if len(arguments) > 0 {
		switch arguments[0] {
		case "get":
			return "service probe"
		case "read-marker":
			return "marker read"
		}
	}
	return "server startup"
}

func run(arguments []string) error {
	switch {
	case len(arguments) == 0:
		return serve(stateStore{root: persistentRoot})
	case len(arguments) == 2 && arguments[0] == "get":
		return get(arguments[1], os.Stdout)
	case len(arguments) == 1 && arguments[0] == "read-marker":
		marker, err := readLine(filepath.Join(persistentRoot, "marker"))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, marker)
		return err
	default:
		return errors.New("usage: arcadectl-conformance-server [get <http-url>|read-marker]")
	}
}

func serve(store stateStore) error {
	if _, err := store.initialize(); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/state", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		snapshot, err := store.snapshot()
		if err != nil {
			http.Error(writer, "state unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(writer, "marker=%s\nseed=%s\nmotd=%s\nboots=%d\n", snapshot.Marker, snapshot.Seed, snapshot.MOTD, snapshot.Boots)
	})
	server := &http.Server{
		Addr:              listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       10 * time.Second,
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()
	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-shutdownContext.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func (store stateStore) initialize() (stateSnapshot, error) {
	seed, err := readLine(filepath.Join(store.root, "config", "seed.txt"))
	if err != nil {
		return stateSnapshot{}, fmt.Errorf("read seed: %w", err)
	}
	markerPath := filepath.Join(store.root, "marker")
	markerFile, err := os.OpenFile(markerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err == nil {
		if _, writeErr := fmt.Fprintln(markerFile, seed); writeErr != nil {
			_ = markerFile.Close()
			return stateSnapshot{}, fmt.Errorf("write marker: %w", writeErr)
		}
		if err := markerFile.Sync(); err != nil {
			_ = markerFile.Close()
			return stateSnapshot{}, fmt.Errorf("sync marker: %w", err)
		}
		if err := markerFile.Close(); err != nil {
			return stateSnapshot{}, fmt.Errorf("close marker: %w", err)
		}
	} else if !errors.Is(err, os.ErrExist) {
		return stateSnapshot{}, fmt.Errorf("create marker: %w", err)
	}
	bootsPath := filepath.Join(store.root, "boots")
	boots := 0
	if contents, err := os.ReadFile(bootsPath); err == nil {
		boots, err = strconv.Atoi(strings.TrimSpace(string(contents)))
		if err != nil || boots < 0 {
			return stateSnapshot{}, errors.New("stored boot count is invalid")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return stateSnapshot{}, fmt.Errorf("read boot count: %w", err)
	}
	if err := writeAtomic(bootsPath, []byte(strconv.Itoa(boots+1)+"\n")); err != nil {
		return stateSnapshot{}, fmt.Errorf("write boot count: %w", err)
	}
	return store.snapshot()
}

func (store stateStore) snapshot() (stateSnapshot, error) {
	marker, err := readLine(filepath.Join(store.root, "marker"))
	if err != nil {
		return stateSnapshot{}, err
	}
	seed, err := readLine(filepath.Join(store.root, "config", "seed.txt"))
	if err != nil {
		return stateSnapshot{}, err
	}
	motd, err := readLine(filepath.Join(store.root, "config", "motd.txt"))
	if err != nil {
		return stateSnapshot{}, err
	}
	bootsText, err := readLine(filepath.Join(store.root, "boots"))
	if err != nil {
		return stateSnapshot{}, err
	}
	boots, err := strconv.Atoi(bootsText)
	if err != nil || boots <= 0 {
		return stateSnapshot{}, errors.New("boot count is invalid")
	}
	return stateSnapshot{Marker: marker, Seed: seed, MOTD: motd, Boots: boots}, nil
}

func readLine(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(contents))
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("file must contain one non-empty line")
	}
	return value, nil
}

func writeAtomic(path string, contents []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".arcadectl-conformance-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func get(url string, output io.Writer) error {
	if !strings.HasPrefix(url, "http://") {
		return errors.New("fixture client requires an http URL")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fixture returned HTTP status %d", response.StatusCode)
	}
	_, err = io.Copy(output, io.LimitReader(response.Body, maxResponse))
	return err
}
