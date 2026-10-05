// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0
package adminclient

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestContextLoginListUseRemoveStoresNoSecret(t *testing.T) {
	config, credential, _ := clientFixture(t, func(http.ResponseWriter, *http.Request, adminauth.ClientCredential) {})
	base := filepath.Join(privateTemp(t), "contexts")
	s, e := OpenContextStore(base, true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	identity, e := s.Login(context.Background(), config)
	if e != nil || identity.PrincipalID != "admin" || identity.Namespace != "isolated-games" {
		t.Fatal("login identity")
	}
	second := config
	second.Name = "second"
	if _, e := s.Login(context.Background(), second); e != nil {
		t.Fatal(e)
	}
	records, current, e := s.List()
	if e != nil || len(records) != 2 || current != "second" {
		t.Fatal("context list")
	}
	if e := s.Use("fixture"); e != nil {
		t.Fatal(e)
	}
	saved, e := s.Load("")
	if e != nil || saved.Config.Name != "fixture" || saved.Identity != identity {
		t.Fatal("selected context")
	}
	raw, e := os.ReadFile(filepath.Join(base, contextFile))
	if e != nil || strings.Contains(string(raw), credential.Token) || strings.Contains(string(raw), adminauth.TokenDigest(credential.Token)) || strings.Contains(string(raw), credential.CredentialID) {
		t.Fatal("context persisted secret or rotating identity")
	}
	if e := s.Remove("fixture"); e != nil {
		t.Fatal(e)
	}
	records, current, e = s.List()
	if e != nil || len(records) != 1 || current != "" {
		t.Fatal("remove did not clear exact selection")
	}
	if _, e := os.Stat(config.CredentialFile); e != nil {
		t.Fatal("context remove deleted credential")
	}
	if _, e := os.Stat(config.CAFile); e != nil {
		t.Fatal("context remove deleted CA")
	}
	if _, e := s.Load(""); e == nil {
		t.Fatal("missing selected context silently fell back")
	}
}
func TestConcurrentContextUpdatesPreserveAllRecords(t *testing.T) {
	config, _, _ := clientFixture(t, func(http.ResponseWriter, *http.Request, adminauth.ClientCredential) {})
	base := filepath.Join(privateTemp(t), "contexts")
	a, e := OpenContextStore(base, true)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := OpenContextStore(base, false)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	var group sync.WaitGroup
	for i, name := range []string{"one", "two", "three", "four"} {
		group.Add(1)
		go func(i int, name string) {
			defer group.Done()
			cfg := config
			cfg.Name = name
			s := a
			if i%2 == 1 {
				s = b
			}
			if _, e := s.Login(context.Background(), cfg); e != nil {
				t.Error("concurrent login")
			}
		}(i, name)
	}
	group.Wait()
	records, current, e := a.List()
	if e != nil || len(records) != 4 || current == "" {
		t.Fatal("concurrent context lost a record")
	}
}
func TestContextCorruptionFailsClosedWithoutRawErrors(t *testing.T) {
	config, _, _ := clientFixture(t, func(http.ResponseWriter, *http.Request, adminauth.ClientCredential) {})
	base := filepath.Join(privateTemp(t), "contexts")
	s, e := OpenContextStore(base, true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e := s.Login(context.Background(), config); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(base, contextFile))
	if e != nil {
		t.Fatal(e)
	}
	var state map[string]any
	if json.Unmarshal(raw, &state) != nil {
		t.Fatal("state")
	}
	state["token"] = "SECRET-CANARY"
	corrupt, _ := json.Marshal(state)
	if os.WriteFile(filepath.Join(base, contextFile), corrupt, 0o600) != nil {
		t.Fatal("fixture write")
	}
	if _, _, e := s.List(); e == nil || strings.Contains(e.Error(), "SECRET-CANARY") {
		t.Fatal("unsafe context was accepted or leaked")
	}
}

func TestContextLockTimeoutAndCancellationRetainRequestClassification(t *testing.T) {
	config, _, requests := clientFixture(t, func(http.ResponseWriter, *http.Request, adminauth.ClientCredential) {})
	s, err := OpenContextStore(filepath.Join(privateTemp(t), "contexts"), true)
	if err != nil {
		t.Fatal("private context fixture unavailable")
	}
	defer s.Close()
	if _, err := s.Login(context.Background(), config); err != nil {
		t.Fatal("initial private login unavailable")
	}
	lock, err := s.store.Lock(context.Background(), contextFile)
	if err != nil {
		t.Fatal("private held context lock unavailable")
	}
	defer lock.Close()
	for _, cause := range []string{"deadline", "cancelled"} {
		t.Run(cause, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			want := "request_timeout"
			if cause == "cancelled" {
				cancel()
				ctx, cancel = context.WithCancel(context.Background())
				timer := time.AfterFunc(100*time.Millisecond, cancel)
				defer timer.Stop()
				want = "interrupted"
			}
			defer cancel()
			_, err := s.Login(ctx, config)
			var classified *Error
			if !errors.As(err, &classified) || classified.Code != want || classified.Ambiguous {
				t.Fatal("held context login lock lost deadline/cancellation classification")
			}
		})
	}
	if err := s.Use("fixture"); err == nil {
		t.Fatal("held context lock unexpectedly changed context")
	} else {
		var classified *Error
		if !errors.As(err, &classified) || classified.Code != "request_timeout" || classified.Ambiguous {
			t.Fatal("bounded context change lock lost timeout classification")
		}
	}
	records, current, err := s.List()
	if err != nil || len(records) != 1 || current != "fixture" || requests.Load() != 3 {
		t.Fatal("failed context lock changed metadata or submitted an unexpected request")
	}
}
