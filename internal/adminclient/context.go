// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0
package adminclient

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"sort"
	"time"
)

const contextFile = "contexts.json"

type ContextStore struct{ store *privatefs.Store }
type contextState struct {
	Version  string         `json:"version"`
	Current  string         `json:"current"`
	Contexts []SavedContext `json:"contexts"`
}

func OpenContextStore(base string, create bool) (*ContextStore, error) {
	store, e := privatefs.Open(base, create)
	if e != nil {
		return nil, problem("context_unavailable")
	}
	return &ContextStore{store: store}, nil
}
func (s *ContextStore) Close() error {
	if s == nil {
		return nil
	}
	return s.store.Close()
}
func (s *ContextStore) state() (contextState, *privatefs.FileIdentity, error) {
	if s == nil || s.store == nil {
		return contextState{}, nil, problem("context_unavailable")
	}
	contents, id, e := s.store.Read(contextFile, privatefs.MaxFileBytes)
	if errors.Is(e, privatefs.ErrNotFound) {
		return contextState{Version: "v1", Contexts: []SavedContext{}}, nil, nil
	}
	if e != nil {
		return contextState{}, nil, problem("context_unavailable")
	}
	var state contextState
	if decodeResponse(contents, &state) != nil || state.Version != "v1" || len(state.Contexts) > 100 {
		return contextState{}, nil, problem("context_unavailable")
	}
	seen := map[string]bool{}
	selected := state.Current == ""
	for _, saved := range state.Contexts {
		normalized, e := NormalizeContext(saved.Config)
		if e != nil || normalized != saved.Config || seen[saved.Config.Name] || saved.Identity.Origin != saved.Config.APIOrigin || !digestPattern.MatchString(saved.Identity.CAHash) || saved.Identity.PrincipalID != "admin" || !labelPattern.MatchString(saved.Identity.Namespace) {
			return contextState{}, nil, problem("context_unavailable")
		}
		seen[saved.Config.Name] = true
		selected = selected || saved.Config.Name == state.Current
	}
	if !selected {
		return contextState{}, nil, problem("context_unavailable")
	}
	return state, &id, nil
}
func (s *ContextStore) List() ([]SavedContext, string, error) {
	state, _, e := s.state()
	if e != nil {
		return nil, "", e
	}
	sort.Slice(state.Contexts, func(i, j int) bool { return state.Contexts[i].Config.Name < state.Contexts[j].Config.Name })
	return state.Contexts, state.Current, nil
}
func (s *ContextStore) Load(name string) (SavedContext, error) {
	state, _, e := s.state()
	if e != nil {
		return SavedContext{}, e
	}
	if name == "" {
		name = state.Current
	}
	if !labelPattern.MatchString(name) {
		return SavedContext{}, problem("context_unavailable")
	}
	for _, saved := range state.Contexts {
		if saved.Config.Name == name {
			return saved, nil
		}
	}
	return SavedContext{}, problem("not_found")
}
func (s *ContextStore) write(state contextState, expected *privatefs.FileIdentity) error {
	sort.Slice(state.Contexts, func(i, j int) bool { return state.Contexts[i].Config.Name < state.Contexts[j].Config.Name })
	contents, e := json.Marshal(state)
	if e != nil {
		return problem("context_unavailable")
	}
	if _, e = s.store.AtomicWrite(contextFile, contents, expected); e != nil {
		if errors.Is(e, privatefs.ErrChanged) || errors.Is(e, privatefs.ErrExists) {
			return problem("context_changed")
		}
		return problem("context_unavailable")
	}
	return nil
}
func (s *ContextStore) Login(ctx context.Context, config ContextConfig) (Identity, error) {
	if ctx == nil || s == nil {
		return Identity{}, problem("invalid_request")
	}
	client, e := Load(config)
	if e != nil {
		return Identity{}, e
	}
	defer client.Close()
	identity, e := client.Verify(ctx)
	if e != nil {
		return Identity{}, e
	}
	lockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	lock, e := s.store.Lock(lockCtx, contextFile)
	if e != nil {
		if lockCtx.Err() != nil {
			return Identity{}, requestFailure(lockCtx.Err(), false)
		}
		return Identity{}, problem("context_unavailable")
	}
	defer lock.Close()
	state, id, e := s.state()
	if e != nil {
		return Identity{}, e
	}
	saved := SavedContext{Config: client.config, Identity: identity}
	found := false
	for i := range state.Contexts {
		if state.Contexts[i].Config.Name == saved.Config.Name {
			state.Contexts[i] = saved
			found = true
		}
	}
	if !found {
		if len(state.Contexts) == 100 {
			return Identity{}, problem("context_unavailable")
		}
		state.Contexts = append(state.Contexts, saved)
	}
	state.Current = saved.Config.Name
	if e = s.write(state, id); e != nil {
		return Identity{}, e
	}
	return identity, nil
}
func (s *ContextStore) Use(name string) error { return s.change(name, false) }

// Remove only removes metadata; external credential/CA files are untouched.
func (s *ContextStore) Remove(name string) error { return s.change(name, true) }
func (s *ContextStore) change(name string, remove bool) error {
	if s == nil || !labelPattern.MatchString(name) {
		return problem("invalid_request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lock, e := s.store.Lock(ctx, contextFile)
	if e != nil {
		if ctx.Err() != nil {
			return requestFailure(ctx.Err(), false)
		}
		return problem("context_unavailable")
	}
	defer lock.Close()
	state, id, e := s.state()
	if e != nil {
		return e
	}
	found := -1
	for i, saved := range state.Contexts {
		if saved.Config.Name == name {
			found = i
		}
	}
	if found < 0 {
		return problem("not_found")
	}
	if remove {
		state.Contexts = append(state.Contexts[:found], state.Contexts[found+1:]...)
		if state.Current == name {
			state.Current = ""
		}
	} else {
		state.Current = name
	}
	return s.write(state, id)
}

// LoadSaved pins persisted origin and CA before any credential is sent. Verify
// then binds the returned namespace/principal to the stored context identity.
func LoadSaved(saved SavedContext) (*Client, error) {
	client, e := Load(saved.Config)
	if e != nil {
		return nil, e
	}
	if client.identity.Origin != saved.Identity.Origin || client.identity.CAHash != saved.Identity.CAHash || saved.Identity.PrincipalID != "admin" || !labelPattern.MatchString(saved.Identity.Namespace) {
		client.Close()
		return nil, problem("context_changed")
	}
	client.expectedIdentity = &saved.Identity
	return client, nil
}
