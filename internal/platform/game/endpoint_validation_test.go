// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"strconv"
	"strings"
	"testing"
)

func TestDefinitionRejectsDuplicateProtocolPortPairs(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolTCP, ProtocolUDP} {
		for _, scope := range []EndpointScope{ScopePlayer, ScopeAdmin, ScopeInternal} {
			t.Run(string(protocol)+"/"+string(scope), func(t *testing.T) {
				definition := validDefinition()
				definition.ReadinessEndpoint, definition.ReadinessMode = "", ""
				definition.Endpoints[0].Protocol = protocol
				definition.Endpoints = append(definition.Endpoints, Endpoint{
					Name: "shadow", Protocol: protocol, ContainerPort: 8080, Scope: scope,
				})
				err := definition.Validate()
				if err == nil || !strings.Contains(err.Error(), "shadow") || !strings.Contains(err.Error(), "duplicat") {
					t.Fatalf("duplicate %s port across %s scope: got %v", protocol, scope, err)
				}
			})
		}
	}
}

func TestDefinitionAllowsSamePortAcrossProtocols(t *testing.T) {
	for _, reversed := range []bool{false, true} {
		definition := validDefinition()
		definition.Endpoints = append(definition.Endpoints, Endpoint{
			Name: "datagrams", Protocol: ProtocolUDP, ContainerPort: 8080, Scope: ScopePlayer,
		})
		if reversed {
			definition.Endpoints[0], definition.Endpoints[1] = definition.Endpoints[1], definition.Endpoints[0]
		}
		if err := definition.Validate(); err != nil {
			t.Fatalf("distinct TCP/UDP endpoints on the same port (reversed=%v): %v", reversed, err)
		}
	}
}

func TestDefinitionEndpointPortNames(t *testing.T) {
	for _, scope := range []EndpointScope{ScopePlayer, ScopeAdmin, ScopeInternal} {
		for _, test := range []struct {
			name  string
			valid bool
		}{
			{"a", true}, {strings.Repeat("a", 15), true}, {"game-tcp", true},
			{strings.Repeat("a", 16), false}, {strings.Repeat("a", 63), false},
			{"123", false}, {"game--tcp", false}, {"-game", false}, {"game-", false},
			{"Game", false}, {"game_tcp", false}, {"", false},
		} {
			t.Run(string(scope)+"/"+strconv.Quote(test.name), func(t *testing.T) {
				definition := validDefinition()
				definition.Endpoints = append(definition.Endpoints, Endpoint{
					Name: test.name, Protocol: ProtocolTCP, ContainerPort: 8081, Scope: scope,
				})
				err := definition.Validate()
				if test.valid {
					if err != nil {
						t.Fatalf("valid endpoint name %q: %v", test.name, err)
					}
				} else if err == nil || !strings.Contains(err.Error(), strconv.Quote(test.name)) {
					t.Fatalf("invalid endpoint name %q: got %v", test.name, err)
				}
			})
		}
	}
}
