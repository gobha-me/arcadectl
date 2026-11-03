// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package webui renders read-only views of the administrator API contract.
package webui

import (
	"cmp"
	_ "embed"
	"html/template"
	"io"
	"net"
	"slices"
	"strconv"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
)

//go:embed templates/servers.html.tmpl
var serverListSource string

var serverListTemplate = template.Must(template.New("servers").Parse(serverListSource))

type serverRow struct {
	Name, Game, Phase, DesiredState, Ready string
	Endpoints                              []string
}

// RenderServerList writes an accessible, read-only server status page.
func RenderServerList(w io.Writer, list adminv1.ServerList) error {
	rows := make([]serverRow, 0, len(list.Items))
	for _, server := range list.Items {
		row := serverRow{
			Name: server.Name, Game: server.Game, Phase: server.Phase,
			DesiredState: server.DesiredState, Ready: "Ready: Unknown",
		}
		for _, condition := range server.Conditions {
			if condition.Type == "Ready" {
				row.Ready = "Ready: " + condition.Status
				if condition.Reason != "" {
					row.Ready += " (" + condition.Reason + ")"
				}
				break
			}
		}
		for _, endpoint := range server.Endpoints {
			address := net.JoinHostPort(endpoint.Address, strconv.Itoa(int(endpoint.Port)))
			row.Endpoints = append(row.Endpoints, address+"/"+endpoint.Protocol)
		}
		rows = append(rows, row)
	}
	slices.SortStableFunc(rows, func(a, b serverRow) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return serverListTemplate.Execute(w, rows)
}
