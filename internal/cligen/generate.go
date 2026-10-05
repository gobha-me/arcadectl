// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package cligen generates deterministic offline help and completions.
package cligen

import (
	"bytes"
	"io"
	"sort"
	"strings"

	"github.com/gobha-me/arcadectl/internal/cli"
	"github.com/spf13/cobra"
)

func Files() (map[string][]byte, error) {
	root := cli.NewCommand(cli.Options{In: strings.NewReader(""), Out: io.Discard, Err: io.Discard})
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	root.InitDefaultHelpFlag()
	result := map[string][]byte{}
	var help bytes.Buffer
	help.WriteString("# Arcadectl command reference\n\nGenerated from the offline command tree. Do not edit manually.\n\n")
	var visit func(*cobra.Command)
	visit = func(command *cobra.Command) {
		if command.Hidden {
			return
		}
		help.WriteString("## " + command.CommandPath() + "\n\n" + command.Short + "\n\n```text\n" + command.UsageString() + "```\n\n")
		children := command.Commands()
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		for _, child := range children {
			visit(child)
		}
	}
	visit(root)
	result["commands.md"] = append(bytes.TrimRight(help.Bytes(), "\n"), '\n')
	var buffer bytes.Buffer
	if err := root.GenBashCompletionV2(&buffer, true); err != nil {
		return nil, err
	}
	result["arcadectl.bash"] = append([]byte(nil), buffer.Bytes()...)
	buffer.Reset()
	if err := root.GenZshCompletion(&buffer); err != nil {
		return nil, err
	}
	result["_arcadectl"] = append([]byte(nil), buffer.Bytes()...)
	buffer.Reset()
	if err := root.GenFishCompletion(&buffer, true); err != nil {
		return nil, err
	}
	result["arcadectl.fish"] = append([]byte(nil), buffer.Bytes()...)
	buffer.Reset()
	if err := root.GenPowerShellCompletionWithDesc(&buffer); err != nil {
		return nil, err
	}
	result["arcadectl.ps1"] = append([]byte(nil), buffer.Bytes()...)
	return result, nil
}
