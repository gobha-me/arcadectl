// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installfiles"
	"github.com/gobha-me/arcadectl/internal/installrender"
)

func runBaseline(args []string, stdout, stderr io.Writer) int {
	var artifact *installbaseline.Verified
	var err error
	if args[0] == "build-baseline" {
		artifact, err = buildBaseline(args[1:])
	} else {
		artifact, err = verifyBaseline(args[1:])
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err) // fixed sentinels only
		if errors.Is(err, errArguments) {
			return 2
		}
		return 1
	}
	metadata, _ := artifact.Manifest()
	digest, _ := artifact.Digest()
	message := fmt.Sprintf("security baseline %s sha256:%s\n", metadata.BaselineVersion, digest)
	if n, err := io.WriteString(stdout, message); err != nil || n != len(message) {
		_, _ = fmt.Fprintln(stderr, "package command output unavailable; preserve and verify existing output")
		return 1
	}
	return 0
}

func buildBaseline(args []string) (*installbaseline.Verified, error) {
	set := flags("build-baseline")
	output := set.String("output", "", "new absolute separate security artifact directory")
	signingPath := set.String("signing-key", "", "external private Ed25519 key")
	trustPath := set.String("trust-key", "", "external trusted Ed25519 public key")
	source := set.String("source-sha", "", "full source SHA containing the reviewed baseline")
	epoch := set.Int64("source-epoch", 0, "explicit source timestamp")
	if set.Parse(args) != nil || set.NArg() != 0 || *output == "" || *signingPath == "" || *trustPath == "" || *source == "" || *source == installrender.LegacySourceSHA || *epoch <= 0 {
		return nil, errArguments
	}
	key, err := installfiles.ReadSigningKey(*signingPath)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	trust, err := installfiles.ReadTrustKey(*trustPath)
	if err != nil {
		return nil, err
	}
	manifest, payload, err := installbaseline.Build(*source, *epoch)
	if err != nil {
		return nil, err
	}
	signature, err := installbaseline.Sign(manifest, key)
	if err != nil {
		return nil, err
	}
	artifact, err := installbaseline.Verify(manifest, signature, payload, trust)
	if err != nil {
		return nil, err
	}
	if err := compileBaseline(artifact); err != nil {
		return nil, err
	}
	if err := installfiles.WriteBaseline(*output, manifest, signature, payload, trust); err != nil {
		return nil, err
	}
	return artifact, nil
}

func verifyBaseline(args []string) (*installbaseline.Verified, error) {
	set := flags("verify-baseline")
	path := set.String("baseline", "", "signed security baseline directory")
	trustPath := set.String("trust-key", "", "external trusted Ed25519 public key")
	if set.Parse(args) != nil || set.NArg() != 0 || *path == "" || *trustPath == "" {
		return nil, errArguments
	}
	trust, err := installfiles.ReadTrustKey(*trustPath)
	if err != nil {
		return nil, err
	}
	artifact, err := installfiles.LoadBaseline(*path, trust)
	if err != nil {
		return nil, err
	}
	if err := compileBaseline(artifact); err != nil {
		return nil, err
	}
	return artifact, nil
}

func compileBaseline(artifact *installbaseline.Verified) error {
	metadata, err := artifact.Manifest()
	if err != nil {
		return err
	}
	// This builder cannot attribute new protection to the frozen predecessor.
	// External metadata is a declaration, never a source-provenance proof.
	if metadata.SourceSHA == installrender.LegacySourceSHA {
		return installbaseline.ErrInvalid
	}
	for _, profile := range metadata.Profiles {
		if _, err := installbaseline.Compile(artifact, installrender.DefaultNamespace, profile); err != nil {
			return err
		}
	}
	return nil
}
