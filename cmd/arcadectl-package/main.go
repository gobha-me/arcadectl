// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// arcadectl-package builds or verifies offline signed installation contents.
// It never discovers trust, generates keys, connects to a cluster or publishes.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/gobha-me/arcadectl/internal/installfiles"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
)

const usage = "usage: arcadectl-package build --output ABS_PATH --signing-key ABS_PATH --trust-key ABS_PATH --version VERSION --source-sha SHA --source-epoch UNIX_SECONDS --controller-image IMAGE@sha256:DIGEST --api-image IMAGE@sha256:DIGEST [--legacy-source] [--predecessor ABS_PATH --predecessor-id ID]\n       arcadectl-package verify --package ABS_PATH --trust-key ABS_PATH\n       arcadectl-package build-baseline --output ABS_PATH --signing-key ABS_PATH --trust-key ABS_PATH --source-sha SHA --source-epoch UNIX_SECONDS\n       arcadectl-package verify-baseline --baseline ABS_PATH --trust-key ABS_PATH\n"

var errArguments = errors.New("invalid package command arguments")

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "help") {
		if n, err := io.WriteString(stdout, usage); err != nil || n != len(usage) {
			_, _ = fmt.Fprintln(stderr, "package command output unavailable")
			return 1
		}
		return 0
	}
	if len(args) < 1 {
		_, _ = fmt.Fprintln(stderr, errArguments)
		return 2
	}
	if args[0] == "build-baseline" || args[0] == "verify-baseline" {
		return runBaseline(args, stdout, stderr)
	}
	var pkg *installpackage.VerifiedPackage
	var err error
	switch args[0] {
	case "build":
		pkg, err = build(args[1:])
	case "verify":
		pkg, err = verify(args[1:])
	default:
		err = errArguments
	}
	if err != nil {
		// All returned errors are fixed sentinels. Never print flag values,
		// filesystem errors, package content, paths or cryptographic material.
		_, _ = fmt.Fprintln(stderr, err)
		if errors.Is(err, errArguments) {
			return 2
		}
		return 1
	}
	metadata, _ := pkg.Manifest()
	digest, _ := pkg.Digest()
	publicOutput := fmt.Sprintf("package %s sha256:%s\n", metadata.PackageVersion, digest)
	if n, err := io.WriteString(stdout, publicOutput); err != nil || n != len(publicOutput) {
		_, _ = fmt.Fprintln(stderr, "package command output unavailable; preserve and verify existing output")
		return 1
	}
	return 0
}

func flags(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func build(args []string) (*installpackage.VerifiedPackage, error) {
	set := flags("build")
	output := set.String("output", "", "new absolute output directory")
	signingPath := set.String("signing-key", "", "external private Ed25519 key")
	trustPath := set.String("trust-key", "", "external trusted Ed25519 public key")
	version := set.String("version", "", "explicit package version")
	source := set.String("source-sha", "", "explicit full source SHA")
	epoch := set.Int64("source-epoch", 0, "explicit source timestamp")
	controller := set.String("controller-image", "", "controller digest image")
	api := set.String("api-image", "", "API digest image")
	legacy := set.Bool("legacy-source", false, "render genuine frozen predecessor assets")
	previousPath := set.String("predecessor", "", "externally trusted genuine predecessor package")
	previousID := set.String("predecessor-id", "", "explicit supported predecessor ID")
	if set.Parse(args) != nil || set.NArg() != 0 || *output == "" || *signingPath == "" || *trustPath == "" || *version == "" || *source == "" || *epoch <= 0 || *controller == "" || *api == "" || (*previousPath == "") != (*previousID == "") || *legacy != (*source == installrender.LegacySourceSHA) || *legacy && *previousPath != "" {
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
	images := installpackage.Images{Controller: *controller, API: *api}
	payloads, crds, err := installrender.RenderPayloads(images, *legacy)
	if err != nil {
		return nil, err
	}
	metadata := installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: *version, SourceSHA: *source, SourceEpoch: *epoch, Images: images, Profiles: installrender.SupportedProfiles(*legacy), Prerequisites: installrender.RequiredPrerequisites(), CRDs: crds}
	if *previousPath != "" {
		previous, err := installfiles.Load(*previousPath, trust)
		if err != nil {
			return nil, err
		}
		if err := compileAll(previous); err != nil {
			return nil, err
		}
		before, _ := previous.Manifest()
		if before.SourceSHA != installrender.LegacySourceSHA || len(before.Predecessors) != 0 {
			return nil, installrender.ErrInvalid
		}
		digest, _ := previous.Digest()
		metadata.Predecessors = []installpackage.Predecessor{{ID: *previousID, PackageSHA256: digest, SourceSHA: before.SourceSHA, Images: before.Images, Namespace: installrender.DefaultNamespace, ProfileIDs: []string{installrender.Profile137}}}
	}
	manifest, err := installpackage.Build(metadata, payloads)
	if err != nil {
		return nil, err
	}
	signature, err := installpackage.Sign(manifest, key)
	if err != nil {
		return nil, err
	}
	pkg, err := installpackage.Verify(manifest, signature, payloads, trust)
	if err != nil {
		return nil, err
	}
	if err := compileAll(pkg); err != nil {
		return nil, err
	}
	if err := installfiles.Write(*output, manifest, signature, payloads, trust); err != nil {
		return nil, err
	}
	return pkg, nil
}

func verify(args []string) (*installpackage.VerifiedPackage, error) {
	set := flags("verify")
	path := set.String("package", "", "signed package directory")
	trustPath := set.String("trust-key", "", "external trusted Ed25519 public key")
	if set.Parse(args) != nil || set.NArg() != 0 || *path == "" || *trustPath == "" {
		return nil, errArguments
	}
	trust, err := installfiles.ReadTrustKey(*trustPath)
	if err != nil {
		return nil, err
	}
	pkg, err := installfiles.Load(*path, trust)
	if err != nil {
		return nil, err
	}
	if err := compileAll(pkg); err != nil {
		return nil, err
	}
	return pkg, nil
}

func compileAll(pkg *installpackage.VerifiedPackage) error {
	metadata, err := pkg.Manifest()
	if err != nil {
		return err
	}
	for _, profile := range metadata.Profiles {
		if _, err := installrender.Compile(pkg, installrender.DefaultNamespace, profile.ID); err != nil {
			return err
		}
	}
	return nil
}
