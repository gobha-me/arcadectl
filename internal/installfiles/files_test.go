// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installfiles

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"golang.org/x/sys/unix"
)

func fakeKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x19}, ed25519.SeedSize))
}
func fakeTrust() ed25519.PublicKey { return fakeKey().Public().(ed25519.PublicKey) }

func packageDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if os.Mkdir(filepath.Join(directory, "manifests"), 0755) != nil {
		t.Fatal("create public package directory")
	}
	metadata := installpackage.Manifest{
		FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion,
		PackageVersion: "0.1.0-rc.1", SourceSHA: strings.Repeat("a", 40), SourceEpoch: 1791223200,
		Images:        installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("b", 64), API: "registry.example/api@sha256:" + strings.Repeat("c", 64)},
		Profiles:      []installpackage.Profile{{ID: "kubernetes-1.35.8", KubernetesVersion: "1.35.8", PodSecurityVersion: "v1.35"}},
		Prerequisites: []string{"api-tls", "restricted-pods"},
	}
	for _, name := range installpackage.CanonicalCRDNames() {
		metadata.CRDs = append(metadata.CRDs, installpackage.CRD{Name: name, SchemaSHA256: strings.Repeat("d", 64), StorageVersion: "v1alpha1", ServedVersions: []string{"v1alpha1"}, ConversionStrategy: "None"})
	}
	payloads := map[string][]byte{installpackage.AnchorsPath: []byte("anchors\n"), installpackage.APIPath: []byte("api\n"), installpackage.ControllerPath: []byte("controller\n")}
	manifest, err := installpackage.Build(metadata, payloads)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := installpackage.Sign(manifest, fakeKey())
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range payloads {
		if os.WriteFile(filepath.Join(directory, name), body, 0644) != nil {
			t.Fatal("write public package payload")
		}
	}
	for name, body := range map[string][]byte{ManifestName: manifest, SignatureName: signature} {
		if os.WriteFile(filepath.Join(directory, name), body, 0644) != nil {
			t.Fatal("write package envelope")
		}
	}
	return directory
}

func TestLoadExactSignedDirectory(t *testing.T) {
	directory := packageDirectory(t)
	pkg, err := Load(directory, fakeTrust())
	if err != nil || !pkg.IsVerified() {
		t.Fatal("valid signed directory rejected")
	}
	first, _ := pkg.Digest()
	second, err := Load(directory, fakeTrust())
	if err != nil {
		t.Fatal(err)
	}
	again, _ := second.Digest()
	if first != again {
		t.Fatal("same package had unstable identity")
	}
	if _, err := Load(directory, make(ed25519.PublicKey, ed25519.PublicKeySize)); !errors.Is(err, installpackage.ErrSignature) {
		t.Fatal("wrong trust key authenticated")
	}
	if _, err := Load(directory, nil); !errors.Is(err, ErrKey) {
		t.Fatal("missing external trust key accepted")
	}
}

func TestLoadRefusesUnexpectedEntriesAndTampering(t *testing.T) {
	for _, path := range []string{"extra", "manifests/extra", ManifestName, SignatureName, installpackage.AnchorsPath, installpackage.APIPath, installpackage.ControllerPath} {
		t.Run(path, func(t *testing.T) {
			directory := packageDirectory(t)
			if os.WriteFile(filepath.Join(directory, path), []byte("SECRET-CANARY"), 0644) != nil {
				t.Fatal("mutate package fixture")
			}
			_, err := Load(directory, fakeTrust())
			if err == nil || strings.Contains(err.Error(), "SECRET-CANARY") {
				t.Fatal("tampered/undeclared bytes accepted or reflected")
			}
		})
	}
}

func TestLoadRefusesAllSymlinksAndHardlinks(t *testing.T) {
	for _, path := range []string{ManifestName, SignatureName, "manifests", installpackage.AnchorsPath, installpackage.APIPath, installpackage.ControllerPath} {
		t.Run(path, func(t *testing.T) {
			directory := packageDirectory(t)
			target := filepath.Join(directory, path)
			// Preserve the exact package entry set: otherwise extra-file refusal
			// would mask whether O_NOFOLLOW actually rejects this symlink.
			original := filepath.Join(t.TempDir(), "original")
			if os.Rename(target, original) != nil || os.Symlink(original, target) != nil {
				t.Fatal("symlink fixture")
			}
			if _, err := Load(directory, fakeTrust()); err == nil {
				t.Fatal("symlink accepted")
			}
		})
	}
	directory := packageDirectory(t)
	link := filepath.Join(t.TempDir(), "package")
	if os.Symlink(directory, link) != nil {
		t.Fatal("root symlink fixture")
	}
	if _, err := Load(link, fakeTrust()); err == nil {
		t.Fatal("package ancestor symlink accepted")
	}
	// Keep the hardlink outside the package so entry-set validation does not
	// hide whether the descriptor's link count is checked.
	if os.Link(filepath.Join(directory, installpackage.APIPath), filepath.Join(t.TempDir(), "linked")) != nil {
		t.Fatal("hardlink fixture")
	}
	if _, err := Load(directory, fakeTrust()); err == nil {
		t.Fatal("hardlinked payload accepted")
	}
}

func TestKeyFilesRejectLinks(t *testing.T) {
	for _, private := range []bool{false, true} {
		for _, kind := range []string{"symlink", "hardlink", "ancestor-symlink"} {
			t.Run(kind+map[bool]string{false: "-public", true: "-private"}[private], func(t *testing.T) {
				publicPath, privatePath := keyFiles(t)
				path := publicPath
				if private {
					path = privatePath
				}
				switch kind {
				case "symlink":
					original := filepath.Join(t.TempDir(), "original")
					if os.Rename(path, original) != nil || os.Symlink(original, path) != nil {
						t.Fatal("key symlink fixture")
					}
				case "hardlink":
					if os.Link(path, filepath.Join(t.TempDir(), "linked")) != nil {
						t.Fatal("key hardlink fixture")
					}
				case "ancestor-symlink":
					link := filepath.Join(t.TempDir(), "linked-directory")
					if os.Symlink(filepath.Dir(path), link) != nil {
						t.Fatal("key ancestor symlink fixture")
					}
					path = filepath.Join(link, filepath.Base(path))
				}
				var err error
				if private {
					_, err = ReadSigningKey(path)
				} else {
					_, err = ReadTrustKey(path)
				}
				if !errors.Is(err, ErrKey) {
					t.Fatal("linked external key accepted")
				}
			})
		}
	}
}

func TestLoadRefusesNonRegularAndBoundedFilesWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"fifo", "directory", "oversized", "empty"} {
		t.Run(kind, func(t *testing.T) {
			directory := packageDirectory(t)
			target := filepath.Join(directory, installpackage.APIPath)
			if os.Remove(target) != nil {
				t.Fatal("remove test-owned payload")
			}
			switch kind {
			case "fifo":
				if unix.Mkfifo(target, 0600) != nil {
					t.Fatal("FIFO fixture")
				}
			case "directory":
				if os.Mkdir(target, 0700) != nil {
					t.Fatal("directory fixture")
				}
			case "empty":
				if os.WriteFile(target, nil, 0644) != nil {
					t.Fatal("empty fixture")
				}
			case "oversized":
				file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
				if err != nil {
					t.Fatal("oversize fixture")
				}
				err = file.Truncate(installpackage.MaxPayloadBytes + 1)
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatal("oversize fixture")
				}
			}
			finished := make(chan error, 1)
			go func() { _, err := Load(directory, fakeTrust()); finished <- err }()
			select {
			case err := <-finished:
				if !errors.Is(err, ErrUnavailable) {
					t.Fatal("nonregular/unbounded file accepted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("special-file load blocked")
			}
		})
	}
	for _, path := range []string{"relative", "/", "/tmp/../tmp", "\x00"} {
		if _, err := Load(path, fakeTrust()); !errors.Is(err, ErrUnavailable) {
			t.Fatal("unsafe root path accepted")
		}
	}
}

func keyFiles(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private key directory")
	}
	public, err := x509.MarshalPKIXPublicKey(fakeTrust())
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(fakeKey())
	if err != nil {
		t.Fatal(err)
	}
	publicPath, privatePath := filepath.Join(directory, "trust.pem"), filepath.Join(directory, "sign.pem")
	if os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), 0644) != nil || os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600) != nil {
		t.Fatal("write fake key files")
	}
	return publicPath, privatePath
}

func TestExternalKeyFilesRequireTypedPEMAndProtection(t *testing.T) {
	public, private := keyFiles(t)
	trust, err := ReadTrustKey(public)
	if err != nil || !bytes.Equal(trust, fakeTrust()) {
		t.Fatal("public trust key rejected")
	}
	signer, err := ReadSigningKey(private)
	if err != nil || !bytes.Equal(signer, fakeKey()) {
		t.Fatal("private signing key rejected")
	}
	if _, err := ReadTrustKey(private); !errors.Is(err, ErrKey) {
		t.Fatal("private key treated as trust key")
	}
	if _, err := ReadSigningKey(public); !errors.Is(err, ErrKey) {
		t.Fatal("public key treated as signing key")
	}
	if os.Chmod(public, 0666) != nil || os.Chmod(private, 0644) != nil {
		t.Fatal("weaken fake file permissions")
	}
	if _, err := ReadTrustKey(public); !errors.Is(err, ErrKey) {
		t.Fatal("writable-by-others trust key accepted")
	}
	if _, err := ReadSigningKey(private); !errors.Is(err, ErrKey) {
		t.Fatal("nonprivate signing key accepted")
	}
	for _, body := range []string{"SECRET-CANARY", strings.Repeat("x", maxKeyBytes+1)} {
		public, private := keyFiles(t)
		if os.WriteFile(public, []byte(body), 0644) != nil || os.WriteFile(private, []byte(body), 0600) != nil {
			t.Fatal("invalid fake key fixture")
		}
		if _, err := ReadTrustKey(public); !errors.Is(err, ErrKey) || strings.Contains(err.Error(), body) {
			t.Fatal("malformed trust key accepted or reflected")
		}
		if _, err := ReadSigningKey(private); !errors.Is(err, ErrKey) || strings.Contains(err.Error(), body) {
			t.Fatal("malformed signing key accepted or reflected")
		}
	}
	public, _ = keyFiles(t)
	body, err := os.ReadFile(public)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range [][]byte{append([]byte("preamble\n"), body...), append(bytes.Clone(body), body...)} {
		if os.WriteFile(public, changed, 0644) != nil {
			t.Fatal("invalid envelope fixture")
		}
		if _, err := ReadTrustKey(public); !errors.Is(err, ErrKey) {
			t.Fatal("extra PEM key/preamble accepted")
		}
	}
}
