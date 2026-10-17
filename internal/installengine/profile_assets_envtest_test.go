//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// The reviewed controller-tools index has 1.35.0, not the declared 1.35.8
// patch. Keep its checksum-pinned etcd/kubectl, but run the exact upstream
// 1.35.8 API-server binary. Never certify a nearby patch as the declared one.
func prerequisite135Assets(t *testing.T, environment *envtest.Environment) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("declared 1.35.8 API-server fixture is pinned for Linux amd64")
	}
	base := environment.BinaryAssetsDirectory
	archive := filepath.Join(base, "envtest.tar.gz")
	fixtureDownload(t, "https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-v1.35.0/envtest-v1.35.0-linux-amd64.tar.gz", archive, sha512.New(), "130369c16f076e724d089189afaede960316f5f5dea6cf57be7a4fc6f09c77342893192509790e4056e116e232dff832ed863f5bd55dcb55d38f3ab834828a11", 96<<20)
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	reader := tar.NewReader(z)
	seen := map[string]bool{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == "controller-tools/envtest/" && header.Typeflag == tar.TypeDir {
			continue
		}
		name := filepath.Base(header.Name)
		if header.Typeflag != tar.TypeReg || header.Name != "controller-tools/envtest/"+name || name != "etcd" && name != "kubectl" && name != "kube-apiserver" || header.Size <= 0 || header.Size > 256<<20 || seen[name] {
			t.Fatal("unreviewed envtest archive member")
		}
		seen[name] = true
		if name == "kube-apiserver" {
			continue // do not install the wrong API-server patch
		}
		file, err := os.OpenFile(filepath.Join(base, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
		if err != nil {
			t.Fatal(err)
		}
		_, copyErr := io.Copy(file, reader)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatal("envtest fixture extraction failed")
		}
	}
	if len(seen) != 3 {
		t.Fatal("incomplete envtest archive")
	}
	path := filepath.Join(base, "kube-apiserver")
	fixtureDownload(t, "https://dl.k8s.io/release/v1.35.8/bin/linux/amd64/kube-apiserver", path, sha256.New(), "1d7b61300f796f257bde37f6699f460bc401d4fa5a7a7c133d8dc00fe39abeed", 256<<20)
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	environment.DownloadBinaryAssets = false
	environment.ControlPlane.APIServer = &envtest.APIServer{Path: path}
	environment.ControlPlane.Etcd = &envtest.Etcd{Path: filepath.Join(base, "etcd")}
	environment.ControlPlane.KubectlPath = filepath.Join(base, "kubectl")
}

func fixtureDownload(t *testing.T, url, path string, digest hash.Hash, expected string, limit int64) {
	t.Helper()
	client := &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) > 5 {
			return ErrRead
		}
		return nil
	}}
	response, err := client.Get(url)
	if err != nil {
		t.Fatal("pinned public fixture download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("pinned public fixture download refused")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	n, copyErr := io.Copy(io.MultiWriter(f, digest), io.LimitReader(response.Body, limit+1))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil || n > limit || n == 0 || hex.EncodeToString(digest.Sum(nil)) != expected {
		t.Fatal("pinned public fixture checksum/size verification failed")
	}
}
