// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var errPrivateOutput = errors.New("private credential output failed")

// writePrivateFile persists the only client copy before any cluster mutation.
// The directory is opened separately so path replacement and symlink traversal
// cannot redirect the O_EXCL create after validation.
func writePrivateFile(path string, contents []byte) error {
	if !filepath.IsAbs(path) || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return errPrivateOutput
	}
	parent := filepath.Dir(filepath.Clean(path))
	base := filepath.Base(filepath.Clean(path))
	directoryFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errPrivateOutput
	}
	defer unix.Close(directoryFD)
	var stat unix.Stat_t
	if err := unix.Fstat(directoryFD, &stat); err != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o077 != 0 {
		return errPrivateOutput
	}
	fileFD, err := unix.Openat(directoryFD, base, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return errPrivateOutput
	}
	if err := unix.Fchmod(fileFD, 0o600); err != nil {
		_ = unix.Close(fileFD)
		return errPrivateOutput
	}
	var fileStat unix.Stat_t
	if err := unix.Fstat(fileFD, &fileStat); err != nil || fileStat.Uid != uint32(os.Geteuid()) ||
		fileStat.Mode&unix.S_IFMT != unix.S_IFREG || fileStat.Mode&0o777 != 0o600 {
		_ = unix.Close(fileFD)
		return errPrivateOutput
	}
	file := os.NewFile(uintptr(fileFD), path)
	if file == nil {
		_ = unix.Close(fileFD)
		return errPrivateOutput
	}
	complete := false
	defer func() {
		if !complete {
			_ = file.Close()
		}
	}()
	for len(contents) > 0 {
		count, writeErr := file.Write(contents)
		if writeErr != nil || count <= 0 {
			return errPrivateOutput
		}
		contents = contents[count:]
	}
	if err := file.Sync(); err != nil {
		return errPrivateOutput
	}
	if err := file.Close(); err != nil {
		return errPrivateOutput
	}
	complete = true
	if err := unix.Fsync(directoryFD); err != nil {
		return errPrivateOutput
	}
	return nil
}
