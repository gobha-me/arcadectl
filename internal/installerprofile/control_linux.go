// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package installerprofile

import (
	"encoding/binary"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// newControlForPipe constructs a purpose-specific immutable control for a
// caller-owned pipe. It does not discover/open arbitrary paths or store keys.
func newControlForPipe(pipe unix.Stat_t) (*os.File, error) {
	if pipe.Mode&unix.S_IFMT != unix.S_IFIFO || pipe.Mode&07777 != 0600 || pipe.Uid != uint32(os.Geteuid()) {
		return nil, errIncomplete
	}
	fd, err := unix.MemfdCreate(controlName, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, errIncomplete
	}
	defer unix.Close(fd)
	var record [controlBytes]byte
	copy(record[:16], controlMagic)
	binary.LittleEndian.PutUint64(record[16:24], MaxProfileBytes)
	binary.LittleEndian.PutUint64(record[24:32], pipe.Dev)
	binary.LittleEndian.PutUint64(record[32:40], pipe.Ino)
	binary.LittleEndian.PutUint32(record[40:44], pipe.Uid)
	binary.LittleEndian.PutUint32(record[44:48], pipe.Mode)
	if n, err := unix.Write(fd, record[:]); err != nil || n != len(record) || unix.Fchmod(fd, 0400) != nil {
		return nil, errIncomplete
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, controlSeals); err != nil {
		return nil, errIncomplete
	}
	// Seals/chmod do not change the original O_RDWR access mode. Reopen only our
	// still-owned exact memfd read-only; close the writable copy on return.
	readFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errIncomplete
	}
	return os.NewFile(uintptr(readFD), controlName), nil
}
