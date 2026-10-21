// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package installerprofile

import (
	"bytes"
	"encoding/binary"
	"os"
	"runtime/pprof"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

var inheritedAttempt atomic.Bool

const (
	controlName        = "arcadectl-installer-cpu-v1"
	controlMagic       = "ARCADECTLCPUv1!!"
	prefixControlName  = "arcadectl-installer-cpu-prefix-v1"
	prefixControlMagic = "ARCADECTLCPUv2!!"
	matrixControlName  = "arcadectl-installer-cpu-upgrade-matrix-v1"
	matrixControlMagic = "ARCADECTLCPUv3!!"
	controlBytes       = 64
	controlFD          = 3
	outputFD           = 4
	controlSeals       = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
)

// StartInherited recognizes only the three closed two-descriptor protocols: the
// legacy full-command, fixed-prefix and deferred first-upgrade-matrix captures. It must
// be called before the installer opens files or initializes signal handling.
// Unrecognized descriptors are neither read for content, wrapped in os.File,
// written, closed, nor modified. This is local diagnostic intent, not
// cryptographic harness authentication or an installation effect capability.
func StartInherited() *Session {
	return startInheritedOnce(&inheritedAttempt, beginInherited)
}

func startInheritedOnce(attempt *atomic.Bool, begin func() *Session) *Session {
	if !attempt.CompareAndSwap(false, true) {
		return nil // No recognition, flags or cleanup on a later/concurrent call.
	}
	return begin()
}

func beginInherited() *Session {
	prefix, matrix := false, false
	if !recognizedInheritedPair(false) {
		if !recognizedInheritedPair(true) {
			if !recognizedInheritedPurpose(false, true) {
				return nil
			}
			matrix = true
		} else {
			prefix = true
		}
	}
	close := func() {
		_ = unix.Close(controlFD)
		_ = unix.Close(outputFD)
	}
	for _, fd := range []int{controlFD, outputFD} {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			close()
			return nil
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
			close()
			return nil
		}
	}
	if matrix {
		return newMatrixSession(pprof.StartCPUProfile, pprof.StopCPUProfile, func(body []byte, notStarted bool) bool {
			return flushMatrixProfile(outputFD, body, notStarted)
		}, close, func(d time.Duration, finish func()) func() bool { return time.AfterFunc(d, finish).Stop })
	}
	s := startSession(pprof.StartCPUProfile, pprof.StopCPUProfile, func(body []byte) bool {
		return flushProfileForProtocol(outputFD, body, prefix)
	}, close)
	if s != nil && prefix {
		s.armPrefixStop(func(d time.Duration, finish func()) func() bool { return time.AfterFunc(d, finish).Stop })
	}
	return s
}

func recognizedInheritedPair(prefix bool) bool {
	return recognizedInheritedPurpose(prefix, false)
}

func recognizedInheritedPurpose(prefix, matrix bool) bool {
	purpose, magic := controlName, controlMagic
	if prefix {
		purpose, magic = prefixControlName, prefixControlMagic
	}
	if matrix {
		purpose, magic = matrixControlName, matrixControlMagic
	}
	var control unix.Stat_t
	if unix.Fstat(controlFD, &control) != nil || control.Mode&unix.S_IFMT != unix.S_IFREG || control.Mode&07777 != 0400 ||
		control.Uid != uint32(os.Geteuid()) || control.Size != controlBytes || control.Nlink != 0 {
		return false
	}
	flags, err := unix.FcntlInt(controlFD, unix.F_GETFL, 0)
	if err != nil || flags&(unix.O_ACCMODE|unix.O_APPEND|unix.O_NONBLOCK|unix.O_PATH|unix.O_ASYNC) != unix.O_RDONLY {
		return false
	}
	seals, err := unix.FcntlInt(controlFD, unix.F_GET_SEALS, 0)
	if err != nil || seals != controlSeals {
		return false
	}
	name, err := os.Readlink("/proc/self/fd/3")
	if err != nil || name != "/memfd:"+purpose+" (deleted)" {
		return false
	}
	// Content is read only after exact type/owner/mode/size/access/seals/purpose
	// recognition. Pread does not move the inherited descriptor's offset.
	var record [controlBytes]byte
	n, err := unix.Pread(controlFD, record[:], 0)
	if err != nil || n != len(record) || !bytes.Equal(record[:16], []byte(magic)) ||
		binary.LittleEndian.Uint64(record[16:24]) != MaxProfileBytes || !bytes.Equal(record[48:], make([]byte, 16)) {
		return false
	}
	var output unix.Stat_t
	if unix.Fstat(outputFD, &output) != nil || output.Mode&unix.S_IFMT != unix.S_IFIFO || output.Mode&07777 != 0600 ||
		output.Uid != uint32(os.Geteuid()) || output.Dev != binary.LittleEndian.Uint64(record[24:32]) ||
		output.Ino != binary.LittleEndian.Uint64(record[32:40]) || output.Uid != binary.LittleEndian.Uint32(record[40:44]) ||
		output.Mode != binary.LittleEndian.Uint32(record[44:48]) {
		return false
	}
	flags, err = unix.FcntlInt(outputFD, unix.F_GETFL, 0)
	return err == nil && flags == unix.O_WRONLY|unix.O_NONBLOCK
}
