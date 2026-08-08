// Copyright © 2026 @sudocelestia. All rights reserved.
//
// PROPRIETARY AND CONFIDENTIAL SOURCE CODE.
//
// No licence, permission or authorisation is granted to use, copy, modify,
// compile, execute, distribute, publish, sublicense or otherwise exploit this
// file, except to the limited extent unavoidably permitted by applicable law
// or GitHub's Terms of Service.
//
// See the LICENSE file at the repository root for the complete terms.

//go:build linux && amd64

package linuxamd64feasibility

import (
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type clone3Pipes struct {
	readyRead  *os.File
	readyWrite *os.File
	gateRead   *os.File
	gateWrite  *os.File
}

func newClone3Pipes() (clone3Pipes, error) {
	readyRead, readyWrite, err := newClone3Pipe("clone3-ready")
	if err != nil {
		return clone3Pipes{}, err
	}
	gateRead, gateWrite, err := newClone3Pipe("clone3-gate")
	if err != nil {
		return clone3Pipes{}, errors.Join(readyRead.Close(), readyWrite.Close(), err)
	}
	if err := unix.SetNonblock(int(readyRead.Fd()), true); err != nil {
		return clone3Pipes{}, errors.Join(readyRead.Close(), readyWrite.Close(), gateRead.Close(), gateWrite.Close(), err)
	}
	return clone3Pipes{
		readyRead:  readyRead,
		readyWrite: readyWrite,
		gateRead:   gateRead,
		gateWrite:  gateWrite,
	}, nil
}

func newClone3Pipe(name string) (*os.File, *os.File, error) {
	var descriptors [2]int
	if err := unix.Pipe2(descriptors[:], unix.O_CLOEXEC); err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(descriptors[0]), name+"-read"), os.NewFile(uintptr(descriptors[1]), name+"-write"), nil
}

func (pipes *clone3Pipes) closeChildEnds() error {
	return errors.Join(pipes.readyWrite.Close(), pipes.gateRead.Close())
}

func (pipes *clone3Pipes) closeParentEnds() error {
	return errors.Join(pipes.readyRead.Close(), pipes.gateWrite.Close())
}

func (pipes *clone3Pipes) readyEmpty() error {
	var byte [1]byte
	count, err := unix.Read(int(pipes.readyRead.Fd()), byte[:])
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
		return nil
	}
	if err != nil {
		return err
	}
	if count == 0 {
		return io.EOF
	}
	return errCgroupEventsMalformed
}

func (pipes *clone3Pipes) release() error {
	return writeUnixFile(&unixFile{fd: int(pipes.gateWrite.Fd())}, []byte{clone3GateByte})
}

func (pipes *clone3Pipes) waitReady(deadline time.Time) error {
	if err := pollPipe(int(pipes.readyRead.Fd()), deadline); err != nil {
		return err
	}
	var byte [1]byte
	count, err := unix.Read(int(pipes.readyRead.Fd()), byte[:])
	if err != nil {
		return err
	}
	if count != 1 || byte[0] != clone3ReadyByte {
		return errCgroupEventsMalformed
	}
	return nil
}

func pollPipe(fd int, deadline time.Time) error {
	pollFD, err := pollDescriptor(fd)
	if err != nil {
		return err
	}
	for {
		milliseconds, expired := pollMilliseconds(deadline)
		if expired {
			return errCgroupDeadlineExceeded
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: pollFD, Events: unix.POLLIN}}, milliseconds)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if ready == 0 {
			return errCgroupDeadlineExceeded
		}
		return nil
	}
}
