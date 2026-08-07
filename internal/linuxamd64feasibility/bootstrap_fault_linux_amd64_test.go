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
	"net"
	"strconv"
	"testing"
)

func TestClone3NamespacePreparationFailures(t *testing.T) {
	failure := errors.New("namespace failure")
	operations := bootstrapNamespaceOps{
		getpid:      func() int { return 1 },
		sethostname: func([]byte) error { return nil },
		mount:       func(string, string, string, uintptr, string) error { return nil },
		filesystem:  func() error { return nil },
		interfaceByName: func(string) (*net.Interface, error) {
			return &net.Interface{}, nil
		},
	}
	tests := map[string]func(*bootstrapNamespaceOps){
		"pid":      func(ops *bootstrapNamespaceOps) { ops.getpid = func() int { return 2 } },
		"hostname": func(ops *bootstrapNamespaceOps) { ops.sethostname = func([]byte) error { return failure } },
		"mount": func(ops *bootstrapNamespaceOps) {
			ops.mount = func(string, string, string, uintptr, string) error { return failure }
		},
		"filesystem": func(ops *bootstrapNamespaceOps) { ops.filesystem = func() error { return failure } },
		"interface": func(ops *bootstrapNamespaceOps) {
			ops.interfaceByName = func(string) (*net.Interface, error) { return nil, failure }
		},
		"loopback": func(ops *bootstrapNamespaceOps) {
			ops.interfaceByName = func(string) (*net.Interface, error) {
				return &net.Interface{Flags: net.FlagUp}, nil
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := operations
			mutate(&candidate)
			if err := prepareClone3NamespaceWith(candidate); err == nil {
				t.Fatal("preparation failure accepted")
			}
		})
	}
	if err := prepareClone3NamespaceWith(operations); err != nil {
		t.Fatalf("valid preparation rejected: %v", err)
	}
}

func TestClone3FilesystemPreparationOrder(t *testing.T) {
	failure := errors.New("filesystem failure")
	for failAt := 0; failAt <= 10; failAt++ {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			calls := 0
			step := func() error {
				calls++
				if calls == failAt {
					return failure
				}
				return nil
			}
			operations := bootstrapFilesystemOps{
				mount:     func(string, string, string, uintptr, string) error { return step() },
				mkdir:     func(string, uint32) error { return step() },
				pivotRoot: func(string, string) error { return step() },
				chdir:     func(string) error { return step() },
				unmount:   func(string, int) error { return step() },
				rmdir:     func(string) error { return step() },
			}
			err := prepareClone3FilesystemWith(operations)
			if failAt == 0 {
				if err != nil || calls != 10 {
					t.Fatalf("calls=%d err=%v", calls, err)
				}
				return
			}
			if !errors.Is(err, failure) || calls != failAt {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}
