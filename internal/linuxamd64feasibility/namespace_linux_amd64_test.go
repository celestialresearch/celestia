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
	"context"
	"os/exec"
	"syscall"
	"testing"
)

func TestClone3NamespaceConfiguration(t *testing.T) {
	t.Parallel()

	command := exec.CommandContext(context.Background(), "fixture")
	if err := configureClone3Namespaces(command, ownedCgroupLeaf{fd: 17}); err != nil {
		t.Fatal(err)
	}
	attributes := command.SysProcAttr
	if !validNamespaceAttributes(attributes) || len(command.Env) != 0 {
		t.Fatalf("namespace attributes = %#v environment = %#v", attributes, command.Env)
	}
	if !validIDMapping(attributes.UidMappings) || !validIDMapping(attributes.GidMappings) {
		t.Fatalf("uid mappings = %#v gid mappings = %#v", attributes.UidMappings, attributes.GidMappings)
	}
}

func validNamespaceAttributes(attributes *syscall.SysProcAttr) bool {
	return attributes != nil && attributes.Cloneflags == requiredNamespaceFlags &&
		attributes.CgroupFD == 17 && attributes.UseCgroupFD &&
		attributes.Pdeathsig == syscall.SIGKILL && !attributes.GidMappingsEnableSetgroups &&
		validNamespaceCredential(attributes.Credential)
}

func validNamespaceCredential(credential *syscall.Credential) bool {
	return credential != nil && credential.Uid == 0 && credential.Gid == 0 &&
		credential.NoSetGroups
}

func validIDMapping(mapping []syscall.SysProcIDMap) bool {
	return len(mapping) == 1 && mapping[0].ContainerID == 0 &&
		mapping[0].HostID >= 0 && mapping[0].Size == 1
}
