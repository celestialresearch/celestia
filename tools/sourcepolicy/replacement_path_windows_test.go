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

//go:build windows

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReplacementPathRejectsJunction(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	external := filepath.Join(base, "external")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(external, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "junction")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx, "cmd.exe", "/d", "/c", "mklink", "/J", "root\\junction", "external",
	)
	command.Dir = base
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("create junction: %v: %s", err, strings.TrimSpace(string(output)))
	}
	linked, err := replacementPathLinked(root, junction)
	if err != nil {
		t.Fatal(err)
	}
	if !linked {
		t.Fatal("junction replacement was accepted")
	}
}
