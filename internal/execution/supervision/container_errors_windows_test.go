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

//go:build windows && amd64

package supervision

import (
	"crypto/rand"

	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"

	"strings"
	"testing"
)

func TestContainerRejectsDuplicateProfile(t *testing.T) {
	var identity [8]byte
	if _, err := rand.Read(identity[:]); err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	name := "celestia.test." + hex.EncodeToString(identity[:])
	container, err := createContainer(name)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer closeContainer(t, &container)
	if _, err := createContainer(name); err == nil {
		t.Fatal("duplicate AppContainer profile was accepted")
	}
	if err := container.close(); err != nil {
		t.Fatalf("close container: %v", err)
	}
}

func TestContainerRejectsInvalidNames(t *testing.T) {
	if _, err := createContainer("invalid\x00name"); err == nil {
		t.Fatal("invalid AppContainer name was created")
	}
	if err := deleteContainer("invalid\x00name"); err == nil {
		t.Fatal("invalid AppContainer name was accepted")
	}
}

func TestContainerFolderRejectsMissingSID(t *testing.T) {
	t.Parallel()

	if _, err := containerFolder(nil); err == nil {
		t.Fatal("containerFolder(nil) error = nil")
	}
}

func TestContainerCloseReportsIdentity(t *testing.T) {
	container := appContainer{name: "invalid\x00name"}
	err := container.close()
	if err == nil || !strings.Contains(err.Error(), "name=") {
		t.Fatalf("close error=%v, want identity", err)
	}
}

func TestContainerCloseRetriesSIDRelease(t *testing.T) {
	sid, err := windows.StringToSid("S-1-0-0")
	if err != nil {
		t.Fatalf("create SID: %v", err)
	}
	container := appContainer{
		name:           "test",
		sid:            sid,
		profileDeleted: true,
	}
	releaseErr := errors.New("release SID")
	if err := container.closeWith(
		func(*windows.SID) error { return releaseErr },
		func(string) error { return nil },
	); !errors.Is(err, releaseErr) {
		t.Fatalf("failed release hidden: %v", err)
	}
	if container.sid == nil || container.sidReleased {
		t.Fatal("failed SID release marked complete")
	}
	if err := container.closeWith(
		func(*windows.SID) error { return nil },
		func(string) error { return nil },
	); err != nil {
		t.Fatalf("retry SID release: %v", err)
	}
	if container.sid != nil || !container.sidReleased {
		t.Fatal("successful SID release not retained")
	}
}
