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

package admission

import (
	"errors"
	"strings"
	"testing"
)

const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestAdmitCopiesRequest(t *testing.T) {
	t.Parallel()

	replacement := []byte("replacement")
	request, err := Admit(Input{
		Target: "report.txt", ExpectedSHA256: testDigest, Replacement: replacement,
	})
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	replacement[0] = 'X'
	first := request.Replacement()
	first[0] = 'Y'
	if got := string(request.Replacement()); got != "replacement" {
		t.Fatalf("Replacement() = %q", got)
	}
	if request.Target() != "report.txt" {
		t.Fatalf("Target() = %q", request.Target())
	}
	if request.ExpectedSHA256()[0] != 0x01 {
		t.Fatal("ExpectedSHA256() differs")
	}
}

func TestAdmitAcceptsEmptyReplacement(t *testing.T) {
	t.Parallel()

	if _, err := Admit(Input{Target: "empty", ExpectedSHA256: testDigest}); err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
}

func TestAdmitRejectsTargets(t *testing.T) {
	t.Parallel()

	targets := []string{
		"", ".", "..", `sub\file`, "sub/file", `C:\file`, "stream:name",
		"*.txt", "trailing.", "trailing ", "CON", "con.txt", "COM1.log",
		"Lpt9", "COM¹", "com².txt", "COM³.log", "LPT¹", "lpt².txt", "LPT³.log",
		"PRN", "aux.txt", "NUL", "CLOCK$", "control\x1f", string([]byte{0xff}),
		strings.Repeat("a", maxFilenameUnits+1),
	}
	for _, prefix := range []string{"COM", "LPT"} {
		for digit := '1'; digit <= '9'; digit++ {
			targets = append(targets, prefix+string(digit))
		}
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			_, err := Admit(Input{Target: target, ExpectedSHA256: testDigest})
			if !errors.Is(err, ErrTarget) {
				t.Fatalf("Admit() error = %v", err)
			}
		})
	}
}

func TestAdmitRejectsDigests(t *testing.T) {
	t.Parallel()

	digests := []string{"", strings.Repeat("0", 63), strings.Repeat("0", 65),
		strings.Repeat("G", 64), strings.ToUpper(testDigest)}
	for _, digest := range digests {
		_, err := Admit(Input{Target: "file", ExpectedSHA256: digest})
		if !errors.Is(err, ErrDigest) {
			t.Fatalf("Admit(%q) error = %v", digest, err)
		}
	}
}

func TestAdmitRejectsOversizedReplacement(t *testing.T) {
	t.Parallel()

	_, err := Admit(Input{
		Target: "file", ExpectedSHA256: testDigest,
		Replacement: make([]byte, MaxReplacementBytes+1),
	})
	if !errors.Is(err, ErrReplacement) {
		t.Fatalf("Admit() error = %v", err)
	}
}

func FuzzAdmitNeverAliasesReplacement(f *testing.F) {
	f.Add("file.txt", testDigest, []byte("value"))
	f.Fuzz(func(t *testing.T, target, digest string, replacement []byte) {
		request, err := Admit(Input{
			Target: target, ExpectedSHA256: digest, Replacement: replacement,
		})
		if err != nil {
			return
		}
		got := request.Replacement()
		if len(got) == 0 {
			return
		}
		got[0] ^= 0xff
		if request.Replacement()[0] == got[0] {
			t.Fatal("request returned aliased replacement")
		}
	})
}
