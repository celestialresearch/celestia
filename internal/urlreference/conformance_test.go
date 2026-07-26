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

package urlreference

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
)

type conformanceFixture struct {
	Version  int               `json:"version"`
	Accepted []conformanceCase `json:"accepted"`
	Rejected []string          `json:"rejected"`
}

type conformanceCase struct {
	Input  string `json:"input"`
	Fang   string `json:"fang"`
	Defang string `json:"defang"`
}

func TestConformanceFixture(t *testing.T) {
	t.Parallel()

	fixture := loadConformanceFixture(t)
	for _, test := range fixture.Accepted {
		assertConformanceCase(t, test)
	}
	for _, input := range fixture.Rejected {
		if _, err := Transform(input, Defang); err == nil {
			t.Fatalf("rejected input accepted: %q", input)
		}
	}
}

func loadConformanceFixture(t *testing.T) conformanceFixture {
	t.Helper()

	data, err := os.ReadFile("../../testdata/url-reference-v0.json")
	if err != nil {
		t.Fatalf("read conformance fixture: %v", err)
	}
	var fixture conformanceFixture
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode conformance fixture: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("trailing conformance fixture data: %v", err)
	}
	if fixture.Version != 0 || len(fixture.Accepted) == 0 || len(fixture.Rejected) == 0 {
		t.Fatalf("invalid conformance fixture: %+v", fixture)
	}
	return fixture
}

func assertConformanceCase(t *testing.T, test conformanceCase) {
	t.Helper()

	for mode, expected := range map[Mode]string{
		Fang:   test.Fang,
		Defang: test.Defang,
	} {
		actual, err := Transform(test.Input, mode)
		if err != nil || actual != expected {
			t.Fatalf("%s %q = %q, %v; want %q", mode, test.Input, actual, err, expected)
		}
	}
}
