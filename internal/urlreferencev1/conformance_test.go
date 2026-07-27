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
	"strings"
	"testing"
)

type conformanceFixture struct {
	Version  int               `json:"version"`
	Bounds   conformanceBounds `json:"boundaries"`
	Accepted []conformanceCase `json:"accepted"`
	Rejected []string          `json:"rejected"`
}

type conformanceBounds struct {
	LabelMax      int `json:"label_max"`
	HostMax       int `json:"host_max"`
	InputMax      int `json:"input_max"`
	PortDigitsMax int `json:"port_digits_max"`
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
		for _, mode := range []Mode{Fang, Defang} {
			if _, err := Transform(input, mode); err == nil {
				t.Fatalf("%s accepted rejected input: %q", mode, input)
			}
		}
	}
	assertConformanceBoundaries(t, fixture.Bounds)
}

func loadConformanceFixture(t *testing.T) conformanceFixture {
	t.Helper()

	data, err := os.ReadFile("../../testdata/url-reference-v1.json")
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
	if fixture.Version != 1 ||
		fixture.Bounds != (conformanceBounds{63, 253, 4096, 5}) ||
		len(fixture.Accepted) == 0 ||
		len(fixture.Rejected) == 0 {
		t.Fatalf("invalid conformance fixture: %+v", fixture)
	}
	return fixture
}

func assertConformanceBoundaries(t *testing.T, bounds conformanceBounds) {
	t.Helper()

	label := strings.Repeat("a", bounds.LabelMax)
	host := label + "." + label + "." + label + "." + strings.Repeat("a", 61)
	accepted := []string{
		"https://" + label + ".test/",
		"https://" + host + "/",
		"https://example.test:1/",
		"https://example.test:65535/",
	}
	prefix := "https://example.test/"
	accepted = append(accepted, prefix+strings.Repeat("a", bounds.InputMax-len(prefix)))
	rejected := []string{
		"https://" + strings.Repeat("a", bounds.LabelMax+1) + ".test/",
		"https://" + host + "a/",
		"https://example.test:0/",
		"https://example.test:65536/",
		prefix + strings.Repeat("a", bounds.InputMax-len(prefix)+1),
	}
	for _, input := range accepted {
		if err := ValidateInput(input); err != nil {
			t.Fatalf("boundary input rejected: length=%d error=%v", len(input), err)
		}
	}
	for _, input := range rejected {
		if err := ValidateInput(input); err == nil {
			t.Fatalf("out-of-bound input accepted: length=%d", len(input))
		}
	}
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
