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

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errWrite
}

func TestInspectDocumentsBounds(t *testing.T) {
	t.Parallel()

	limits := streamLimits{documents: 1, pathBytes: 5, dataBytes: 8, totalBytes: 13}
	valid := "a.yml\x00jobs: {}\x00"
	tests := []struct {
		name   string
		input  string
		limits streamLimits
		want   string
	}{
		{name: "valid", input: valid, limits: limits},
		{name: "path", input: "ab.yml\x00jobs: {}\x00", limits: limits, want: "field exceeds limit"},
		{name: "document", input: "a.yml\x00jobs: {}\n\x00", limits: limits, want: "field exceeds limit"},
		{name: "count", input: valid + valid, limits: limits, want: "document count exceeds limit"},
		{
			name:   "corpus",
			input:  valid,
			limits: streamLimits{documents: 1, pathBytes: 5, dataBytes: 8, totalBytes: 12},
			want:   "document corpus exceeds limit",
		},
		{name: "truncated path", input: "a.yml", limits: limits, want: "field is truncated"},
		{name: "missing document", input: "a.yml\x00", limits: limits, want: "action document is missing"},
		{name: "truncated document", input: "a.yml\x00jobs:{}", limits: limits, want: "field is truncated"},
		{
			name:   "invalid limits",
			input:  valid,
			limits: streamLimits{},
			want:   "limits must be positive",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := inspectDocuments(
				strings.NewReader(test.input),
				&bytes.Buffer{},
				actionsMode,
				test.limits,
			)
			if test.want == "" {
				if err != nil {
					t.Fatalf("inspectDocuments() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("inspectDocuments() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestInspectDocumentsBoundsAliasExpansion(t *testing.T) {
	t.Parallel()

	var input strings.Builder
	input.WriteString("level0: &level0 [value, value, value, value, value, value, value, value, value, value]\n")
	for level := 1; level <= 7; level++ {
		fmt.Fprintf(&input, "level%d: &level%d [", level, level)
		for item := range 10 {
			if item > 0 {
				input.WriteString(", ")
			}
			fmt.Fprintf(&input, "*level%d", level-1)
		}
		input.WriteString("]\n")
	}

	stream := "main.yml\x00" + input.String() + "\x00"
	err := inspectDocuments(
		strings.NewReader(stream),
		&bytes.Buffer{},
		actionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 4096, totalBytes: 4160},
	)
	if err == nil || !strings.Contains(err.Error(), "traversal budget") {
		t.Fatalf("inspectDocuments() error = %v, want traversal budget rejection", err)
	}
}

func TestInspectDocumentsBoundsNesting(t *testing.T) {
	t.Parallel()

	input := strings.Repeat("[", maxYAMLDepth+1) +
		"value" +
		strings.Repeat("]", maxYAMLDepth+1)
	stream := "main.yml\x00value: " + input + "\x00"
	err := inspectDocuments(
		strings.NewReader(stream),
		&bytes.Buffer{},
		actionsMode,
		streamLimits{documents: 1, pathBytes: 64, dataBytes: 2048, totalBytes: 2112},
	)
	if err == nil || !strings.Contains(err.Error(), "depth limit") {
		t.Fatalf("inspectDocuments() error = %v, want depth rejection", err)
	}
}

func TestReadFieldBoundaries(t *testing.T) {
	t.Parallel()
	value, eof, err := readField(
		bufio.NewReader(strings.NewReader(strings.Repeat("a", 5000)+"\x00")),
		6000,
		false,
	)
	if err != nil || eof || len(value) != 5000 {
		t.Fatalf("buffered field length=%d eof=%t error=%v", len(value), eof, err)
	}
	if _, _, err := readField(
		bufio.NewReader(strings.NewReader("\x00")), 1, false,
	); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty field error = %v", err)
	}
	if _, _, err := readField(
		bufio.NewReaderSize(failingReader{}, 1), 1, false,
	); !errors.Is(err, errWrite) {
		t.Fatalf("reader error = %v", err)
	}
	if _, _, err := readField(
		bufio.NewReader(io.LimitReader(strings.NewReader("abc"), 3)),
		3,
		false,
	); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated field error = %v", err)
	}
}
