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
	"errors"
	"strings"
	"testing"
)

func TestTransform(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		mode     Mode
		expected string
	}{
		{"defang HTTP", "http://example.test", Defang, "hxxp://example[.]test"},
		{"defang HTTPS", "https://example.test", Defang, "hxxps://example[.]test"},
		{"fang HTTP", "hxxp://example[.]test", Fang, "http://example.test"},
		{"fang HTTPS", "hxxps://example[.]test", Fang, "https://example.test"},
		{"already active", "https://example.test", Fang, "https://example.test"},
		{"already defanged", "hxxps://example[.]test", Defang, "hxxps://example[.]test"},
		{"port", "https://example.test:00443", Defang, "hxxps://example[.]test:00443"},
		{"suffix", "https://example.test/a.b?q=1.2#f.g", Defang, "hxxps://example[.]test/a.b?q=1.2#f.g"},
		{"suffix delimiters", "https://example.test/a?b?c#d?e#f", Defang, "hxxps://example[.]test/a?b?c#d?e#f"},
		{"IPv4", "https://192.0.2.10/a.exe", Defang, "hxxps://192[.]0[.]2[.]10/a.exe"},
		{"IPv6", "https://[2001:db8::1]/", Defang, "hxxps://[2001:db8::1]/"},
		{"IPv6 hex mapped", "https://[::ffff:c000:201]/", Defang, "hxxps://[::ffff:c000:201]/"},
		{"IPv6 port", "https://[2001:db8::1]:443/", Defang, "hxxps://[2001:db8::1]:443/"},
		{"root separator", "https://example.test./", Defang, "hxxps://example[.]test[.]/"},
		{"single label", "https://localhost/a", Defang, "hxxps://localhost/a"},
		{"punycode", "https://xn--bcher-kva.example/", Defang, "hxxps://xn--bcher-kva[.]example/"},
		{"percent triplet", "https://example.test/a%2Eb", Defang, "hxxps://example[.]test/a%2Eb"},
		{"four DNS labels", "https://one.two.three.four/", Defang, "hxxps://one[.]two[.]three[.]four/"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			actual, err := Transform(test.input, test.mode)
			if err != nil {
				t.Fatalf("Transform() error = %v", err)
			}
			if actual != test.expected {
				t.Fatalf("Transform() = %q, want %q", actual, test.expected)
			}
		})
	}
}

func TestTransformRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"oversized", "https://" + strings.Repeat("a", MaxReferenceBytes)},
		{"missing scheme", "example.test"},
		{"uppercase scheme", "HTTPS://example.test"},
		{"empty host", "https:///path"},
		{"empty port", "https://example.test:"},
		{"zero port", "https://example.test:0"},
		{"large port", "https://example.test:65536"},
		{"non-decimal port", "https://example.test:abc"},
		{"user information", "https://user@example.test/"},
		{"empty host with port", "https://:443/"},
		{"mixed state active scheme", "https://example[.]test/"},
		{"mixed state defanged scheme", "hxxps://example.test/"},
		{"mixed host", "hxxps://a[.]b.c/"},
		{"invalid IPv4", "https://256.0.2.1/"},
		{"IPv4 leading zero", "https://192.00.2.1/"},
		{"unbracketed IPv6", "https://2001:db8::1/"},
		{"unclosed IPv6", "https://[2001:db8::1/"},
		{"invalid IPv6 character", "https://[2001:db8::g]/"},
		{"invalid IPv6 form", "https://[2001:db8:::1]/"},
		{"IPv6 authority suffix", "https://[2001:db8::1]x/"},
		{"mapped IPv6", "https://[::ffff:192.0.2.1]/"},
		{"IPv6 zone", "https://[fe80::1%25eth0]/"},
		{"Unicode host", "https://bücher.example/"},
		{"Unicode lookalike", "https://example。test/"},
		{"invalid percent", "https://example.test/%2"},
		{"embedded NUL", "https://example.test/\x00"},
		{"leading whitespace", " https://example.test/"},
		{"trailing whitespace", "https://example.test/ "},
		{"byte-order mark", "\uFEFFhttps://example.test/"},
		{"wrapped dot", "hxxps://example[dot]test/"},
		{"long label", "https://" + strings.Repeat("a", 64) + ".test/"},
		{"leading hyphen", "https://-example.test/"},
		{"trailing hyphen", "https://example-.test/"},
		{"long host", "https://" + strings.Repeat("a.", 127) + "aa/"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Transform(test.input, Defang)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Transform() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestTransformRejectsMode(t *testing.T) {
	t.Parallel()

	_, err := Transform("https://example.test/", "invalid")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Transform() error = %v, want ErrInvalid", err)
	}
}

func TestValidateInput(t *testing.T) {
	t.Parallel()

	if err := ValidateInput("https://example.test/"); err != nil {
		t.Fatalf("ValidateInput() error = %v", err)
	}
	expanded := "hxxps://" + strings.Repeat("a[.]", 126) + "a/" + strings.Repeat("x", 3834)
	if len(expanded) <= MaxInputBytes {
		t.Fatal("fixture did not exceed original input limit")
	}
	if err := ValidateInput(expanded); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ValidateInput() error = %v, want ErrInvalid", err)
	}
}

func TestTransformProperties(t *testing.T) {
	t.Parallel()

	activeInputs := []string{
		"http://example.test",
		"https://sub.example.test:443/a.b?q=1.2#x.y",
		"https://192.0.2.10/",
		"https://[2001:db8::1]/",
		"https://xn--bcher-kva.example/",
	}
	for _, input := range activeInputs {
		defanged, err := Transform(input, Defang)
		if err != nil {
			t.Fatalf("defang %q: %v", input, err)
		}
		repeated, err := Transform(defanged, Defang)
		if err != nil || repeated != defanged {
			t.Fatalf("defang idempotency for %q: got %q, %v", input, repeated, err)
		}
		restored, err := Transform(defanged, Fang)
		if err != nil || restored != input {
			t.Fatalf("round trip for %q: got %q, %v", input, restored, err)
		}
	}
}

func TestTransformMaximumExpansion(t *testing.T) {
	t.Parallel()

	input := "https://" + strings.Repeat("a.", 126) + "a/" + strings.Repeat("x", 3834)
	if len(input) != MaxInputBytes {
		t.Fatalf("fixture length = %d, want %d", len(input), MaxInputBytes)
	}
	defanged, err := Transform(input, Defang)
	if err != nil {
		t.Fatalf("Transform() error = %v", err)
	}
	if len(defanged) != 4348 {
		t.Fatalf("defanged length = %d, want 4348", len(defanged))
	}
	repeated, err := Transform(defanged, Defang)
	if err != nil || repeated != defanged {
		t.Fatalf("idempotency = %q, %v", repeated, err)
	}
	restored, err := Transform(defanged, Fang)
	if err != nil || restored != input {
		t.Fatalf("round trip changed maximum input: %v", err)
	}
}

func TestTransformRejectsOversizedOutput(t *testing.T) {
	t.Parallel()

	prefix := "https://" + strings.Repeat("a.", 126) + "a/"
	input := prefix + strings.Repeat("x", MaxReferenceBytes-len(prefix))
	if len(input) != MaxReferenceBytes {
		t.Fatalf("fixture length = %d, want %d", len(input), MaxReferenceBytes)
	}
	if _, err := Transform(input, Defang); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Transform() error = %v, want ErrInvalid", err)
	}
}

func FuzzTransform(f *testing.F) {
	seeds := []string{
		"https://example.test/",
		"hxxps://example[.]test/",
		"https://192.0.2.1/a%2Eb",
		"https://[2001:db8::1]/",
		"",
		"https://user@example.test/",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		for _, mode := range []Mode{Fang, Defang} {
			assertTransformProperties(t, input, mode)
		}
	})
}

func assertTransformProperties(t *testing.T, input string, mode Mode) {
	t.Helper()

	first, err := Transform(input, mode)
	if err != nil {
		return
	}
	if len(first) > MaxReferenceBytes {
		t.Fatalf("output exceeded bound: %d", len(first))
	}
	second, err := Transform(first, mode)
	if err != nil {
		t.Fatalf("accepted output was rejected: %v", err)
	}
	if second != first {
		t.Fatalf("non-idempotent transform: %q then %q", first, second)
	}
	ref, err := parse(input)
	if err != nil {
		t.Fatalf("accepted input no longer parsed: %v", err)
	}
	if mode == Defang && ref.state == active {
		assertRoundTrip(t, input, first, Fang)
	}
	if mode == Fang && ref.state == defanged {
		assertRoundTrip(t, input, first, Defang)
	}
}

func assertRoundTrip(t *testing.T, input, transformed string, opposite Mode) {
	t.Helper()

	restored, err := Transform(transformed, opposite)
	if err != nil {
		t.Fatalf("opposite transform failed: %v", err)
	}
	if restored != input {
		t.Fatalf("round trip changed input: %q to %q", input, restored)
	}
}
