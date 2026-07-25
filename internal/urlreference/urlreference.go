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
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxInputBytes     = 4096
	MaxReferenceBytes = 8192
)

type Mode string

const (
	Fang   Mode = "fang"
	Defang Mode = "defang"
)

var ErrInvalid = errors.New("invalid URL reference")

type state uint8

const (
	active state = iota
	defanged
)

type reference struct {
	schemeEnd int
	hostStart int
	hostEnd   int
	state     state
	hostKind  hostKind
}

type hostKind uint8

const (
	hostNeutral hostKind = iota
	hostDNS
	hostIPv4
)

func ValidateInput(input string) error {
	if len(input) > MaxInputBytes {
		return invalid("original input length")
	}
	_, err := parse(input)
	return err
}

func Transform(input string, mode Mode) (string, error) {
	if mode != Fang && mode != Defang {
		return "", invalid("unsupported mode")
	}

	ref, err := parse(input)
	if err != nil {
		return "", err
	}

	target := active
	if mode == Defang {
		target = defanged
	}
	if ref.state == target {
		return input, nil
	}

	scheme := input[:ref.schemeEnd]
	if target == active {
		scheme = strings.Replace(scheme, "xx", "tt", 1)
	} else {
		scheme = strings.Replace(scheme, "tt", "xx", 1)
	}

	host := input[ref.hostStart:ref.hostEnd]
	if ref.hostKind != hostNeutral {
		if target == active {
			host = strings.ReplaceAll(host, "[.]", ".")
		} else {
			host = strings.ReplaceAll(host, ".", "[.]")
		}
	}

	output := scheme + input[ref.schemeEnd:ref.hostStart] + host + input[ref.hostEnd:]
	if len(output) > MaxReferenceBytes {
		return "", invalid("output length")
	}
	return output, nil
}

func parse(input string) (reference, error) {
	if err := validateInput(input); err != nil {
		return reference{}, err
	}

	schemeEnd := strings.Index(input, "://")
	if schemeEnd < 0 {
		return reference{}, invalid("scheme delimiter")
	}
	schemeState, ok := schemeClass(input[:schemeEnd])
	if !ok {
		return reference{}, invalid("scheme")
	}
	return parseReference(input, schemeEnd, schemeState)
}

func validateInput(input string) error {
	if len(input) == 0 || len(input) > MaxReferenceBytes {
		return invalid("input length")
	}
	if !utf8.ValidString(input) || strings.HasPrefix(input, "\uFEFF") {
		return invalid("UTF-8")
	}
	for _, r := range input {
		if r == 0 || r < 0x20 || r == 0x7f || rejectedSpace(r) {
			return invalid("control or whitespace")
		}
	}
	return nil
}

func parseReference(input string, schemeEnd int, schemeState state) (reference, error) {
	authorityStart := schemeEnd + 3
	authorityEnd := suffixStart(input, authorityStart)
	if authorityEnd == authorityStart {
		return reference{}, invalid("empty authority")
	}
	if err := validateSuffix(input[authorityEnd:]); err != nil {
		return reference{}, err
	}

	hostText, hostStart, hostEnd, err := splitAuthority(input, authorityStart, authorityEnd)
	if err != nil {
		return reference{}, err
	}
	hostState, kind, err := classifyHost(hostText)
	if err != nil {
		return reference{}, err
	}
	if kind != hostNeutral && hostState != schemeState {
		return reference{}, invalid("mixed transformation state")
	}

	return reference{
		schemeEnd: schemeEnd,
		hostStart: hostStart,
		hostEnd:   hostEnd,
		state:     schemeState,
		hostKind:  kind,
	}, nil
}

func schemeClass(scheme string) (state, bool) {
	switch scheme {
	case "http", "https":
		return active, true
	case "hxxp", "hxxps":
		return defanged, true
	default:
		return 0, false
	}
}

func suffixStart(input string, start int) int {
	end := len(input)
	for _, delimiter := range []byte{'/', '?', '#'} {
		if index := strings.IndexByte(input[start:], delimiter); index >= 0 {
			end = min(end, start+index)
		}
	}
	return end
}

func validateSuffix(suffix string) error {
	for index := 0; index < len(suffix); index++ {
		if suffix[index] != '%' {
			continue
		}
		if index+2 >= len(suffix) || !isHex(suffix[index+1]) || !isHex(suffix[index+2]) {
			return invalid("percent triplet")
		}
		index += 2
	}
	return nil
}

func splitAuthority(input string, start, end int) (string, int, int, error) {
	authority := input[start:end]
	if strings.Contains(authority, "@") {
		return "", 0, 0, invalid("user information")
	}
	if strings.HasPrefix(authority, "[") {
		closeIndex := strings.IndexByte(authority, ']')
		if closeIndex < 0 {
			return "", 0, 0, invalid("IPv6 bracket")
		}
		host := authority[:closeIndex+1]
		if err := validateIPv6(host); err != nil {
			return "", 0, 0, err
		}
		if err := validatePortSuffix(authority[closeIndex+1:]); err != nil {
			return "", 0, 0, err
		}
		return host, start, start + len(host), nil
	}
	host := authority
	if colon := strings.LastIndexByte(authority, ':'); colon >= 0 {
		if strings.Contains(authority[:colon], ":") {
			return "", 0, 0, invalid("unbracketed IPv6")
		}
		host = authority[:colon]
		if err := validatePort(authority[colon+1:]); err != nil {
			return "", 0, 0, err
		}
	}
	if host == "" {
		return "", 0, 0, invalid("empty host")
	}
	return host, start, start + len(host), nil
}

func validatePortSuffix(suffix string) error {
	if suffix == "" {
		return nil
	}
	if suffix[0] != ':' {
		return invalid("authority suffix")
	}
	return validatePort(suffix[1:])
}

func validatePort(port string) error {
	if len(port) == 0 || len(port) > 5 {
		return invalid("port")
	}
	for index := range len(port) {
		if port[index] < '0' || port[index] > '9' {
			return invalid("port")
		}
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return invalid("port")
	}
	return nil
}

func validateIPv6(host string) error {
	value := host[1 : len(host)-1]
	if value == "" || strings.ContainsAny(value, ".%") {
		return invalid("IPv6")
	}
	for index := range len(value) {
		if value[index] != ':' && !isHex(value[index]) {
			return invalid("IPv6")
		}
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is6() {
		return invalid("IPv6")
	}
	return nil
}

func classifyHost(host string) (state, hostKind, error) {
	if strings.HasPrefix(host, "[") {
		return active, hostNeutral, nil
	}

	labels, trailingRoot, hostState, err := splitHost(host)
	if err != nil {
		return 0, 0, err
	}
	allDecimal, err := validateLabels(labels)
	if err != nil {
		return 0, 0, err
	}
	if allDecimal {
		if err := validateIPv4(labels); err != nil {
			return 0, 0, err
		}
		return hostState, hostIPv4, nil
	}
	if logicalHostLength(labels) > 253 {
		return 0, 0, invalid("DNS host length")
	}
	if len(labels) == 1 && !trailingRoot {
		return hostState, hostNeutral, nil
	}
	return hostState, hostDNS, nil
}

func splitHost(host string) ([]string, bool, state, error) {
	hasDefanged := strings.Contains(host, "[.]")
	hasActive := strings.Contains(strings.ReplaceAll(host, "[.]", ""), ".")
	if hasActive && hasDefanged {
		return nil, false, 0, invalid("mixed host separators")
	}
	separator := "."
	hostState := active
	if hasDefanged {
		separator = "[.]"
		hostState = defanged
	}
	labels := strings.Split(host, separator)
	trailingRoot := len(labels) > 1 && labels[len(labels)-1] == ""
	if trailingRoot {
		labels = labels[:len(labels)-1]
	}
	return labels, trailingRoot, hostState, nil
}

func validateLabels(labels []string) (bool, error) {
	allDecimal := len(labels) == 4
	for _, label := range labels {
		if err := validateLabel(label); err != nil {
			return false, err
		}
		allDecimal = allDecimal && decimal(label)
	}
	return allDecimal, nil
}

func logicalHostLength(labels []string) int {
	length := 0
	for _, label := range labels {
		length += len(label)
	}
	return length + len(labels) - 1
}

func validateLabel(label string) error {
	if len(label) == 0 || len(label) > 63 {
		return invalid("DNS label")
	}
	for index := range len(label) {
		value := label[index]
		if !isASCIIAlpha(value) && !isDigit(value) && value != '-' {
			return invalid("DNS label")
		}
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return invalid("DNS label")
	}
	return nil
}

func validateIPv4(labels []string) error {
	for _, label := range labels {
		if len(label) > 1 && label[0] == '0' {
			return invalid("IPv4 leading zero")
		}
		_, err := strconv.ParseUint(label, 10, 8)
		if err != nil {
			return invalid("IPv4 octet")
		}
	}
	return nil
}

func decimal(value string) bool {
	for index := range len(value) {
		if !isDigit(value[index]) {
			return false
		}
	}
	return true
}

func rejectedSpace(r rune) bool {
	return r == 0x20 ||
		r == 0x85 ||
		r == 0xA0 ||
		r == 0x1680 ||
		r >= 0x2000 && r <= 0x200A ||
		r == 0x2028 ||
		r == 0x2029 ||
		r == 0x202F ||
		r == 0x205F ||
		r == 0x3000 ||
		r == 0xFEFF
}

func isASCIIAlpha(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func isHex(value byte) bool {
	return isDigit(value) ||
		value >= 'A' && value <= 'F' ||
		value >= 'a' && value <= 'f'
}

func invalid(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalid, reason)
}
