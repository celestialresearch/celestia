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
	"net/netip"
	"strconv"
	"strings"
)

type hostKind uint8

const (
	hostNeutral hostKind = iota
	hostDNS
	hostIPv4
)

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
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return invalid("port")
	}
	return nil
}

func validateIPv6(host string) error {
	value := host[1 : len(host)-1]
	if strings.ContainsAny(value, ".%") {
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
		if _, err := strconv.ParseUint(label, 10, 8); err != nil {
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
