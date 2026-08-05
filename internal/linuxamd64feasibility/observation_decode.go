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

package linuxamd64feasibility

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var errObservationInvalid = errors.New("invalid Linux AMD64 feasibility observation")

func decodeObservation(data []byte) (observation, error) {
	if len(data) == 0 || len(data) > maxObservationBytes || !utf8.Valid(data) {
		return observation{}, errObservationInvalid
	}
	if !canonicalObservationJSON(data) || !uniqueObservationFields(data) {
		return observation{}, errObservationInvalid
	}
	var result observation
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || !observationEnd(decoder) {
		return observation{}, errObservationInvalid
	}
	if !validObservation(result) {
		return observation{}, errObservationInvalid
	}
	return result, nil
}

func canonicalObservationJSON(data []byte) bool {
	var compact bytes.Buffer
	if json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), data) {
		return false
	}
	var result observation
	if json.Unmarshal(data, &result) != nil {
		return false
	}
	canonical, err := json.Marshal(result)
	return err == nil && bytes.Equal(data, canonical)
}

func observationEnd(decoder *json.Decoder) bool {
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func uniqueObservationFields(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	budget := 1024
	return scanObservationValue(decoder, 0, &budget) && observationEnd(decoder)
}

func scanObservationValue(decoder *json.Decoder, depth int, budget *int) bool {
	if depth > 32 || *budget < 1 {
		return false
	}
	*budget--
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			return scanObservationObject(decoder, depth+1, budget)
		case '[':
			return scanObservationArray(decoder, depth+1, budget)
		default:
			return false
		}
	default:
		return true
	}
}

func scanObservationObject(decoder *json.Decoder, depth int, budget *int) bool {
	fields := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return false
		}
		if _, duplicate := fields[name]; duplicate {
			return false
		}
		fields[name] = struct{}{}
		if !scanObservationValue(decoder, depth, budget) {
			return false
		}
	}
	return observationDelimiter(decoder, '}')
}

func scanObservationArray(decoder *json.Decoder, depth int, budget *int) bool {
	for decoder.More() {
		if !scanObservationValue(decoder, depth, budget) {
			return false
		}
	}
	return observationDelimiter(decoder, ']')
}

func observationDelimiter(decoder *json.Decoder, want rune) bool {
	token, err := decoder.Token()
	return err == nil && token == json.Delim(want)
}
