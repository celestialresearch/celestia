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

package urloperation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	workerprotocol "celestia.research/celestia/internal/operation/urlreference/protocol"
)

const (
	performanceCorpusPath  = "../../../testdata/url-reference-performance-workload-v1.json"
	performanceInputBytes  = 4096
	maximumCorpusFileBytes = 1 << 20
	maximumCorpusJSONDepth = 64
	maximumCorpusJSONNodes = 1 << 20
)

type performanceCorpus struct {
	Version   int                       `json:"version"`
	Operation string                    `json:"operation"`
	Cases     []performanceWorkloadCase `json:"cases"`
}

type performanceWorkloadCase struct {
	ID           string   `json:"id"`
	Class        string   `json:"class"`
	Kind         string   `json:"kind"`
	Mode         string   `json:"mode"`
	Input        string   `json:"input"`
	Expected     string   `json:"expected"`
	Paths        []string `json:"required_paths"`
	Eligible     bool     `json:"sample_eligible"`
	OutputBytes  int      `json:"declared_output_bytes"`
	OutputSHA256 string   `json:"output_sha256"`
	Control      string   `json:"control"`
}

var acceptedClasses = []string{"shortest_fang", "shortest_defang", "ordinary", "ipv4", "ipv6", "escaped_percent_non_ascii", "maximum_input", "maximum_label", "maximum_host"}
var faultClasses = []string{"maximum_output", "malformed", "mixed_state", "worker_rejection", "worker_failure", "cancellation", "timeout", "publication_fault", "cleanup_fault", "recovery_fault"}
var fullCampaignWorkloads = map[string]string{
	"shortest_fang":             "shortest-fang",
	"shortest_defang":           "shortest-defang",
	"ordinary":                  "ordinary",
	"ipv4":                      "ipv4",
	"ipv6":                      "ipv6",
	"escaped_percent_non_ascii": "escaped_percent_non_ascii",
	"maximum_input":             "maximum_input",
	"maximum_label":             "maximum_label",
	"maximum_host":              "maximum_host",
}

func TestPerformanceWorkloadCorpusRejectsInvalidRows(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown":          `{"version":1,"operation":"url-reference","cases":[],"unknown":true}`,
		"duplicate-field":  `{"version":1,"version":1,"operation":"url-reference","cases":[]}`,
		"nested-duplicate": `{"version":1,"operation":"url-reference","cases":[{"id":"a","id":"b"}]}`,
		"duplicate":        `{"version":1,"operation":"url-reference","cases":[{"id":"a","class":"short","kind":"accepted","mode":"fang","input":"x","expected":"x","required_paths":["cold","warm"],"sample_eligible":true},{"id":"a","class":"ordinary","kind":"accepted","mode":"fang","input":"x","expected":"x","required_paths":["cold","warm"],"sample_eligible":true}]}`,
		"invalid-mode":     `{"version":1,"operation":"url-reference","cases":[{"id":"a","class":"short","kind":"accepted","mode":"bad","input":"x","expected":"x","required_paths":["cold","warm"],"sample_eligible":true}]}`,
		"missing-output":   `{"version":1,"operation":"url-reference","cases":[{"id":"a","class":"short","kind":"accepted","mode":"fang","input":"x","expected":"","required_paths":["cold","warm"],"sample_eligible":true}]}`,
		"oversized":        fmt.Sprintf("{\"version\":1,\"operation\":\"url-reference\",\"cases\":[{\"id\":\"a\",\"class\":\"short\",\"kind\":\"accepted\",\"mode\":\"fang\",\"input\":\"%s\",\"expected\":\"x\",\"required_paths\":[\"cold\",\"warm\"],\"sample_eligible\":true}]}", strings.Repeat("a", performanceInputBytes+1)),
		"eligible-fault":   `{"version":1,"operation":"url-reference","cases":[{"id":"a","class":"timeout","kind":"fault","mode":"fang","input":"x","expected":"timed_out","required_paths":[],"sample_eligible":true}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePerformanceCorpus([]byte(raw)); err == nil {
				t.Fatal("invalid corpus accepted")
			}
		})
	}
}

func TestPerformanceWorkloadCorpusRejectsInvalidUTF8(t *testing.T) {
	raw := []byte(`{"version":1,"operation":"url-reference","cases":[],"unknown":"`)
	raw = append(raw, 0xff)
	raw = append(raw, '"', '}')
	if utf8.Valid(raw) {
		t.Fatal("fixture is valid UTF-8")
	}
	if _, err := decodePerformanceCorpus(raw); err == nil || err.Error() != "invalid UTF-8" {
		t.Fatalf("error = %v, want invalid UTF-8", err)
	}
}

func TestValidateCorpusJSONSurrogates(t *testing.T) {
	for _, test := range []struct {
		data  string
		valid bool
	}{
		{`{"value":"\ud800"}`, false}, {`{"value":"\udc00"}`, false},
		{`{"value":"\ud800x"}`, false}, {`{"value":"\ud800\u1234"}`, false},
		{`{"value":"\ud83d\ude00"}`, true}, {`{"value":"\\ud800"}`, true},
	} {
		t.Run(test.data, func(t *testing.T) {
			err := validateCorpusJSON([]byte(test.data))
			if (err == nil) != test.valid {
				t.Fatalf("validate error = %v, valid = %t", err, test.valid)
			}
		})
	}
}

func TestPerformanceCorpusFileRejectsUnpairedSurrogate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.json")
	if err := os.WriteFile(path, []byte(`{"input":"\ud800"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readPerformanceCorpusFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePerformanceCorpus(data); err == nil || err.Error() != "unpaired surrogate" {
		t.Fatalf("decode error = %v, want unpaired surrogate", err)
	}
}

func TestPerformanceCorpusFileIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maximumCorpusFileBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readPerformanceCorpusFile(path); err != nil || len(data) != maximumCorpusFileBytes {
		t.Fatalf("boundary bytes=%d error=%v", len(data), err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maximumCorpusFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPerformanceCorpusFile(path); err == nil {
		t.Fatal("oversized corpus accepted")
	}
}

func TestPerformanceWorkloadCorpusRejectsEveryValidationBranch(t *testing.T) {
	tests := []struct {
		name string
		data func(*performanceCorpus) []byte
		want string
	}{
		{"header", func(c *performanceCorpus) []byte { c.Version++; return marshalCorpus(t, c) }, "header"},
		{"trailing", func(c *performanceCorpus) []byte { return append(marshalCorpus(t, c), 'x') }, "trailing data"},
		{"unknown class", func(c *performanceCorpus) []byte { c.Cases[0].Class = "unknown"; return marshalCorpus(t, c) }, "identity"},
		{"duplicate class", func(c *performanceCorpus) []byte { c.Cases[1].Class = c.Cases[0].Class; return marshalCorpus(t, c) }, "duplicate class"},
		{"missing paths", func(c *performanceCorpus) []byte { c.Cases[0].Paths = nil; return marshalCorpus(t, c) }, "accepted"},
		{"reordered paths", func(c *performanceCorpus) []byte {
			c.Cases[0].Paths = []string{"warm", "cold"}
			return marshalCorpus(t, c)
		}, "accepted"},
		{"extra path", func(c *performanceCorpus) []byte {
			c.Cases[0].Paths = []string{"cold", "warm", "cold"}
			return marshalCorpus(t, c)
		}, "accepted"},
		{"wrong accepted kind", func(c *performanceCorpus) []byte { c.Cases[0].Kind = "fault"; return marshalCorpus(t, c) }, "class kind"},
		{"wrong rejected kind", func(c *performanceCorpus) []byte {
			c.CasesByClass("malformed").Kind = "fault"
			return marshalCorpus(t, c)
		}, "class kind"},
		{"wrong fault kind", func(c *performanceCorpus) []byte {
			c.CasesByClass("timeout").Kind = "rejected"
			return marshalCorpus(t, c)
		}, "class kind"},
		{"accepted ineligible", func(c *performanceCorpus) []byte { c.Cases[0].Eligible = false; return marshalCorpus(t, c) }, "accepted"},
		{"fault paths", func(c *performanceCorpus) []byte {
			c.CasesByClass("timeout").Paths = []string{"cold"}
			return marshalCorpus(t, c)
		}, "fault"},
		{"fault control", func(c *performanceCorpus) []byte {
			c.CasesByClass("timeout").Control = "other"
			return marshalCorpus(t, c)
		}, "fault control"},
		{"maximum input", func(c *performanceCorpus) []byte {
			c.CasesByClass("maximum_input").Input = c.CasesByClass("maximum_input").Input[:performanceInputBytes-1]
			return marshalCorpus(t, c)
		}, "maximum input"},
		{"maximum label", func(c *performanceCorpus) []byte {
			c.CasesByClass("maximum_label").Input = "https://" + strings.Repeat("a", 62) + ".test/"
			return marshalCorpus(t, c)
		}, "maximum label"},
		{"maximum host", func(c *performanceCorpus) []byte {
			c.CasesByClass("maximum_host").Input = "https://" + strings.Repeat("a", 252) + "/"
			return marshalCorpus(t, c)
		}, "maximum host"},
		{"maximum output size", func(c *performanceCorpus) []byte {
			c.CasesByClass("maximum_output").OutputBytes--
			return marshalCorpus(t, c)
		}, "maximum output"},
		{"maximum output hash", func(c *performanceCorpus) []byte {
			c.CasesByClass("maximum_output").OutputSHA256 = "0"
			return marshalCorpus(t, c)
		}, "maximum output"},
		{"missing class", func(c *performanceCorpus) []byte { c.Cases = c.Cases[1:]; return marshalCorpus(t, c) }, "incomplete classes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			corpus := readPerformanceCorpus(t)
			_, err := decodePerformanceCorpus(test.data(&corpus))
			if err == nil || !strings.HasPrefix(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func (corpus *performanceCorpus) CasesByClass(class string) *performanceWorkloadCase {
	for index := range corpus.Cases {
		if corpus.Cases[index].Class == class {
			return &corpus.Cases[index]
		}
	}
	panic("missing performance workload class")
}

func marshalCorpus(t *testing.T, corpus *performanceCorpus) []byte {
	t.Helper()
	data, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func loadPerformanceCorpus(t *testing.T) performanceCorpus {
	t.Helper()
	return readPerformanceCorpus(t)
}

func readPerformanceCorpus(t *testing.T) performanceCorpus {
	t.Helper()
	data, err := readPerformanceCorpusFile(performanceCorpusPath)
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := decodePerformanceCorpus(data)
	if err != nil {
		t.Fatal(err)
	}
	return corpus
}

func readPerformanceCorpusFile(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximumCorpusFileBytes+1))
	if closeErr := errors.Join(file.Close(), root.Close()); readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if len(data) == 0 || len(data) > maximumCorpusFileBytes {
		return nil, fmt.Errorf("corpus size")
	}
	return data, nil
}

func decodePerformanceCorpus(data []byte) (performanceCorpus, error) {
	corpus, err := decodeCorpus(data)
	if err != nil {
		return corpus, err
	}
	if err := validateCorpusHeader(corpus); err != nil {
		return corpus, err
	}
	return corpus, validateCorpusRows(corpus)
}

func decodeCorpus(data []byte) (performanceCorpus, error) {
	if err := validateCorpusJSON(data); err != nil {
		return performanceCorpus{}, err
	}
	var corpus performanceCorpus
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		return corpus, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return corpus, fmt.Errorf("trailing data: %w", err)
	}
	return corpus, nil
}

func validateCorpusJSON(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid UTF-8")
	}
	if hasUnpairedCorpusSurrogate(data) {
		return fmt.Errorf("unpaired surrogate")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	nodes := maximumCorpusJSONNodes
	if err := scanCorpusValue(decoder, 0, &nodes); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing data")
	}
	return nil
}

func hasUnpairedCorpusSurrogate(data []byte) bool {
	inString := false
	for index := 0; index < len(data); index++ {
		switch data[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString {
				continue
			}
			next, invalid := inspectCorpusSurrogate(data, index)
			if invalid {
				return true
			}
			index = next
		}
	}
	return false
}

func inspectCorpusSurrogate(data []byte, index int) (int, bool) {
	if index+5 >= len(data) || data[index+1] != 'u' {
		return min(index+1, len(data)-1), false
	}
	value, ok := corpusHex4(data[index+2 : index+6])
	if !ok || value&0xf800 != 0xd800 {
		return index + 5, false
	}
	if value&0xfc00 == 0xdc00 {
		return index + 5, true
	}
	if index+11 >= len(data) || data[index+6] != '\\' || data[index+7] != 'u' {
		return index + 5, true
	}
	low, ok := corpusHex4(data[index+8 : index+12])
	return index + 11, !ok || low&0xfc00 != 0xdc00
}

func corpusHex4(data []byte) (uint16, bool) {
	value, err := strconv.ParseUint(string(data), 16, 16)
	return uint16(value), err == nil && len(data) == 4
}

func scanCorpusValue(decoder *json.Decoder, depth int, nodes *int) error {
	if depth > maximumCorpusJSONDepth || *nodes == 0 {
		return fmt.Errorf("JSON bounds")
	}
	*nodes--
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("JSON token")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delimiter == '{' {
		return scanCorpusObject(decoder, depth+1, nodes)
	}
	if delimiter == '[' {
		return scanCorpusArray(decoder, depth+1, nodes)
	}
	return fmt.Errorf("JSON delimiter")
}

func scanCorpusObject(decoder *json.Decoder, depth int, nodes *int) error {
	keys := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return fmt.Errorf("JSON object key")
		}
		if _, exists := keys[key]; exists {
			return fmt.Errorf("duplicate field")
		}
		keys[key] = struct{}{}
		if err := scanCorpusValue(decoder, depth, nodes); err != nil {
			return err
		}
	}
	return expectCorpusDelimiter(decoder, '}')
}

func scanCorpusArray(decoder *json.Decoder, depth int, nodes *int) error {
	for decoder.More() {
		if err := scanCorpusValue(decoder, depth, nodes); err != nil {
			return err
		}
	}
	return expectCorpusDelimiter(decoder, ']')
}

func expectCorpusDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil || token != expected {
		return fmt.Errorf("JSON delimiter")
	}
	return nil
}

func validateCorpusHeader(c performanceCorpus) error {
	if c.Version != 1 || c.Operation != "url-reference" {
		return fmt.Errorf("header")
	}
	return nil
}

func validateCorpusRows(corpus performanceCorpus) error {
	classes, ids, seen := knownClasses(), map[string]bool{}, map[string]bool{}
	for _, row := range corpus.Cases {
		if err := validateCorpusRow(row, classes, ids, seen); err != nil {
			return err
		}
	}
	return validateCorpusCompleteness(corpus, classes, seen)
}

func validateCorpusRow(c performanceWorkloadCase, classes, ids, seen map[string]bool) error {
	if err := validateRowIdentity(c, classes, ids, seen); err != nil {
		return err
	}
	if c.Kind == "accepted" {
		return validateAcceptedRow(c)
	}
	return validateNonAcceptedRow(c)
}

func validateRowIdentity(c performanceWorkloadCase, classes, ids, seen map[string]bool) error {
	if c.ID == "" || ids[c.ID] || !classes[c.Class] || c.Input == "" || c.Expected == "" || (c.Mode != "fang" && c.Mode != "defang") {
		return fmt.Errorf("identity")
	}
	if seen[c.Class] {
		return fmt.Errorf("duplicate class")
	}
	if c.Kind != expectedKind(c.Class) {
		return fmt.Errorf("class kind")
	}
	ids[c.ID], seen[c.Class] = true, true
	return nil
}

func validateAcceptedRow(c performanceWorkloadCase) error {
	if !c.Eligible || len(c.Input) > performanceInputBytes || !slices.Equal(c.Paths, []string{"cold", "warm"}) {
		return fmt.Errorf("accepted")
	}
	if c.Class == "maximum_input" && len(c.Input) != performanceInputBytes {
		return fmt.Errorf("maximum input")
	}
	if c.Class == "maximum_label" && len(strings.TrimSuffix(strings.TrimPrefix(c.Input, "https://"), ".test/")) != 63 {
		return fmt.Errorf("maximum label")
	}
	if c.Class == "maximum_host" && len(strings.TrimSuffix(strings.TrimPrefix(c.Input, "https://"), "/")) != 253 {
		return fmt.Errorf("maximum host")
	}
	return nil
}

func validateNonAcceptedRow(c performanceWorkloadCase) error {
	if c.Eligible || len(c.Paths) != 0 {
		return fmt.Errorf("fault")
	}
	if c.Control != faultControls[c.Class] {
		return fmt.Errorf("fault control")
	}
	if c.Class == "maximum_output" && (c.OutputBytes != workerprotocol.MaxOutputBytes || c.OutputSHA256 != "18f8d2eb4a387bbc1e37ec099a7326805739bc9c99ecf0f14b808a5bcb65bf49") {
		return fmt.Errorf("maximum output")
	}
	return nil
}

func validateCorpusCompleteness(c performanceCorpus, classes, seen map[string]bool) error {
	if len(c.Cases) != len(classes) {
		return fmt.Errorf("incomplete classes")
	}
	for class := range classes {
		if !seen[class] {
			return fmt.Errorf("missing class")
		}
	}
	return nil
}

func validFullCampaignCorpus(corpus performanceCorpus) bool {
	if validateCorpusHeader(corpus) != nil || validateCorpusRows(corpus) != nil {
		return false
	}
	accepted := 0
	for _, workload := range corpus.Cases {
		if !workload.Eligible {
			continue
		}
		if fullCampaignWorkloads[workload.Class] != workload.ID {
			return false
		}
		accepted++
	}
	return accepted == len(fullCampaignWorkloads)
}

func corpusDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func workloadDigest(workload performanceWorkloadCase) string {
	data, err := json.Marshal(workload)
	if err != nil {
		return ""
	}
	return corpusDigest(data)
}

var faultControls = map[string]string{"maximum_output": "TestSupervisorCapturesStreamOverflow", "malformed": "TestOperationRejectsBeforeExecution", "mixed_state": "TestOperationRejectsBeforeExecution", "worker_rejection": "TestOperationRecordsValidWorkerFailure", "worker_failure": "TestOperationRecordsValidWorkerFailure", "cancellation": "TestOperationPreservesTermination", "timeout": "TestOperationPreservesTermination", "publication_fault": "TestExecuteRecordsPublicationFailure", "cleanup_fault": "TestPublishReleaseFailurePreservesTerminalStatus", "recovery_fault": "TestRecoverPublishesAfterReceiptFailure"}

func expectedKind(class string) string {
	if slices.Contains(acceptedClasses, class) {
		return "accepted"
	}
	if class == "malformed" || class == "mixed_state" {
		return "rejected"
	}
	return "fault"
}

func knownClasses() map[string]bool {
	classes := map[string]bool{}
	for _, c := range acceptedClasses {
		classes[c] = true
	}
	for _, c := range faultClasses {
		classes[c] = true
	}
	return classes
}
