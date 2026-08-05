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
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestPerformanceReport_DecodesCalculatedReport(t *testing.T) {
	report := testPerformanceReport(t)
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var parsed performanceReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if !validPerformanceReport(parsed) {
		t.Fatal("valid report failed semantic validation")
	}
	decoded, err := decodePerformanceReport(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if !reflect.DeepEqual(decoded, report) {
		t.Fatalf("decoded report differs\n got: %#v\nwant: %#v", decoded, report)
	}
}

func TestPerformanceReport_RejectsHostileInput(t *testing.T) {
	valid := testPerformanceReport(t)
	data := marshalPerformanceReport(t, valid)
	tests := map[string]func() []byte{
		"unknown field":   func() []byte { return replaceOne(data, []byte("}"), []byte(",\"unknown\":1}")) },
		"duplicate field": func() []byte { return duplicatePerformanceField(data) },
		"unknown nested field": func() []byte {
			return replaceOne(data, []byte("\"sequence\":1"), []byte("\"sequence\":1,\"unknown\":1"))
		},
		"duplicate nested field": func() []byte {
			return replaceOne(data, []byte("\"sequence\":1"), []byte("\"sequence\":1,\"sequence\":1"))
		},
		"trailing data":       func() []byte { return append(append([]byte{}, data...), 'x') },
		"noncanonical number": func() []byte { return replaceOne(data, []byte("\"sequence\":1"), []byte("\"sequence\":1e0")) },
		"numeric overflow": func() []byte {
			return replaceOne(data, []byte("\"sequence\":1"), []byte("\"sequence\":18446744073709551616"))
		},
		"unpaired surrogate": func() []byte {
			return replaceOne(data, []byte("\"hardware\":\"test-host\""), []byte("\"hardware\":\"\\ud800\""))
		},
		"unpaired after escaped quote": func() []byte {
			return replaceOne(data, []byte("\"hardware\":\"test-host\""), []byte(`"hardware":"\"\ud800"`))
		},
		"oversized report":   func() []byte { return bytes.Repeat([]byte("x"), maxPerformanceReportBytes+1) },
		"missing phase":      func() []byte { return marshalPerformanceReport(t, missingPhase(clonePerformanceReport(t, valid))) },
		"duplicate phase":    func() []byte { return marshalPerformanceReport(t, duplicatePhase(clonePerformanceReport(t, valid))) },
		"wrong sample count": func() []byte { return marshalPerformanceReport(t, wrongSampleCount(clonePerformanceReport(t, valid))) },
		"false percentile":   func() []byte { return marshalPerformanceReport(t, falsePercentile(clonePerformanceReport(t, valid))) },
		"false resource percentile": func() []byte {
			return marshalPerformanceReport(t, falseResourcePercentile(clonePerformanceReport(t, valid)))
		},
		"mixed environment": func() []byte { return marshalPerformanceReport(t, mixedEnvironment(clonePerformanceReport(t, valid))) },
		"invalid toolchain": func() []byte { return marshalPerformanceReport(t, invalidToolchain(clonePerformanceReport(t, valid))) },
		"changed environment": func() []byte {
			return marshalPerformanceReport(t, changedEnvironment(clonePerformanceReport(t, valid)))
		},
		"repeated attempt": func() []byte { return marshalPerformanceReport(t, repeatedAttempt(clonePerformanceReport(t, valid))) },
		"report-wide repeated attempt": func() []byte {
			return marshalPerformanceReport(t, reportWideRepeatedAttempt(clonePerformanceReport(t, valid)))
		},
		"invalid attempt":    func() []byte { return marshalPerformanceReport(t, invalidAttempt(clonePerformanceReport(t, valid))) },
		"unverified outcome": func() []byte { return marshalPerformanceReport(t, unverifiedSample(clonePerformanceReport(t, valid))) },
		"incomplete cleanup": func() []byte { return marshalPerformanceReport(t, incompleteCleanup(clonePerformanceReport(t, valid))) },
		"unmeasured resource": func() []byte {
			return marshalPerformanceReport(t, unmeasuredResource(clonePerformanceReport(t, valid)))
		},
		"empty required resource": func() []byte {
			return marshalPerformanceReport(t, emptyRequiredResource(clonePerformanceReport(t, valid)))
		},
		"total overflow": func() []byte { return marshalPerformanceReport(t, overflowingTotal(clonePerformanceReport(t, valid))) },
		"unknown phase":  func() []byte { return marshalPerformanceReport(t, unknownPhase(clonePerformanceReport(t, valid))) },
		"mismatched statistics": func() []byte {
			return marshalPerformanceReport(t, mismatchedStatistics(clonePerformanceReport(t, valid)))
		},
		"wrong calculation": func() []byte {
			report := clonePerformanceReport(t, valid)
			report.Calculation = "different"
			return marshalPerformanceReport(t, report)
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := decodePerformanceReport(bytes.NewReader(build()))
			if !errors.Is(err, errPerformanceReport) {
				t.Fatalf("decode error = %v, want invalid report", err)
			}
		})
	}
}

func TestPerformanceReport_NearestRank(t *testing.T) {
	values := make([]uint64, 30)
	for index := range values {
		values[index] = uint64(index + 1)
	}
	if got := nearestRank(values, 50); got != 15 {
		t.Fatalf("p50 = %d, want 15", got)
	}
	if got := nearestRank(values, 95); got != 29 {
		t.Fatalf("p95 = %d, want 29", got)
	}
	if got := nearestRank(values, 99); got != 30 {
		t.Fatalf("p99 = %d, want 30", got)
	}
}

func TestPerformanceReport_RejectsStatisticsOverflow(t *testing.T) {
	samples := []performanceSample{testPerformanceSample(1, 1), testPerformanceSample(2, 2)}
	samples[0].Phases[len(performancePhases)-1].DurationNS = math.MaxUint64
	samples[1].Phases[len(performancePhases)-1].DurationNS = 1
	_, err := calculateStatistics(samples)
	if !errors.Is(err, errPerformanceReport) {
		t.Fatalf("calculate error = %v, want invalid report", err)
	}
}

func testPerformanceReport(t *testing.T) performanceReport {
	t.Helper()
	cold := testPerformanceProfile(t, "cold", coldSampleCount, 0)
	warm := testPerformanceProfile(t, "warm", warmSampleCount, coldSampleCount)
	report := performanceReport{
		SchemaVersion: performanceReportSchema,
		CorpusVersion: performanceCorpusSchema,
		CorpusSHA256:  strings.Repeat("a", 64),
		Calculation:   performanceCalculation,
		Environment: performanceEnvironment{
			Platform:      "windows/amd64",
			Hardware:      "test-host",
			Toolchains:    []string{"go1.26.5", "rustc1.95.0"},
			CacheState:    "declared",
			Concurrency:   1,
			WorkerSHA256:  strings.Repeat("c", 64),
			ProductCommit: strings.Repeat("d", 40),
		},
		Workloads: []performanceWorkload{{
			Class:          "active-dns",
			WorkloadID:     "active-dns-defang",
			WorkloadSHA256: strings.Repeat("e", 64),
			Cold:           cold,
			Warm:           warm,
		}},
	}
	report.Environment.Identity = performanceEnvironmentIdentity(report.Environment)
	for index := range report.Workloads {
		for sample := range report.Workloads[index].Cold.Samples {
			report.Workloads[index].Cold.Samples[sample].EnvironmentID = report.Environment.Identity
		}
		for sample := range report.Workloads[index].Warm.Samples {
			report.Workloads[index].Warm.Samples[sample].EnvironmentID = report.Environment.Identity
		}
	}
	return report
}

func testPerformanceProfile(t *testing.T, mode string, count int, start uint64) performanceProfile {
	t.Helper()
	samples := make([]performanceSample, count)
	sequence := uint64(1)
	identity := start + 1
	for index := range samples {
		samples[index] = testPerformanceSample(sequence, identity)
		sequence++
		identity++
	}
	statistics, err := calculateStatistics(samples)
	if err != nil {
		t.Fatalf("calculate statistics: %v", err)
	}
	return performanceProfile{Mode: mode, Samples: samples, Statistics: statistics}
}

func testPerformanceSample(sequence, identity uint64) performanceSample {
	phases := make([]phaseMeasurement, len(performancePhases))
	duration := sequence + 1
	for index, id := range performancePhases {
		phases[index] = phaseMeasurement{ID: id, DurationNS: duration}
		duration++
	}
	return performanceSample{
		Sequence:        sequence,
		AttemptID:       performanceTestIdentity(identity),
		EnvironmentID:   strings.Repeat("b", 64),
		Outcome:         string(Verified),
		CleanupComplete: true,
		Phases:          phases,
		Resources: resourceMeasurement{
			Measured:               true,
			PeakWorkingSetBytes:    1,
			PeakProcessCommitBytes: 1,
			PeakJobCommitBytes:     1,
			EvidenceBytes:          1,
			WorkerImageBytes:       1,
		},
	}
}

func performanceTestIdentity(sequence uint64) string {
	seed := byte(0)
	for range sequence {
		seed++
	}
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}

func marshalPerformanceReport(t *testing.T, report performanceReport) []byte {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	return data
}

func clonePerformanceReport(t *testing.T, report performanceReport) performanceReport {
	t.Helper()
	data := marshalPerformanceReport(t, report)
	var cloned performanceReport
	if err := json.Unmarshal(data, &cloned); err != nil {
		t.Fatalf("clone report: %v", err)
	}
	return cloned
}

func replaceOne(data, old, next []byte) []byte {
	return bytes.Replace(data, old, next, 1)
}

func duplicatePerformanceField(data []byte) []byte {
	return replaceOne(data, []byte("\"schema_version\":\""+performanceReportSchema+"\""), []byte("\"schema_version\":\""+performanceReportSchema+"\",\"schema_version\":\""+performanceReportSchema+"\""))
}

func missingPhase(report performanceReport) performanceReport {
	report.Workloads[0].Cold.Samples[0].Phases = report.Workloads[0].Cold.Samples[0].Phases[:len(performancePhases)-1]
	return report
}

func duplicatePhase(report performanceReport) performanceReport {
	report.Workloads[0].Cold.Samples[0].Phases[1].ID = performancePhases[0]
	return report
}

func wrongSampleCount(report performanceReport) performanceReport {
	report.Workloads[0].Cold.Samples = report.Workloads[0].Cold.Samples[:coldSampleCount-1]
	return report
}

func falsePercentile(report performanceReport) performanceReport {
	report.Workloads[0].Warm.Statistics.Phases[0].P99++
	return report
}

func falseResourcePercentile(report performanceReport) performanceReport {
	report.Workloads[0].Warm.Statistics.Resources[0].P99++
	return report
}

func mixedEnvironment(report performanceReport) performanceReport {
	report.Workloads[0].Warm.Samples[0].EnvironmentID = strings.Repeat("f", 64)
	return report
}

func invalidToolchain(report performanceReport) performanceReport {
	report.Environment.Toolchains = []string{"rustc1.95.0", "go1.26.5"}
	return report
}

func changedEnvironment(report performanceReport) performanceReport {
	report.Environment.CacheState = "other"
	return report
}

func repeatedAttempt(report performanceReport) performanceReport {
	report.Workloads[0].Warm.Samples[0].AttemptID = report.Workloads[0].Cold.Samples[0].AttemptID
	return report
}

func reportWideRepeatedAttempt(report performanceReport) performanceReport {
	additional := report.Workloads[0]
	additional.Class = "defanged-ipv4"
	additional.WorkloadID = "defanged-ipv4-fang"
	additional.WorkloadSHA256 = strings.Repeat("f", 64)
	report.Workloads = append(report.Workloads, additional)
	return report
}

func invalidAttempt(report performanceReport) performanceReport {
	report.Workloads[0].Cold.Samples[0].AttemptID = "invalid"
	return report
}

func unverifiedSample(report performanceReport) performanceReport {
	report.Workloads[0].Cold.Samples[0].Outcome = string(ExecutedUnverified)
	return report
}

func incompleteCleanup(report performanceReport) performanceReport {
	report.Workloads[0].Cold.Samples[0].CleanupComplete = false
	return report
}

func unmeasuredResource(report performanceReport) performanceReport {
	report.Workloads[0].Cold.Samples[0].Resources.Measured = false
	return report
}

func emptyRequiredResource(report performanceReport) performanceReport {
	report.Workloads[0].Cold.Samples[0].Resources.PeakWorkingSetBytes = 0
	return report
}

func overflowingTotal(report performanceReport) performanceReport {
	report.Workloads[0].Cold.Samples[0].Phases[len(performancePhases)-1].DurationNS = math.MaxUint64
	report.Workloads[0].Cold.Samples[1].Phases[len(performancePhases)-1].DurationNS = 1
	return report
}

func unknownPhase(report performanceReport) performanceReport {
	report.Workloads[0].Cold.Samples[0].Phases[0].ID = "unknown"
	return report
}

func mismatchedStatistics(report performanceReport) performanceReport {
	report.Workloads[0].Cold.Statistics.SampleCount++
	return report
}
