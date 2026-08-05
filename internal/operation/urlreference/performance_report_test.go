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
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestPerformanceReport_DecodesCalculatedReport(t *testing.T) {
	corpus, corpusSHA256 := testPerformanceCorpus(t)
	report := testPerformanceReport(t, corpus, corpusSHA256)
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var parsed performanceReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if !validPerformanceReport(parsed, corpus, corpusSHA256) {
		t.Fatal("valid report failed semantic validation")
	}
	decoded, err := decodePerformanceReport(bytes.NewReader(data), corpus, corpusSHA256)
	if err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if !reflect.DeepEqual(decoded, report) {
		t.Fatalf("decoded report differs\n got: %#v\nwant: %#v", decoded, report)
	}
}

func TestPerformanceReport_RejectsHostileInput(t *testing.T) {
	corpus, corpusSHA256 := testPerformanceCorpus(t)
	valid := testPerformanceReport(t, corpus, corpusSHA256)
	data := marshalPerformanceReport(t, valid)
	groups := []map[string]func() []byte{
		performanceReportEncodingCases(data),
		performanceReportSemanticCases(t, valid),
		performanceReportBindingCases(t, valid),
	}
	for _, tests := range groups {
		for name, build := range tests {
			t.Run(name, func(t *testing.T) {
				_, err := decodePerformanceReport(bytes.NewReader(build()), corpus, corpusSHA256)
				if !errors.Is(err, errPerformanceReport) {
					t.Fatalf("decode error = %v, want invalid report", err)
				}
			})
		}
	}
}

func performanceReportEncodingCases(data []byte) map[string]func() []byte {
	return map[string]func() []byte{
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
		"oversized report": func() []byte { return bytes.Repeat([]byte("x"), maxPerformanceReportBytes+1) },
	}
}

func performanceReportSemanticCases(
	t *testing.T,
	valid performanceReport,
) map[string]func() []byte {
	return map[string]func() []byte{
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
		"working set exceeds memory bound": func() []byte {
			return marshalPerformanceReport(t, excessiveResource(t, clonePerformanceReport(t, valid), func(resources *resourceMeasurement) {
				resources.PeakWorkingSetBytes = maxPerformanceMemoryBytes + 1
			}))
		},
		"process commit exceeds memory bound": func() []byte {
			return marshalPerformanceReport(t, excessiveResource(t, clonePerformanceReport(t, valid), func(resources *resourceMeasurement) {
				resources.PeakProcessCommitBytes = maxPerformanceMemoryBytes + 1
			}))
		},
		"job commit exceeds memory bound": func() []byte {
			return marshalPerformanceReport(t, excessiveResource(t, clonePerformanceReport(t, valid), func(resources *resourceMeasurement) {
				resources.PeakJobCommitBytes = maxPerformanceMemoryBytes + 1
			}))
		},
		"evidence exceeds persistence bound": func() []byte {
			return marshalPerformanceReport(t, excessiveResource(t, clonePerformanceReport(t, valid), func(resources *resourceMeasurement) {
				resources.EvidenceBytes = maxPerformanceEvidenceBytes + 1
			}))
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
}

func performanceReportBindingCases(
	t *testing.T,
	valid performanceReport,
) map[string]func() []byte {
	return map[string]func() []byte{
		"wrong corpus digest": func() []byte {
			report := clonePerformanceReport(t, valid)
			report.CorpusSHA256 = strings.Repeat("f", 64)
			return marshalPerformanceReport(t, report)
		},
		"wrong workload class": func() []byte {
			report := clonePerformanceReport(t, valid)
			report.Workloads[0].Class = "active-dns"
			return marshalPerformanceReport(t, report)
		},
		"wrong workload ID": func() []byte {
			report := clonePerformanceReport(t, valid)
			report.Workloads[0].WorkloadID = "active-dns-defang"
			return marshalPerformanceReport(t, report)
		},
		"wrong workload digest": func() []byte {
			report := clonePerformanceReport(t, valid)
			report.Workloads[0].WorkloadSHA256 = strings.Repeat("f", 64)
			return marshalPerformanceReport(t, report)
		},
		"reordered workloads": func() []byte {
			report := clonePerformanceReport(t, valid)
			report.Workloads[0], report.Workloads[1] = report.Workloads[1], report.Workloads[0]
			return marshalPerformanceReport(t, report)
		},
		"missing workload": func() []byte {
			report := clonePerformanceReport(t, valid)
			report.Workloads = report.Workloads[1:]
			return marshalPerformanceReport(t, report)
		},
		"additional workload": func() []byte {
			report := clonePerformanceReport(t, valid)
			additional := report.Workloads[0]
			additional.Class = "active-dns"
			additional.WorkloadID = "active-dns-defang"
			additional.WorkloadSHA256 = strings.Repeat("f", 64)
			for index := range additional.Cold.Samples {
				additional.Cold.Samples[index].AttemptID = performanceTestIdentity(uint64(1_000 + index))
			}
			for index := range additional.Warm.Samples {
				additional.Warm.Samples[index].AttemptID = performanceTestIdentity(uint64(2_000 + index))
			}
			report.Workloads = append(report.Workloads, additional)
			return marshalPerformanceReport(t, report)
		},
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

func TestPerformanceReport_RejectsPhaseBeyondTotal(t *testing.T) {
	phases := testPerformanceSample(1, 1).Phases
	phases[0].DurationNS = phases[len(phases)-1].DurationNS + 1
	if validSamplePhases(phases) {
		t.Fatal("phase beyond total was accepted")
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

func testPerformanceCorpus(t *testing.T) (performanceCorpus, string) {
	t.Helper()
	data, err := readPerformanceCorpusFile(performanceCorpusPath)
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := decodePerformanceCorpus(data)
	if err != nil {
		t.Fatal(err)
	}
	return corpus, corpusDigest(data)
}

func testPerformanceReport(
	t *testing.T,
	corpus performanceCorpus,
	corpusSHA256 string,
) performanceReport {
	t.Helper()
	report := performanceReport{
		SchemaVersion: performanceReportSchema,
		CorpusVersion: performanceCorpusSchema,
		CorpusSHA256:  corpusSHA256,
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
	}
	for _, workload := range acceptedPerformanceWorkloads(corpus) {
		start := uint64(len(report.Workloads) * (coldSampleCount + warmSampleCount))
		report.Workloads = append(report.Workloads, performanceWorkload{
			Class:          workload.Class,
			WorkloadID:     workload.ID,
			WorkloadSHA256: workloadDigest(workload),
			Cold:           testPerformanceProfile(t, "cold", coldSampleCount, start),
			Warm:           testPerformanceProfile(t, "warm", warmSampleCount, start+coldSampleCount),
		})
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
	var value [32]byte
	binary.BigEndian.PutUint64(value[24:], sequence)
	return base64.RawURLEncoding.EncodeToString(value[:])
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

func excessiveResource(
	t *testing.T,
	report performanceReport,
	mutate func(*resourceMeasurement),
) performanceReport {
	t.Helper()
	mutate(&report.Workloads[0].Cold.Samples[0].Resources)
	statistics, err := calculateStatistics(report.Workloads[0].Cold.Samples)
	if err != nil {
		t.Fatalf("calculate statistics: %v", err)
	}
	report.Workloads[0].Cold.Statistics = statistics
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
