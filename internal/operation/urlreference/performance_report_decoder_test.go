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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxPerformanceReportBytes   = 16 << 20
	maxPerformanceMemoryBytes   = 64 << 20
	maxPerformanceEvidenceBytes = 2 << 20
)

var (
	identifierPerformance = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)
)

func decodePerformanceReport(
	reader io.Reader,
	corpus performanceCorpus,
	corpusSHA256 string,
) (performanceReport, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxPerformanceReportBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxPerformanceReportBytes || !utf8.Valid(data) {
		return performanceReport{}, errPerformanceReport
	}
	var report performanceReport
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil || !performanceEnd(decoder) ||
		!validPerformanceReport(report, corpus, corpusSHA256) {
		return performanceReport{}, errPerformanceReport
	}
	canonical, err := json.Marshal(report)
	if err != nil || !bytes.Equal(data, canonical) {
		return performanceReport{}, errPerformanceReport
	}
	return report, nil
}

func performanceEnd(decoder *json.Decoder) bool {
	var trailing struct{}
	return decoder.Decode(&trailing) == io.EOF
}

func validPerformanceReport(
	report performanceReport,
	corpus performanceCorpus,
	corpusSHA256 string,
) bool {
	if !validPerformanceHeader(report, corpusSHA256) || !validFullCampaignCorpus(corpus) {
		return false
	}
	accepted := acceptedPerformanceWorkloads(corpus)
	if len(report.Workloads) != len(accepted) {
		return false
	}
	attempts := make(map[string]struct{}, len(report.Workloads)*(coldSampleCount+warmSampleCount))
	for index, workload := range report.Workloads {
		expected := accepted[index]
		if !validWorkload(workload, report.Environment.Identity) {
			return false
		}
		if workload.Class != expected.Class || workload.WorkloadID != expected.ID ||
			workload.WorkloadSHA256 != workloadDigest(expected) {
			return false
		}
		if !addReportAttempts(attempts, workload) {
			return false
		}
	}
	return true
}

func acceptedPerformanceWorkloads(corpus performanceCorpus) []performanceWorkloadCase {
	accepted := make([]performanceWorkloadCase, 0, len(acceptedClasses))
	for _, workload := range corpus.Cases {
		if workload.Eligible {
			accepted = append(accepted, workload)
		}
	}
	return accepted
}

func validPerformanceHeader(report performanceReport, corpusSHA256 string) bool {
	return report.SchemaVersion == performanceReportSchema &&
		report.CorpusVersion == performanceCorpusSchema &&
		report.Calculation == performanceCalculation &&
		validPerformanceHash(corpusSHA256) && report.CorpusSHA256 == corpusSHA256 &&
		validEnvironment(report.Environment) &&
		len(report.Workloads) == len(acceptedClasses)
}

func addReportAttempts(attempts map[string]struct{}, workload performanceWorkload) bool {
	for _, profile := range []performanceProfile{workload.Cold, workload.Warm} {
		for _, sample := range profile.Samples {
			if _, duplicate := attempts[sample.AttemptID]; duplicate {
				return false
			}
			attempts[sample.AttemptID] = struct{}{}
		}
	}
	return true
}

func validEnvironment(environment performanceEnvironment) bool {
	if !validPerformanceHash(environment.Identity) || environment.Platform != "windows/amd64" ||
		!validPerformanceText(environment.Hardware, 256) ||
		!identifierPerformance.MatchString(environment.CacheState) || environment.Concurrency != 1 ||
		!validPerformanceHash(environment.WorkerSHA256) || !validCommit(environment.ProductCommit) {
		return false
	}
	return validToolchains(environment.Toolchains) &&
		environment.Identity == performanceEnvironmentIdentity(environment)
}

func validWorkload(workload performanceWorkload, environmentID string) bool {
	return validProfile(workload.Cold, "cold", coldSampleCount, environmentID) &&
		validProfile(workload.Warm, "warm", warmSampleCount, environmentID)
}

func validProfile(profile performanceProfile, mode string, count int, environmentID string) bool {
	if profile.Mode != mode || len(profile.Samples) != count {
		return false
	}
	for index, sample := range profile.Samples {
		if !validSample(sample, uint64(index+1), environmentID) {
			return false
		}
	}
	expected, err := calculateStatistics(profile.Samples)
	return err == nil && sameStatistics(profile.Statistics, expected)
}

func sameStatistics(actual, expected performanceStatistics) bool {
	if actual.SampleCount != expected.SampleCount ||
		actual.ThroughputMilliOpsPerSecond != expected.ThroughputMilliOpsPerSecond ||
		len(actual.Phases) != len(expected.Phases) ||
		len(actual.Resources) != len(expected.Resources) {
		return false
	}
	for index, phase := range actual.Phases {
		if phase != expected.Phases[index] {
			return false
		}
	}
	for index, resource := range actual.Resources {
		if resource != expected.Resources[index] {
			return false
		}
	}
	return true
}

func validSample(sample performanceSample, sequence uint64, environmentID string) bool {
	return sample.Sequence == sequence && validPerformanceIdentity(sample.AttemptID) &&
		sample.EnvironmentID == environmentID && sample.Outcome == string(Verified) &&
		sample.CleanupComplete && validSamplePhases(sample.Phases) && validResources(sample.Resources)
}

func validResources(resources resourceMeasurement) bool {
	return resources.Measured && resources.PeakWorkingSetBytes > 0 &&
		resources.PeakWorkingSetBytes <= maxPerformanceMemoryBytes &&
		resources.PeakProcessCommitBytes > 0 &&
		resources.PeakProcessCommitBytes <= maxPerformanceMemoryBytes &&
		resources.PeakJobCommitBytes > 0 &&
		resources.PeakJobCommitBytes <= maxPerformanceMemoryBytes &&
		resources.EvidenceBytes > 0 && resources.EvidenceBytes <= maxPerformanceEvidenceBytes &&
		resources.WorkerImageBytes > 0
}

func validToolchains(toolchains []string) bool {
	if len(toolchains) == 0 || len(toolchains) > 16 {
		return false
	}
	previous := ""
	for _, toolchain := range toolchains {
		if !identifierPerformance.MatchString(toolchain) || toolchain <= previous {
			return false
		}
		previous = toolchain
	}
	return true
}

func validPerformanceIdentity(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validPerformanceHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func validCommit(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 20 && hex.EncodeToString(decoded) == value
}

func validPerformanceText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, rune := range value {
		if rune < 0x20 || rune == 0x7f {
			return false
		}
	}
	return true
}

func performanceEnvironmentIdentity(environment performanceEnvironment) string {
	canonical := strings.Join([]string{
		environment.Platform,
		environment.Hardware,
		strings.Join(environment.Toolchains, "\x00"),
		environment.CacheState,
		strconv.FormatUint(environment.Concurrency, 10),
		environment.WorkerSHA256,
		environment.ProductCommit,
	}, "\x00")
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}
