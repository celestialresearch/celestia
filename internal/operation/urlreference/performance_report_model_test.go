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
	"errors"
	"math"
	"slices"
)

const (
	performanceReportSchema = "celestia.operation-performance-report.v1"
	performanceCorpusSchema = "celestia.url-reference-performance-workload.v1"
	performanceCalculation  = "nearest-rank-v1"
	coldSampleCount         = 30
	warmSampleCount         = 100
)

var errPerformanceReport = errors.New("invalid operation performance report")

type performanceReport struct {
	SchemaVersion string                 `json:"schema_version"`
	CorpusVersion string                 `json:"corpus_version"`
	CorpusSHA256  string                 `json:"corpus_sha256"`
	Calculation   string                 `json:"calculation_version"`
	Environment   performanceEnvironment `json:"environment"`
	Workloads     []performanceWorkload  `json:"workloads"`
}

type performanceEnvironment struct {
	Identity      string   `json:"identity"`
	Platform      string   `json:"platform"`
	Hardware      string   `json:"hardware"`
	Toolchains    []string `json:"toolchains"`
	CacheState    string   `json:"cache_state"`
	Concurrency   uint64   `json:"concurrency"`
	WorkerSHA256  string   `json:"worker_sha256"`
	ProductCommit string   `json:"product_commit"`
}

type performanceWorkload struct {
	Class          string             `json:"class"`
	WorkloadID     string             `json:"workload_id"`
	WorkloadSHA256 string             `json:"workload_sha256"`
	Cold           performanceProfile `json:"cold"`
	Warm           performanceProfile `json:"warm"`
}

type performanceProfile struct {
	Mode       string                `json:"mode"`
	Samples    []performanceSample   `json:"samples"`
	Statistics performanceStatistics `json:"statistics"`
}

type performanceSample struct {
	Sequence        uint64              `json:"sequence"`
	AttemptID       string              `json:"attempt_id"`
	EnvironmentID   string              `json:"environment_id"`
	Outcome         string              `json:"outcome"`
	CleanupComplete bool                `json:"cleanup_complete"`
	Phases          []phaseMeasurement  `json:"phases"`
	Resources       resourceMeasurement `json:"resources"`
}

type phaseMeasurement struct {
	ID         string `json:"id"`
	DurationNS uint64 `json:"duration_ns"`
}

type resourceMeasurement struct {
	Measured                bool   `json:"measured"`
	WorkerCPUTimeNS         uint64 `json:"worker_cpu_time_ns"`
	PeakWorkingSetBytes     uint64 `json:"peak_working_set_bytes"`
	PeakProcessCommitBytes  uint64 `json:"peak_process_commit_bytes"`
	PeakJobCommitBytes      uint64 `json:"peak_job_commit_bytes"`
	JobReadOperations       uint64 `json:"job_read_operations"`
	JobWriteOperations      uint64 `json:"job_write_operations"`
	JobOtherOperations      uint64 `json:"job_other_operations"`
	JobReadBytes            uint64 `json:"job_read_bytes"`
	JobWriteBytes           uint64 `json:"job_write_bytes"`
	JobOtherBytes           uint64 `json:"job_other_bytes"`
	GoRuntimeAllocatedBytes uint64 `json:"go_runtime_allocated_bytes"`
	EvidenceBytes           uint64 `json:"evidence_bytes"`
	WorkerImageBytes        uint64 `json:"worker_image_bytes"`
}

type performanceStatistics struct {
	SampleCount                 uint64                `json:"sample_count"`
	ThroughputMilliOpsPerSecond uint64                `json:"throughput_milli_ops_per_second"`
	Phases                      []phasePercentiles    `json:"phases"`
	Resources                   []resourcePercentiles `json:"resources"`
}

type phasePercentiles struct {
	ID  string `json:"id"`
	P50 uint64 `json:"p50_ns"`
	P95 uint64 `json:"p95_ns"`
	P99 uint64 `json:"p99_ns"`
}

type resourcePercentiles struct {
	ID  string `json:"id"`
	P50 uint64 `json:"p50"`
	P95 uint64 `json:"p95"`
	P99 uint64 `json:"p99"`
}

var performancePhases = [...]string{
	"request",
	"admission",
	"staging",
	"preparation",
	"process_start",
	"stdin_write",
	"worker_transform",
	"stdout_collection",
	"stderr_collection",
	"wait_and_cleanup",
	"protocol_validation",
	"independent_verification",
	"terminal_observation",
	"durable_publication",
	"receipt_projection",
	"total_latency",
}

var performanceResources = [...]string{
	"worker_cpu_time_ns",
	"peak_working_set_bytes",
	"peak_process_commit_bytes",
	"peak_job_commit_bytes",
	"job_read_operations",
	"job_write_operations",
	"job_other_operations",
	"job_read_bytes",
	"job_write_bytes",
	"job_other_bytes",
	"go_runtime_allocated_bytes",
	"evidence_bytes",
	"worker_image_bytes",
}

func calculateStatistics(samples []performanceSample) (performanceStatistics, error) {
	if len(samples) == 0 {
		return performanceStatistics{}, errPerformanceReport
	}
	phaseValues := make([][]uint64, len(performancePhases))
	resourceValues := make([][]uint64, len(performanceResources))
	var total uint64
	for _, sample := range samples {
		if !validSamplePhases(sample.Phases) {
			return performanceStatistics{}, errPerformanceReport
		}
		for index, phase := range sample.Phases {
			phaseValues[index] = append(phaseValues[index], phase.DurationNS)
		}
		for index, value := range sampleResourceValues(sample.Resources) {
			resourceValues[index] = append(resourceValues[index], value)
		}
		var overflow bool
		total, overflow = addDuration(total, sample.Phases[len(sample.Phases)-1].DurationNS)
		if overflow {
			return performanceStatistics{}, errPerformanceReport
		}
	}
	if total == 0 {
		return performanceStatistics{}, errPerformanceReport
	}
	sampleCount := uint64(0)
	for range samples {
		sampleCount++
	}
	statistics := performanceStatistics{
		SampleCount: sampleCount,
		Phases:      make([]phasePercentiles, len(performancePhases)),
		Resources:   make([]resourcePercentiles, len(performanceResources)),
	}
	statistics.ThroughputMilliOpsPerSecond = throughput(sampleCount, total)
	for index := range performancePhases {
		statistics.Phases[index] = percentileValues(performancePhases[index], phaseValues[index])
	}
	for index := range performanceResources {
		statistics.Resources[index] = resourceValuesPercentiles(performanceResources[index], resourceValues[index])
	}
	return statistics, nil
}

func sampleResourceValues(resources resourceMeasurement) [len(performanceResources)]uint64 {
	return [...]uint64{
		resources.WorkerCPUTimeNS,
		resources.PeakWorkingSetBytes,
		resources.PeakProcessCommitBytes,
		resources.PeakJobCommitBytes,
		resources.JobReadOperations,
		resources.JobWriteOperations,
		resources.JobOtherOperations,
		resources.JobReadBytes,
		resources.JobWriteBytes,
		resources.JobOtherBytes,
		resources.GoRuntimeAllocatedBytes,
		resources.EvidenceBytes,
		resources.WorkerImageBytes,
	}
}

func addDuration(total, next uint64) (uint64, bool) {
	if math.MaxUint64-total < next {
		return 0, true
	}
	return total + next, false
}

func throughput(samples, totalNS uint64) uint64 {
	const nanosecondsPerSecond = uint64(1_000_000_000)
	if samples > math.MaxUint64/(nanosecondsPerSecond*1_000) {
		return math.MaxUint64
	}
	return samples * nanosecondsPerSecond * 1_000 / totalNS
}

func percentileValues(id string, values []uint64) phasePercentiles {
	slices.Sort(values)
	return phasePercentiles{
		ID:  id,
		P50: nearestRank(values, 50),
		P95: nearestRank(values, 95),
		P99: nearestRank(values, 99),
	}
}

func resourceValuesPercentiles(id string, values []uint64) resourcePercentiles {
	slices.Sort(values)
	return resourcePercentiles{
		ID:  id,
		P50: nearestRank(values, 50),
		P95: nearestRank(values, 95),
		P99: nearestRank(values, 99),
	}
}

func nearestRank(values []uint64, percentile uint64) uint64 {
	rank := (percentile*uint64(len(values)) + 99) / 100
	return values[rank-1]
}

func validSamplePhases(phases []phaseMeasurement) bool {
	if len(phases) != len(performancePhases) {
		return false
	}
	total := phases[len(phases)-1].DurationNS
	for index, phase := range phases {
		if phase.ID != performancePhases[index] || phase.DurationNS > total {
			return false
		}
	}
	return true
}
