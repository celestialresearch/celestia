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

//go:build windows && amd64

package urloperation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	attemptstore "celestia.research/celestia/internal/operation/urlreference/attempt"
	workerprotocol "celestia.research/celestia/internal/operation/urlreference/protocol"
	"celestia.research/celestia/internal/operation/urlreference/transform"
	"celestia.research/celestia/internal/testcargo"
)

const performanceReportEnvironment = "CELESTIA_OPERATION_PERFORMANCE_REPORT"

const maximumCampaignEvidenceFiles = 4

const performanceCampaignTimeout = 10 * time.Minute

type campaignOperation struct {
	operation    *Operation
	evidenceRoot string
	workerPath   string
	workerSHA256 string
	cleanup      func() error
}

type performanceCampaign struct {
	corpus       performanceCorpus
	corpusSHA256 string
	environment  performanceEnvironment
	coldCount    int
	warmCount    int
	requireFull  bool
	newCold      func() (campaignOperation, error)
	newWarm      func() (campaignOperation, error)
	execute      func(context.Context, campaignOperation, performanceWorkloadCase) (performanceSample, error)
	publish      func(performanceReport) error
}

func TestOperationPerformanceCampaign(t *testing.T) {
	output := os.Getenv(performanceReportEnvironment)
	if output == "" {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), performanceCampaignTimeout)
	defer cancel()
	campaign, err := newOperationPerformanceCampaign(t, ctx, output)
	if err != nil {
		t.Fatal(err)
	}
	report, err := campaign.run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Workloads) != len(acceptedClasses) {
		t.Fatalf("workloads=%d want=%d", len(report.Workloads), len(acceptedClasses))
	}
}

func TestPerformanceManifestBindsResourceOwners(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	repository, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := repository.Close(); err != nil {
			t.Errorf("close repository root: %v", err)
		}
	})
	data, err := repository.ReadFile("docs/contracts/governed_url_reference_performance_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest performanceManifestBounds
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if !validPerformanceManifestBounds(manifest.Bounds) {
		t.Fatalf("bounds=%+v", manifest.Bounds)
	}
	want := fmt.Sprintf("One attempt bundle and %d aggregate output bytes", maxPerformanceEvidenceBytes)
	acquisition := "One shared warm root plus one cold root per sample; each holds one attempt bundle at a time"
	matched := 0
	for _, resource := range manifest.Resources {
		if resource.ID == "CEL-PERF-RESOURCE-002" {
			matched++
			if resource.Acquisition != acquisition {
				t.Fatalf("evidence acquisition=%q want=%q", resource.Acquisition, acquisition)
			}
			if resource.Bound != want {
				t.Fatalf("evidence bound=%q want=%q", resource.Bound, want)
			}
		}
	}
	if matched != 1 {
		t.Fatalf("temporary evidence resources=%d", matched)
	}
}

type performanceManifestBounds struct {
	Bounds    performanceBounds `json:"bounds"`
	Resources []struct {
		ID          string `json:"id"`
		Acquisition string `json:"acquisition"`
		Bound       string `json:"bound"`
	} `json:"resources"`
}

type performanceBounds struct {
	Processes              uint64 `json:"processes"`
	MemoryBytes            uint64 `json:"memory_bytes"`
	OutputBytes            uint64 `json:"output_bytes"`
	WorkerTimeMilliseconds uint64 `json:"worker_time_milliseconds"`
	PersistenceBytes       uint64 `json:"persistence_bytes"`
}

func validPerformanceManifestBounds(bounds performanceBounds) bool {
	return bounds.Processes == uint64(workerprotocol.Processes) &&
		bounds.MemoryBytes == uint64(workerprotocol.MemoryBytes) &&
		bounds.OutputBytes == uint64(maxPerformanceReportBytes) &&
		bounds.WorkerTimeMilliseconds == uint64(workerprotocol.TimeoutMS) &&
		bounds.PersistenceBytes == uint64(maxPerformanceEvidenceBytes)
}

func TestPerformanceCampaignReleasesWarmEvidencePerSample(t *testing.T) {
	corpus := performanceCorpus{Cases: []performanceWorkloadCase{
		{ID: "short-fang", Class: "shortest_fang", Kind: "accepted", Mode: "fang", Input: "hxxp://a[.]b/", Expected: "http://a.b/", Paths: []string{"cold", "warm"}, Eligible: true},
	}}
	var cold, warm, next uint64
	warmRoot := newCampaignMeterRoot(t)
	warmCleaned := false
	campaign := performanceCampaign{
		corpus:       corpus,
		corpusSHA256: strings.Repeat("a", 64),
		environment:  testCampaignEnvironment(),
		coldCount:    2,
		warmCount:    3,
		newCold: func() (campaignOperation, error) {
			cold++
			return campaignOperation{evidenceRoot: newCampaignMeterRoot(t)}, nil
		},
		newWarm: func() (campaignOperation, error) {
			warm++
			return campaignOperation{evidenceRoot: warmRoot, cleanup: func() error {
				warmCleaned = true
				return nil
			}}, nil
		},
		execute: func(_ context.Context, operation campaignOperation, _ performanceWorkloadCase) (performanceSample, error) {
			if attemptCount(t, operation.evidenceRoot) != 0 {
				return performanceSample{}, errors.New("prior attempt remains")
			}
			next++
			writeCampaignAttempt(t, operation.evidenceRoot, performanceTestIdentity(next))
			return testPerformanceSample(0, next), nil
		},
	}
	report, err := campaign.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cold != 2 || warm != 1 || !warmCleaned || len(report.Workloads) != 1 {
		t.Fatalf("cold=%d warm=%d warm_cleaned=%t workloads=%d", cold, warm, warmCleaned, len(report.Workloads))
	}
	if got := report.Workloads[0]; len(got.Cold.Samples) != 2 || len(got.Warm.Samples) != 3 {
		t.Fatalf("samples=%+v", got)
	}
	if attemptCount(t, warmRoot) != 0 {
		t.Fatal("warm root retained a measured attempt")
	}
}

func TestPerformanceCampaignDoesNotPublishPartialReport(t *testing.T) {
	corpus := performanceCorpus{Cases: []performanceWorkloadCase{
		{ID: "short-fang", Class: "shortest_fang", Kind: "accepted", Mode: "fang", Input: "hxxp://a[.]b/", Expected: "http://a.b/", Paths: []string{"cold", "warm"}, Eligible: true},
	}}
	published := false
	campaign := performanceCampaign{
		corpus:       corpus,
		corpusSHA256: strings.Repeat("a", 64),
		environment:  testCampaignEnvironment(),
		coldCount:    1,
		warmCount:    1,
		newCold:      func() (campaignOperation, error) { return campaignOperation{}, nil },
		newWarm:      func() (campaignOperation, error) { return campaignOperation{}, nil },
		execute: func(context.Context, campaignOperation, performanceWorkloadCase) (performanceSample, error) {
			return performanceSample{}, errors.New("injected failure")
		},
		publish: func(performanceReport) error {
			published = true
			return nil
		},
	}
	if _, err := campaign.run(context.Background()); err == nil {
		t.Fatal("campaign accepted failed sample")
	}
	if published {
		t.Fatal("campaign published partial report")
	}
}

func TestPerformanceCampaignCancellationAfterFinalRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	warmCleaned := false
	published := false
	var next uint64
	warmRoot := newCampaignMeterRoot(t)
	campaign := performanceCampaign{
		corpus:       singleCampaignCorpus(),
		corpusSHA256: strings.Repeat("a", 64),
		environment:  testCampaignEnvironment(),
		coldCount:    1,
		warmCount:    1,
		newCold:      func() (campaignOperation, error) { return testCampaignOperation(t, nil), nil },
		newWarm: func() (campaignOperation, error) {
			return campaignOperation{evidenceRoot: warmRoot, cleanup: func() error {
				if attemptCount(t, warmRoot) != 0 {
					return errors.New("warm attempt remained after release")
				}
				warmCleaned = true
				cancel()
				return nil
			}}, nil
		},
		execute: func(_ context.Context, operation campaignOperation, _ performanceWorkloadCase) (performanceSample, error) {
			next++
			return testCampaignSample(t, operation, next), nil
		},
		publish: func(performanceReport) error {
			published = true
			return nil
		},
	}
	if _, err := campaign.run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
	if !warmCleaned {
		t.Fatal("campaign did not clean the warm operation")
	}
	if next != 2 {
		t.Fatalf("samples=%d want=2", next)
	}
	if published {
		t.Fatal("campaign published after cancellation")
	}
}

func singleCampaignCorpus() performanceCorpus {
	return performanceCorpus{Cases: []performanceWorkloadCase{{
		ID: "short-fang", Class: "shortest_fang", Kind: "accepted", Mode: "fang",
		Input: "hxxp://a[.]b/", Expected: "http://a.b/", Paths: []string{"cold", "warm"}, Eligible: true,
	}}}
}

func TestPerformanceCampaignDoesNotPublishWhenCleanupFails(t *testing.T) {
	corpus := performanceCorpus{Cases: []performanceWorkloadCase{
		{ID: "short-fang", Class: "shortest_fang", Kind: "accepted", Mode: "fang", Input: "hxxp://a[.]b/", Expected: "http://a.b/", Paths: []string{"cold", "warm"}, Eligible: true},
	}}
	cleanupErr := errors.New("injected cleanup failure")
	warmCleaned := false
	published := false
	campaign := performanceCampaign{
		corpus:       corpus,
		corpusSHA256: strings.Repeat("a", 64),
		environment:  testCampaignEnvironment(),
		coldCount:    1,
		warmCount:    1,
		newCold: func() (campaignOperation, error) {
			return testCampaignOperation(t, func() error { return cleanupErr }), nil
		},
		newWarm: func() (campaignOperation, error) {
			return testCampaignOperation(t, func() error {
				warmCleaned = true
				return nil
			}), nil
		},
		execute: func(_ context.Context, operation campaignOperation, _ performanceWorkloadCase) (performanceSample, error) {
			return testCampaignSample(t, operation, 1), nil
		},
		publish: func(performanceReport) error {
			published = true
			return nil
		},
	}
	if _, err := campaign.run(context.Background()); !errors.Is(err, cleanupErr) {
		t.Fatalf("cleanup error=%v", err)
	}
	if published {
		t.Fatal("campaign published report after cleanup failure")
	}
	if !warmCleaned {
		t.Fatal("campaign did not clean the warm evidence root")
	}
}

func TestPerformanceCampaignDoesNotPublishWhenWarmCleanupFails(t *testing.T) {
	corpus := performanceCorpus{Cases: []performanceWorkloadCase{
		{ID: "short-fang", Class: "shortest_fang", Kind: "accepted", Mode: "fang", Input: "hxxp://a[.]b/", Expected: "http://a.b/", Paths: []string{"cold", "warm"}, Eligible: true},
	}}
	cleanupErr := errors.New("injected warm cleanup failure")
	published := false
	campaign := performanceCampaign{
		corpus:       corpus,
		corpusSHA256: strings.Repeat("a", 64),
		environment:  testCampaignEnvironment(),
		coldCount:    1,
		warmCount:    1,
		newCold:      func() (campaignOperation, error) { return testCampaignOperation(t, nil), nil },
		newWarm: func() (campaignOperation, error) {
			return testCampaignOperation(t, func() error { return cleanupErr }), nil
		},
		execute: func(_ context.Context, operation campaignOperation, _ performanceWorkloadCase) (performanceSample, error) {
			return testCampaignSample(t, operation, 1), nil
		},
		publish: func(performanceReport) error {
			published = true
			return nil
		},
	}
	if _, err := campaign.run(context.Background()); !errors.Is(err, cleanupErr) {
		t.Fatalf("cleanup error=%v", err)
	}
	if published {
		t.Fatal("campaign published report after warm cleanup failure")
	}
}

func TestPerformanceCampaignCleansEvidenceBeforePublication(t *testing.T) {
	corpus := performanceCorpus{Cases: []performanceWorkloadCase{
		{ID: "short-fang", Class: "shortest_fang", Kind: "accepted", Mode: "fang", Input: "hxxp://a[.]b/", Expected: "http://a.b/", Paths: []string{"cold", "warm"}, Eligible: true},
	}}
	coldCleaned := false
	warmCleaned := false
	published := false
	campaign := performanceCampaign{
		corpus:       corpus,
		corpusSHA256: strings.Repeat("a", 64),
		environment:  testCampaignEnvironment(),
		coldCount:    1,
		warmCount:    1,
		newCold: func() (campaignOperation, error) {
			return testCampaignOperation(t, func() error {
				coldCleaned = true
				return nil
			}), nil
		},
		newWarm: func() (campaignOperation, error) {
			return testCampaignOperation(t, func() error {
				warmCleaned = true
				return nil
			}), nil
		},
		execute: func(_ context.Context, operation campaignOperation, _ performanceWorkloadCase) (performanceSample, error) {
			return testCampaignSample(t, operation, 1), nil
		},
		publish: func(performanceReport) error {
			if !coldCleaned || !warmCleaned {
				return errors.New("publish before evidence cleanup")
			}
			published = true
			return nil
		},
	}
	if _, err := campaign.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !published {
		t.Fatal("campaign did not publish after cleanup")
	}
}

func TestNewCampaignEvidenceRootRemovesOwnedDirectory(t *testing.T) {
	root, cleanup := newCampaignEvidenceRoot(t)
	directory := filepath.Dir(filepath.Dir(root))
	if _, err := New(testWorker(t), root); err != nil {
		t.Fatalf("create operation: %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("evidence root: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("campaign directory remains: %v", err)
	}
}

func TestCampaignEvidenceBytesRejectsAdditionalAttempt(t *testing.T) {
	root := t.TempDir()
	first := performanceTestIdentity(1)
	second := performanceTestIdentity(2)
	writeCampaignAttempt(t, root, first)
	bytes, err := campaignEvidenceBytes(root, first)
	if err != nil || bytes != 4 {
		t.Fatalf("first attempt bytes=%d error=%v", bytes, err)
	}
	writeCampaignAttempt(t, root, second)
	if _, err := campaignEvidenceBytes(root, first); !errors.Is(err, errPerformanceReport) {
		t.Fatalf("additional attempt error=%v", err)
	}
	if err := discardCampaignAttempt(root, "../first"); !errors.Is(err, errPerformanceReport) {
		t.Fatalf("invalid attempt removal error=%v", err)
	}
}

func writeCampaignAttempt(t *testing.T, root, attemptID string) {
	t.Helper()
	directory := filepath.Join(root, "attempts", attemptID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"admitted.json", "observation.json", "receipt.json", "publication.json"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name[:1]), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func newCampaignMeterRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "attempts", ".pending"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func testCampaignOperation(t *testing.T, cleanup func() error) campaignOperation {
	t.Helper()
	return campaignOperation{evidenceRoot: newCampaignMeterRoot(t), cleanup: cleanup}
}

func testCampaignSample(t *testing.T, operation campaignOperation, identity uint64) performanceSample {
	t.Helper()
	sample := testPerformanceSample(0, identity)
	writeCampaignAttempt(t, operation.evidenceRoot, sample.AttemptID)
	return sample
}

func attemptCount(t *testing.T, root string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if entry.Name() != ".pending" {
			count++
		}
	}
	return count
}

func TestPerformanceCampaignRejectsUnmeasuredSample(t *testing.T) {
	corpus := performanceCorpus{Cases: []performanceWorkloadCase{
		{ID: "short-fang", Class: "shortest_fang", Kind: "accepted", Mode: "fang", Input: "hxxp://a[.]b/", Expected: "http://a.b/", Paths: []string{"cold", "warm"}, Eligible: true},
	}}
	var next uint64
	campaign := performanceCampaign{
		corpus:       corpus,
		corpusSHA256: strings.Repeat("a", 64),
		environment:  testCampaignEnvironment(),
		coldCount:    1,
		warmCount:    1,
		newCold:      func() (campaignOperation, error) { return campaignOperation{}, nil },
		newWarm:      func() (campaignOperation, error) { return campaignOperation{}, nil },
		execute: func(context.Context, campaignOperation, performanceWorkloadCase) (performanceSample, error) {
			next++
			sample := testPerformanceSample(0, next)
			sample.Resources.Measured = false
			return sample, nil
		},
	}
	if _, err := campaign.run(context.Background()); err == nil {
		t.Fatal("campaign accepted an unmeasured sample")
	}
}

func TestPerformanceCampaignDigestsCorpusAndRows(t *testing.T) {
	data := []byte(`{"version":1,"operation":"url-reference","cases":[]}`)
	corpus := performanceCorpus{Cases: []performanceWorkloadCase{{ID: "short-fang", Class: "shortest_fang"}}}
	digest := sha256.Sum256(data)
	if got := corpusDigest(data); got != hex.EncodeToString(digest[:]) {
		t.Fatalf("corpus digest=%s", got)
	}
	encoded, err := json.Marshal(corpus.Cases[0])
	if err != nil {
		t.Fatal(err)
	}
	rowDigest := sha256.Sum256(encoded)
	if got := workloadDigest(corpus.Cases[0]); got != hex.EncodeToString(rowDigest[:]) {
		t.Fatalf("workload digest=%s", got)
	}
}

func TestPerformanceCampaignRequiresCleanCheckout(t *testing.T) {
	root := t.TempDir()
	run := func(command *exec.Cmd) {
		t.Helper()
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", command.Args, err, output)
		}
	}
	run(exec.CommandContext(t.Context(), "git", "init", "--quiet"))
	path := filepath.Join(root, "source.go")
	if err := os.WriteFile(path, []byte("package fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(exec.CommandContext(t.Context(), "git", "add", "source.go"))
	run(exec.CommandContext(
		t.Context(),
		"git", "-c", "commit.gpgsign=false", "-c", "user.name=Celestia Test",
		"-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "fixture",
	))
	if err := requireCleanPerformanceCheckout(root); err != nil {
		t.Fatalf("clean checkout rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte("package changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireCleanPerformanceCheckout(root); !errors.Is(err, errPerformanceReport) {
		t.Fatalf("dirty checkout error=%v", err)
	}
	run(exec.CommandContext(t.Context(), "git", "checkout", "--", "source.go"))
	if err := os.WriteFile(filepath.Join(root, "untracked.go"), []byte("package fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireCleanPerformanceCheckout(root); !errors.Is(err, errPerformanceReport) {
		t.Fatalf("untracked source error=%v", err)
	}
}

func TestPerformanceCampaignRequiresCompleteCorpus(t *testing.T) {
	campaign := performanceCampaign{
		corpus:       performanceCorpus{},
		corpusSHA256: strings.Repeat("a", 64),
		environment:  testCampaignEnvironment(),
		coldCount:    coldSampleCount,
		warmCount:    warmSampleCount,
		requireFull:  true,
		newCold:      func() (campaignOperation, error) { return campaignOperation{}, nil },
		newWarm:      func() (campaignOperation, error) { return campaignOperation{}, nil },
		execute: func(context.Context, campaignOperation, performanceWorkloadCase) (performanceSample, error) {
			return performanceSample{}, nil
		},
	}
	if err := campaign.valid(); !errors.Is(err, errPerformanceReport) {
		t.Fatalf("validation error=%v", err)
	}
}

func TestPerformanceCampaignMeasuresPublishedEvidence(t *testing.T) {
	root := testEvidenceRoot(t)
	worker := testWorker(t)
	workerSHA256, err := fileDigest(worker)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := New(worker, root)
	if err != nil {
		t.Fatal(err)
	}
	result, timings := operation.executeMeasured(
		context.Background(),
		"https://example.test/",
		urlreference.Defang,
	)
	if result.Status != Verified {
		t.Fatalf("result=%+v", result)
	}
	if !validCampaignResult(result, timings, *result.Response.Output) {
		t.Fatal("verified operation rejected")
	}
	phases := campaignPhases(timings)
	publication := slices.IndexFunc(phases, func(phase phaseMeasurement) bool {
		return phase.ID == "durable_publication"
	})
	if publication < 0 || phases[publication].DurationNS != durationNanoseconds(timings.Publication) {
		t.Fatal("durable publication phase did not retain its timing")
	}
	failedCleanup := result
	failedCleanup.Err = ErrCleanup
	if validCampaignResult(failedCleanup, timings, *result.Response.Output) {
		t.Fatal("cleanup failure accepted")
	}
	bytes, err := campaignEvidenceBytes(root, result.AttemptID)
	if err != nil || bytes == 0 {
		t.Fatalf("evidence bytes=%d error=%v", bytes, err)
	}
	candidate := campaignOperation{
		operation: operation, evidenceRoot: root, workerPath: worker, workerSHA256: workerSHA256,
	}
	if err := validCampaignEvidence(candidate, result.AttemptID, *result.Response.Output); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	candidate.workerSHA256 = strings.Repeat("0", 64)
	if err := validCampaignEvidence(candidate, result.AttemptID, *result.Response.Output); !errors.Is(err, errPerformanceReport) {
		t.Fatalf("worker mismatch error=%v", err)
	}
}

func newOperationPerformanceCampaign(
	t *testing.T,
	ctx context.Context,
	output string,
) (performanceCampaign, error) {
	t.Helper()
	outputRoot, outputName, err := openPerformanceOutput(output)
	if err != nil {
		return performanceCampaign{}, err
	}
	t.Cleanup(func() {
		if err := outputRoot.Close(); err != nil {
			t.Errorf("close performance output root: %v", err)
		}
	})
	root, err := repositoryRoot()
	if err != nil {
		return performanceCampaign{}, err
	}
	if err := requireCleanPerformanceCheckout(root); err != nil {
		return performanceCampaign{}, err
	}
	corpusData, err := readPerformanceCorpusFile(performanceCorpusPath)
	if err != nil {
		return performanceCampaign{}, fmt.Errorf("read performance corpus: %w", err)
	}
	corpus, err := decodePerformanceCorpus(corpusData)
	if err != nil {
		return performanceCampaign{}, fmt.Errorf("decode performance corpus: %w", err)
	}
	worker, err := performanceWorker(t, ctx)
	if err != nil {
		return performanceCampaign{}, err
	}
	environment, err := operationPerformanceEnvironment(worker)
	if err != nil {
		return performanceCampaign{}, err
	}
	return performanceCampaign{
		corpus:       corpus,
		corpusSHA256: corpusDigest(corpusData),
		environment:  environment,
		coldCount:    coldSampleCount,
		warmCount:    warmSampleCount,
		requireFull:  true,
		newCold: func() (campaignOperation, error) {
			root, cleanup := newCampaignEvidenceRoot(t)
			operation, err := New(worker, root)
			if err != nil {
				return campaignOperation{}, errors.Join(err, cleanup())
			}
			return campaignOperation{
				operation: operation, evidenceRoot: root, workerPath: worker,
				workerSHA256: environment.WorkerSHA256, cleanup: cleanup,
			}, nil
		},
		newWarm: func() (campaignOperation, error) {
			root, cleanup := newCampaignEvidenceRoot(t)
			operation, err := New(worker, root)
			if err != nil {
				return campaignOperation{}, errors.Join(err, cleanup())
			}
			return campaignOperation{
				operation: operation, evidenceRoot: root, workerPath: worker,
				workerSHA256: environment.WorkerSHA256, cleanup: cleanup,
			}, nil
		},
		execute: campaignOperationSample,
		publish: func(report performanceReport) error {
			return writeOpenedPerformanceReport(outputRoot, outputName, report, corpus, corpusDigest(corpusData))
		},
	}, nil
}

func performanceWorker(t *testing.T, ctx context.Context) (string, error) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	root, err := repositoryRoot()
	if err != nil {
		return "", err
	}
	targetDirectory := filepath.Join(t.TempDir(), "cargo-target")
	if err := testcargo.Build(ctx, testcargo.Request{
		Arguments: []string{
			"build", "--release", "--locked", "--target", "x86_64-pc-windows-msvc",
			"--package", "celestia-url-reference", "--bin", "celestia-url-reference",
		},
		Directory:   root,
		Environment: cargoTargetEnvironment(os.Environ(), targetDirectory),
	}); err != nil {
		return "", fmt.Errorf("build release worker: %w", err)
	}
	path := filepath.Join(
		targetDirectory, "x86_64-pc-windows-msvc", "release", "celestia-url-reference.exe",
	)
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", errPerformanceReport
	}
	return path, nil
}

func TestPerformanceWorkerRejectsCancelledCampaign(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := performanceWorker(t, ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}

func newCampaignEvidenceRoot(t *testing.T) (string, func() error) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "campaign")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	root := testEvidenceRootAt(t, directory)
	return root, func() error {
		if err := os.RemoveAll(directory); err != nil {
			return fmt.Errorf("remove campaign evidence root %q: %w", root, err)
		}
		return nil
	}
}

func (campaign performanceCampaign) run(ctx context.Context) (report performanceReport, err error) {
	if err := campaign.valid(); err != nil {
		return performanceReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return performanceReport{}, err
	}
	report = performanceReport{
		SchemaVersion: performanceReportSchema,
		CorpusVersion: performanceCorpusSchema,
		CorpusSHA256:  campaign.corpusSHA256,
		Calculation:   performanceCalculation,
		Environment:   campaign.environment,
	}
	report.Environment.Identity = performanceEnvironmentIdentity(report.Environment)
	warm, err := campaign.newWarm()
	if err != nil {
		return performanceReport{}, fmt.Errorf("create warm operation: %w", errors.Join(err, cleanCampaignOperation(warm)))
	}
	cleaned := false
	cleanWarm := func() error {
		if cleaned {
			return nil
		}
		cleaned = true
		return cleanCampaignOperation(warm)
	}
	defer func() {
		if cleanupErr := cleanWarm(); cleanupErr != nil {
			report = performanceReport{}
			err = errors.Join(err, cleanupErr)
		}
	}()
	if err := ctx.Err(); err != nil {
		return performanceReport{}, err
	}
	for _, workload := range campaign.corpus.Cases {
		if !workload.Eligible {
			continue
		}
		measured, err := campaign.measureWorkload(ctx, workload, warm)
		if err != nil {
			return performanceReport{}, err
		}
		report.Workloads = append(report.Workloads, measured)
	}
	if err := cleanWarm(); err != nil {
		return performanceReport{}, err
	}
	if campaign.requireFull && !validPerformanceReport(report, campaign.corpus, campaign.corpusSHA256) {
		return performanceReport{}, errPerformanceReport
	}
	if campaign.publish != nil {
		if err := ctx.Err(); err != nil {
			return performanceReport{}, err
		}
		if err := campaign.publish(report); err != nil {
			return performanceReport{}, fmt.Errorf("publish performance report: %w", err)
		}
	}
	return report, nil
}

func (campaign performanceCampaign) valid() error {
	if !validCampaignCore(campaign) || !validCampaignCounts(campaign) {
		return errPerformanceReport
	}
	if campaign.requireFull && !validFullCampaignCorpus(campaign.corpus) {
		return errPerformanceReport
	}
	return nil
}

func validCampaignCore(campaign performanceCampaign) bool {
	return campaign.newCold != nil && campaign.newWarm != nil && campaign.execute != nil &&
		validPerformanceHash(campaign.corpusSHA256) && validEnvironment(campaign.environment)
}

func validCampaignCounts(campaign performanceCampaign) bool {
	if campaign.coldCount < 1 || campaign.warmCount < 1 {
		return false
	}
	return !campaign.requireFull ||
		(campaign.coldCount == coldSampleCount && campaign.warmCount == warmSampleCount)
}

func (campaign performanceCampaign) measureWorkload(
	ctx context.Context,
	workload performanceWorkloadCase,
	warm campaignOperation,
) (performanceWorkload, error) {
	cold, err := campaign.measureProfile(
		ctx, workload, "cold", campaign.coldCount, campaign.newCold, releaseColdCampaignOperation,
	)
	if err != nil {
		return performanceWorkload{}, err
	}
	warmProfile, err := campaign.measureProfile(
		ctx, workload, "warm", campaign.warmCount, func() (campaignOperation, error) {
			return warm, nil
		}, releaseWarmCampaignOperation,
	)
	if err != nil {
		return performanceWorkload{}, err
	}
	return performanceWorkload{
		Class:          workload.Class,
		WorkloadID:     workload.ID,
		WorkloadSHA256: workloadDigest(workload),
		Cold:           cold,
		Warm:           warmProfile,
	}, nil
}

func (campaign performanceCampaign) measureProfile(
	ctx context.Context,
	workload performanceWorkloadCase,
	mode string,
	count int,
	nextOperation func() (campaignOperation, error),
	release func(campaignOperation, string) error,
) (performanceProfile, error) {
	profile := performanceProfile{Mode: mode, Samples: make([]performanceSample, 0, count)}
	for index := range count {
		if err := ctx.Err(); err != nil {
			return performanceProfile{}, err
		}
		operation, err := nextOperation()
		if err != nil {
			return performanceProfile{}, fmt.Errorf(
				"create %s operation: %w", mode, errors.Join(err, cleanCampaignOperation(operation)),
			)
		}
		if err := ctx.Err(); err != nil {
			return performanceProfile{}, errors.Join(err, release(operation, ""))
		}
		sample, err := campaign.execute(ctx, operation, workload)
		if err != nil {
			return performanceProfile{}, fmt.Errorf(
				"measure %s/%s %d: %w", workload.ID, mode, index+1,
				errors.Join(err, release(operation, "")),
			)
		}
		sample.Sequence = uint64(index + 1)
		sample.EnvironmentID = campaign.environment.Identity
		if !validSample(sample, sample.Sequence, campaign.environment.Identity) {
			return performanceProfile{}, fmt.Errorf(
				"measure %s/%s %d: %w: sample=%+v",
				workload.ID, mode, index+1,
				errors.Join(errPerformanceReport, release(operation, "")), sample,
			)
		}
		if err := release(operation, sample.AttemptID); err != nil {
			return performanceProfile{}, fmt.Errorf(
				"measure %s/%s %d: %w", workload.ID, mode, index+1, err,
			)
		}
		if err := ctx.Err(); err != nil {
			return performanceProfile{}, err
		}
		profile.Samples = append(profile.Samples, sample)
	}
	statistics, err := calculateStatistics(profile.Samples)
	if err != nil {
		return performanceProfile{}, err
	}
	profile.Statistics = statistics
	return profile, nil
}

func cleanCampaignOperation(operation campaignOperation) error {
	if operation.cleanup == nil {
		return nil
	}
	return operation.cleanup()
}

func releaseColdCampaignOperation(operation campaignOperation, attemptID string) error {
	if attemptID == "" {
		return cleanCampaignOperation(operation)
	}
	return errors.Join(
		discardCampaignAttempt(operation.evidenceRoot, attemptID),
		cleanCampaignOperation(operation),
	)
}

func releaseWarmCampaignOperation(operation campaignOperation, attemptID string) error {
	if attemptID == "" {
		return nil
	}
	return discardCampaignAttempt(operation.evidenceRoot, attemptID)
}

func campaignOperationSample(
	ctx context.Context,
	candidate campaignOperation,
	workload performanceWorkloadCase,
) (performanceSample, error) {
	if candidate.operation == nil || candidate.evidenceRoot == "" ||
		!validPerformanceHash(candidate.workerSHA256) {
		return performanceSample{}, errPerformanceReport
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	result, timings := candidate.operation.executeMeasured(ctx, workload.Input, urlreference.Mode(workload.Mode))
	runtime.ReadMemStats(&after)
	if err := verifiedCampaignResult(candidate, result, timings, workload.Expected); err != nil {
		return performanceSample{}, err
	}
	evidenceBytes, err := campaignEvidenceBytes(candidate.evidenceRoot, result.AttemptID)
	if err != nil {
		return performanceSample{}, err
	}
	workerImage, err := campaignWorkerBytes(candidate.workerPath)
	if err != nil {
		return performanceSample{}, err
	}
	return performanceSample{
		AttemptID:       result.AttemptID,
		Outcome:         string(result.Status),
		CleanupComplete: result.Process.CleanupComplete,
		Phases:          campaignPhases(timings),
		Resources: resourceMeasurement{
			Measured:                timings.Resources.Measured && timings.Resources.Err == nil,
			WorkerCPUTimeNS:         durationNanoseconds(timings.Resources.CPUTime),
			PeakWorkingSetBytes:     timings.Resources.PeakWorkingSet,
			PeakProcessCommitBytes:  timings.Resources.PeakProcessCommit,
			PeakJobCommitBytes:      timings.Resources.PeakJobCommit,
			JobReadOperations:       timings.Resources.ReadOperations,
			JobWriteOperations:      timings.Resources.WriteOperations,
			JobOtherOperations:      timings.Resources.OtherOperations,
			JobReadBytes:            timings.Resources.ReadBytes,
			JobWriteBytes:           timings.Resources.WriteBytes,
			JobOtherBytes:           timings.Resources.OtherBytes,
			GoRuntimeAllocatedBytes: allocationDelta(before.TotalAlloc, after.TotalAlloc),
			EvidenceBytes:           evidenceBytes,
			WorkerImageBytes:        workerImage,
		},
	}, nil
}

func verifiedCampaignResult(
	candidate campaignOperation,
	result Result,
	timings operationTimings,
	expected string,
) error {
	if !validCampaignResult(result, timings, expected) {
		return errPerformanceReport
	}
	return validCampaignEvidence(candidate, result.AttemptID, expected)
}

func validCampaignResult(result Result, timings operationTimings, expected string) bool {
	return result.Err == nil && result.Status == Verified && result.AttemptID != "" && result.Response != nil &&
		result.Response.Output != nil && *result.Response.Output == expected &&
		result.Process.CleanupComplete && timings.measured == allMeasuredPhases &&
		timings.Resources.Measured && timings.Resources.Err == nil
}

func validCampaignEvidence(candidate campaignOperation, attemptID, expected string) error {
	records, err := candidate.operation.store.Inspect(attemptID)
	if err != nil || records.Observation == nil || records.Observation.TerminalStatus != string(Verified) ||
		!records.Observation.CleanupComplete || records.Observation.ExpectedOutput != expected ||
		!records.Observation.VerificationPass || records.Observation.VerificationID != attemptstore.URLVerifierID ||
		records.Observation.VerificationVer != attemptstore.URLVerifierVersion ||
		records.Observation.WorkerSHA256 != candidate.workerSHA256 {
		return errPerformanceReport
	}
	return nil
}

func campaignPhases(timings operationTimings) []phaseMeasurement {
	values := [...]time.Duration{
		timings.Request,
		timings.Admission,
		timings.Staging,
		timings.Preparation,
		timings.ProcessStart,
		timings.Input,
		timings.Worker,
		timings.Output,
		timings.Diagnostics,
		timings.Lifecycle,
		timings.Protocol,
		timings.Verification,
		timings.Observation,
		timings.Publication,
		timings.Receipt,
		timings.Total,
	}
	phases := make([]phaseMeasurement, len(performancePhases))
	for index, id := range performancePhases {
		phases[index] = phaseMeasurement{ID: id, DurationNS: durationNanoseconds(values[index])}
	}
	return phases
}

type evidenceMeter struct {
	root     string
	attempts string
	bytes    uint64
	paths    []string
}

func campaignEvidenceBytes(root, attemptID string) (uint64, error) {
	meter, err := measureCampaignEvidence(root, attemptID)
	if err != nil {
		return 0, err
	}
	return meter.bytes, nil
}

func discardCampaignAttempt(root, attemptID string) error {
	if !validPerformanceIdentity(attemptID) {
		return errPerformanceReport
	}
	meter, err := measureCampaignEvidence(root, attemptID)
	if err != nil {
		return err
	}
	for _, path := range meter.paths {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove measured campaign record: %w", err)
		}
	}
	if err := os.Remove(meter.root); err != nil {
		return fmt.Errorf("remove measured campaign attempt: %w", err)
	}
	return nil
}

func measureCampaignEvidence(root, attemptID string) (evidenceMeter, error) {
	if !validPerformanceIdentity(attemptID) {
		return evidenceMeter{}, errPerformanceReport
	}
	meter := evidenceMeter{
		root:     filepath.Join(root, "attempts", attemptID),
		attempts: filepath.Join(root, "attempts"),
	}
	err := filepath.WalkDir(meter.attempts, meter.visit)
	if err != nil || len(meter.paths) != maximumCampaignEvidenceFiles || meter.bytes == 0 {
		return evidenceMeter{}, errPerformanceReport
	}
	return meter, nil
}

func (meter *evidenceMeter) visit(path string, entry os.DirEntry, err error) error {
	if err != nil || entry.Type()&os.ModeSymlink != 0 {
		return errPerformanceReport
	}
	pending := filepath.Join(meter.attempts, ".pending")
	if path == meter.attempts || path == pending || path == meter.root {
		if !entry.IsDir() {
			return errPerformanceReport
		}
		return nil
	}
	if entry.IsDir() || filepath.Dir(path) != meter.root {
		return errPerformanceReport
	}
	return meter.addFile(path, entry)
}

func (meter *evidenceMeter) addFile(path string, entry os.DirEntry) error {
	if len(meter.paths) == maximumCampaignEvidenceFiles {
		return errPerformanceReport
	}
	info, err := entry.Info()
	if err != nil || !info.Mode().IsRegular() {
		return errPerformanceReport
	}
	size, err := nonNegativeUint64(info.Size())
	if err != nil || size > maxPerformanceEvidenceBytes-meter.bytes {
		return errPerformanceReport
	}
	meter.bytes += size
	meter.paths = append(meter.paths, path)
	return nil
}

func campaignWorkerBytes(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return 0, errPerformanceReport
	}
	return nonNegativeUint64(info.Size())
}

func allocationDelta(before, after uint64) uint64 {
	if after < before {
		return 0
	}
	return after - before
}

func durationNanoseconds(duration time.Duration) uint64 {
	value, err := nonNegativeUint64(int64(duration))
	if err != nil {
		return 0
	}
	return value
}

func nonNegativeUint64(value int64) (uint64, error) {
	if value < 0 {
		return 0, errPerformanceReport
	}
	return uint64(value), nil
}

func operationPerformanceEnvironment(worker string) (performanceEnvironment, error) {
	workerHash, err := fileDigest(worker)
	if err != nil {
		return performanceEnvironment{}, err
	}
	commit, err := performanceCommit()
	if err != nil {
		return performanceEnvironment{}, err
	}
	rust, err := performanceRustVersion()
	if err != nil {
		return performanceEnvironment{}, err
	}
	hardware := strings.TrimSpace(os.Getenv("PROCESSOR_IDENTIFIER"))
	if hardware == "" {
		hardware = fmt.Sprintf("logical-cpus-%d", runtime.NumCPU())
	}
	environment := performanceEnvironment{
		Platform:      runtime.GOOS + "/" + runtime.GOARCH,
		Hardware:      hardware,
		Toolchains:    []string{runtime.Version(), rust},
		CacheState:    "cold-fresh-operation-warm-reused-operation",
		Concurrency:   1,
		WorkerSHA256:  workerHash,
		ProductCommit: commit,
	}
	sort.Strings(environment.Toolchains)
	environment.Identity = performanceEnvironmentIdentity(environment)
	if !validEnvironment(environment) {
		return performanceEnvironment{}, errPerformanceReport
	}
	return environment, nil
}

func fileDigest(path string) (string, error) {
	root, name, err := rootedPath(path)
	if err != nil {
		return "", err
	}
	file, err := root.Open(name)
	if err != nil {
		closeErr := root.Close()
		return "", errors.Join(err, closeErr)
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, file)
	return hex.EncodeToString(digest.Sum(nil)), errors.Join(copyErr, file.Close(), root.Close())
}

func performanceCommit() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	root, err := repositoryRoot()
	if err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	command.Dir = root
	output, err := command.Output()
	commit := strings.TrimSpace(string(output))
	if err != nil || !validCommit(commit) {
		return "", errPerformanceReport
	}
	return commit, nil
}

func requireCleanPerformanceCheckout(root string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "status", "--porcelain=v1", "--untracked-files=all")
	command.Dir = root
	output, err := command.Output()
	if err != nil || len(bytes.TrimSpace(output)) != 0 {
		return errPerformanceReport
	}
	return nil
}

func performanceRustVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "rustc", "--version").Output()
	fields := strings.Fields(string(output))
	if err != nil || len(fields) < 2 {
		return "", errPerformanceReport
	}
	version := fields[0] + "-" + fields[1]
	if !identifierPerformance.MatchString(version) {
		return "", errPerformanceReport
	}
	return version, nil
}

func testCampaignEnvironment() performanceEnvironment {
	environment := performanceEnvironment{
		Platform:      "windows/amd64",
		Hardware:      "test-host",
		Toolchains:    []string{"go1.26.5", "rustc-1.95.0"},
		CacheState:    "declared",
		Concurrency:   1,
		WorkerSHA256:  strings.Repeat("c", 64),
		ProductCommit: strings.Repeat("d", 40),
	}
	environment.Identity = performanceEnvironmentIdentity(environment)
	return environment
}
