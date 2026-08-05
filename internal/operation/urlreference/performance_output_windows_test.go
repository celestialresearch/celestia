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
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPerformanceCampaignWritesOnlyCompleteReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	corpus, corpusSHA256 := testPerformanceCorpus(t)
	report := testPerformanceReport(t, corpus, corpusSHA256)
	if err := writePerformanceReport(path, report, corpus, corpusSHA256); err != nil {
		t.Fatalf("write report: %v", err)
	}
	data, err := readRootedPerformanceReport(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if _, err := decodePerformanceReport(strings.NewReader(string(data)), corpus, corpusSHA256); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if err := writePerformanceReport(path, report, corpus, corpusSHA256); err == nil {
		t.Fatal("existing report was replaced")
	}
	if err := writePerformanceReport(filepath.Join(t.TempDir(), "invalid.json"), performanceReport{}, corpus, corpusSHA256); err == nil {
		t.Fatal("invalid report was published")
	}
}

func TestPerformanceCampaignRejectsUnavailableOutputBeforeExecution(t *testing.T) {
	repository := t.TempDir()
	path := filepath.Join(repository, "reports", "missing", "report.json")
	if _, _, err := openPerformanceOutputIn(repository, path); !errors.Is(err, errPerformanceReport) {
		t.Fatal("missing output directory was accepted")
	}
}

func TestPerformanceCampaignRefusesExternalOutputBeforeExecution(t *testing.T) {
	repository := t.TempDir()
	external := filepath.Join(t.TempDir(), "report.json")
	if _, _, err := openPerformanceOutputIn(repository, external); !errors.Is(err, errPerformanceReport) {
		t.Fatalf("external output error=%v", err)
	}
}

func TestPerformanceCampaignRetainsOpenedOutputAcrossReparseReplacement(t *testing.T) {
	repository := t.TempDir()
	directory := filepath.Join(repository, "reports", "candidate")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	output := filepath.Join(directory, "report.json")
	type openedOutput struct {
		root *os.Root
		name string
		err  error
	}
	opened := make(chan openedOutput, 1)
	replace := make(chan struct{})
	replaced := make(chan error, 1)
	go func() {
		root, name, err := openPerformanceOutputIn(repository, output)
		opened <- openedOutput{root: root, name: name, err: err}
		if err != nil {
			return
		}
		<-replace
		held := filepath.Join(repository, "reports", "held")
		if err := os.Rename(directory, held); err != nil {
			replaced <- err
			return
		}
		replaced <- os.Symlink(external, directory)
	}()
	value := <-opened
	if value.err != nil {
		t.Fatalf("open output: %v", value.err)
	}
	t.Cleanup(func() {
		if err := value.root.Close(); err != nil {
			t.Error(err)
		}
	})
	close(replace)
	if err := <-replaced; err != nil {
		t.Fatalf("replace output ancestry: %v", err)
	}
	if _, _, err := openPerformanceOutputIn(repository, output); !errors.Is(err, errPerformanceReport) {
		t.Fatalf("replacement output root error=%v", err)
	}
	corpus, corpusSHA256 := testPerformanceCorpus(t)
	if err := writeOpenedPerformanceReport(value.root, value.name, testPerformanceReport(t, corpus, corpusSHA256), corpus, corpusSHA256); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(external, value.name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement target received output: %v", err)
	}
	data, err := value.root.ReadFile(value.name)
	if err != nil || len(data) == 0 {
		t.Fatalf("retained report bytes=%d error=%v", len(data), err)
	}
}

func TestPerformanceCampaignDoesNotReplaceRacedReport(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	corpus, corpusSHA256 := testPerformanceCorpus(t)
	data := marshalPerformanceReport(t, testPerformanceReport(t, corpus, corpusSHA256))
	err = writeRootedPerformanceReportWith(root, "report.json", data, func(_, name string) error {
		if err := root.WriteFile(name, []byte("existing"), 0o600); err != nil {
			return err
		}
		return os.ErrExist
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("write error=%v", err)
	}
	retained, err := root.ReadFile("report.json")
	if err != nil || string(retained) != "existing" {
		t.Fatalf("retained=%q error=%v", retained, err)
	}
}

func writePerformanceReport(
	path string,
	report performanceReport,
	corpus performanceCorpus,
	corpusSHA256 string,
) error {
	root, name, err := rootedPath(path)
	if err != nil {
		return err
	}
	writeErr := writeOpenedPerformanceReport(root, name, report, corpus, corpusSHA256)
	return errors.Join(writeErr, root.Close())
}

func openPerformanceOutput(path string) (*os.Root, string, error) {
	repositoryPath, err := repositoryRoot()
	if err != nil {
		return nil, "", err
	}
	return openPerformanceOutputIn(repositoryPath, path)
}

func openPerformanceOutputIn(repositoryPath, path string) (*os.Root, string, error) {
	relative, err := performanceOutputRelative(repositoryPath, path)
	if err != nil {
		return nil, "", err
	}
	repository, err := os.OpenRoot(repositoryPath)
	if err != nil {
		return nil, "", errors.Join(errPerformanceReport, err)
	}
	root, openErr := repository.OpenRoot(filepath.Dir(relative))
	closeErr := repository.Close()
	if openErr != nil || closeErr != nil {
		if root != nil {
			closeErr = errors.Join(closeErr, root.Close())
		}
		return nil, "", errors.Join(errPerformanceReport, openErr, closeErr)
	}
	name := filepath.Base(relative)
	if err := validateOpenedPerformanceOutput(root, name); err != nil {
		return nil, "", errors.Join(err, root.Close())
	}
	return root, name, nil
}

func performanceOutputRelative(root, path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path || filepath.Base(clean) == "." {
		return "", errPerformanceReport
	}
	relative, err := filepath.Rel(root, clean)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return "", errPerformanceReport
	}
	parts := strings.Split(relative, string(filepath.Separator))
	if len(parts) < 2 || parts[0] != "reports" {
		return "", errPerformanceReport
	}
	return relative, nil
}

func validateOpenedPerformanceOutput(root *os.Root, name string) error {
	if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errPerformanceReport
	}
	if _, err := root.Lstat(name + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		return errPerformanceReport
	}
	return nil
}

func writeRootedPerformanceReport(root *os.Root, name string, data []byte) error {
	return writeRootedPerformanceReportWith(root, name, data, root.Link)
}

func writeOpenedPerformanceReport(
	root *os.Root,
	name string,
	report performanceReport,
	corpus performanceCorpus,
	corpusSHA256 string,
) error {
	if !validPerformanceReport(report, corpus, corpusSHA256) {
		return errPerformanceReport
	}
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if _, err := decodePerformanceReport(strings.NewReader(string(data)), corpus, corpusSHA256); err != nil {
		return err
	}
	return writeRootedPerformanceReport(root, name, data)
}

func writeRootedPerformanceReportWith(
	root *os.Root,
	name string,
	data []byte,
	link func(string, string) error,
) (err error) {
	if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errPerformanceReport
	}
	temporary := name + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	created := true
	defer func() {
		if created {
			err = errors.Join(err, root.Remove(temporary))
		}
	}()
	if err := writeAndClosePerformanceReport(file, data); err != nil {
		return err
	}
	if err := link(temporary, name); err != nil {
		return err
	}
	created = false
	return root.Remove(temporary)
}

func writeAndClosePerformanceReport(file *os.File, data []byte) error {
	if _, err := file.Write(data); err != nil {
		return errors.Join(err, file.Close())
	}
	return errors.Join(file.Sync(), file.Close())
}

func readRootedPerformanceReport(path string) ([]byte, error) {
	root, name, err := rootedPath(path)
	if err != nil {
		return nil, err
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxPerformanceReportBytes+1))
	return data, errors.Join(readErr, file.Close(), root.Close())
}

func rootedPath(path string) (*os.Root, string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path || filepath.Base(clean) == "." {
		return nil, "", errPerformanceReport
	}
	directory := filepath.Dir(clean)
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, "", err
	}
	return root, filepath.Base(clean), nil
}
