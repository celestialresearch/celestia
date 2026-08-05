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

	"golang.org/x/sys/windows"
)

func TestPerformanceCampaignWritesOnlyCompleteReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	report := testPerformanceReport(t)
	if err := writePerformanceReport(path, report); err != nil {
		t.Fatalf("write report: %v", err)
	}
	data, err := readRootedPerformanceReport(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if _, err := decodePerformanceReport(strings.NewReader(string(data))); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if err := writePerformanceReport(path, report); err == nil {
		t.Fatal("existing report was replaced")
	}
	if err := writePerformanceReport(filepath.Join(t.TempDir(), "invalid.json"), performanceReport{}); err == nil {
		t.Fatal("invalid report was published")
	}
}

func TestPerformanceCampaignRejectsUnavailableOutputBeforeExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "report.json")
	if err := validatePerformanceOutput(path); err == nil {
		t.Fatal("missing output directory was accepted")
	}
}

func TestPerformanceCampaignRequiresIgnoredOutput(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := ignoredPerformanceOutput(filepath.Join(root, "reports", "performance.json")); err != nil {
		t.Fatalf("ignored output rejected: %v", err)
	}
	if err := ignoredPerformanceOutput(filepath.Join(t.TempDir(), "performance.json")); err == nil {
		t.Fatal("external output accepted")
	}
}

func TestPerformanceCampaignRefusesExternalOutputBeforeProbe(t *testing.T) {
	probed := false
	err := validateCampaignOutput(
		filepath.Join(t.TempDir(), "performance.json"),
		ignoredPerformanceOutput,
		func(string) error {
			probed = true
			return nil
		},
	)
	if !errors.Is(err, errPerformanceReport) {
		t.Fatalf("external output error=%v", err)
	}
	if probed {
		t.Fatal("external output was probed")
	}
}

func TestPerformanceCampaignRejectsReparseOutputAncestry(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "reports", "candidate", "report.json")
	attributes := func(candidate string) (uint32, error) {
		if candidate == filepath.Join(root, "reports") {
			return windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT, nil
		}
		return windows.FILE_ATTRIBUTE_DIRECTORY, nil
	}
	if err := validatePerformanceOutputAncestry(root, path, attributes); !errors.Is(err, errPerformanceReport) {
		t.Fatalf("reparse ancestry error=%v", err)
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
	data := marshalPerformanceReport(t, testPerformanceReport(t))
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

func writePerformanceReport(path string, report performanceReport) error {
	if !validPerformanceReport(report) {
		return errPerformanceReport
	}
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if _, err := decodePerformanceReport(strings.NewReader(string(data))); err != nil {
		return err
	}
	root, name, err := rootedPath(path)
	if err != nil {
		return err
	}
	writeErr := writeRootedPerformanceReport(root, name, data)
	return errors.Join(writeErr, root.Close())
}

func validatePerformanceOutput(path string) (err error) {
	root, name, err := rootedPath(path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errPerformanceReport
	}
	if _, err := root.Lstat(name + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		return errPerformanceReport
	}
	return nil
}

func ignoredPerformanceOutput(path string) error {
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return errPerformanceReport
	}
	parts := strings.Split(relative, string(filepath.Separator))
	if len(parts) < 2 || parts[0] != "reports" {
		return errPerformanceReport
	}
	return validatePerformanceOutputAncestry(root, path, performanceFileAttributes)
}

func validatePerformanceOutputAncestry(
	root, output string,
	attributes func(string) (uint32, error),
) error {
	relative, err := filepath.Rel(root, filepath.Dir(output))
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errPerformanceReport
	}
	current := root
	for component := range strings.SplitSeq(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		value, err := attributes(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || value&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
			value&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errPerformanceReport
		}
	}
	return nil
}

func performanceFileAttributes(path string) (uint32, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return windows.GetFileAttributes(pointer)
}

func writeRootedPerformanceReport(root *os.Root, name string, data []byte) error {
	return writeRootedPerformanceReportWith(root, name, data, root.Link)
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
