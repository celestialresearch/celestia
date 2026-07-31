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

package main

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	root := t.TempDir()
	rustSkipPath := filepath.Join(root, "skipped.rs")
	rustPath := filepath.Join(root, "suppressed.rs")
	missingRustPath := filepath.Join(root, "missing.rs")
	if err := os.WriteFile(
		rustSkipPath, []byte("#[ignore]\nfn skipped() {}"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		rustPath, []byte("#![allow(clippy::all)]"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		args      []string
		inventory func() ([]string, error)
		code      int
		output    string
	}{
		{
			"usage",
			nil,
			func() ([]string, error) { return nil, nil },
			2,
			"usage:",
		},
		{
			"inventory failure",
			[]string{modeTestSkips},
			func() ([]string, error) { return nil, errors.New("inventory failed") },
			1,
			"inventory failed",
		},
		{
			"Rust skip",
			[]string{modeTestSkips},
			func() ([]string, error) { return []string{rustSkipPath}, nil },
			1,
			"Rust tests must not ignore",
		},
		{
			"Rust suppression",
			[]string{modeSuppressions},
			func() ([]string, error) { return []string{rustPath}, nil },
			1,
			"invalid Clippy suppression",
		},
		{
			"missing Rust source",
			[]string{modeTestSkips},
			func() ([]string, error) { return []string{missingRustPath}, nil },
			1,
			"missing.rs",
		},
		{
			"irrelevant file",
			[]string{modeSuppressions},
			func() ([]string, error) { return []string{"README.md"}, nil },
			0,
			"",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			code := run(test.args, &stderr, test.inventory, os.ReadFile)
			if code != test.code {
				t.Fatalf("code = %d, want %d", code, test.code)
			}
			if !strings.Contains(stderr.String(), test.output) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.output)
			}
		})
	}
}

func TestOrdinaryTestMainIsNotCandidate(t *testing.T) {
	t.Parallel()
	candidate, err := hasGoPolicySelector(
		"fixture.go",
		[]byte("package fixture\nfunc TestMain() {}\n"),
	)
	if err != nil || candidate {
		t.Fatalf("ordinary TestMain candidate = %t, error = %v", candidate, err)
	}
}

func TestRunRejectsCargoSuppression(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Cargo.toml")
	if err := os.WriteFile(
		path,
		[]byte("[lints.clippy]\nall = \"allow\"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	code := run(
		[]string{modeSuppressions},
		&stderr,
		func() ([]string, error) { return []string{path}, nil },
		os.ReadFile,
	)
	if code != 1 ||
		!strings.Contains(stderr.String(), "Cargo lint allowances are prohibited") {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunRejectsGolangciExclusions(t *testing.T) {
	t.Parallel()
	for _, owner := range []string{"linters", "formatters"} {
		t.Run(owner, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), ".golangci.yml")
			source := []byte(
				"version: \"2\"\n" + owner +
					":\n  exclusions:\n    paths:\n      - internal\n",
			)
			if err := os.WriteFile(path, source, 0o600); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			code := run(
				[]string{modeSuppressions},
				&stderr,
				func() ([]string, error) { return []string{path}, nil },
				os.ReadFile,
			)
			if code != 1 ||
				!strings.Contains(stderr.String(), "exclusions are prohibited") {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
		})
	}
}

func TestRunRejectsAlternateGolangciConfigs(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		".golangci.yaml",
		".golangci.toml",
		".golangci.json",
		".GOLANGCI.YML",
		".GoLaNgCi.YaMl",
		".GolangCI.TOML",
		".golangCI.JSON",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			code := run(
				[]string{modeSuppressions},
				&stderr,
				func() ([]string, error) { return []string{path}, nil },
				os.ReadFile,
			)
			if code != 1 ||
				!strings.Contains(
					stderr.String(),
					"alternate golangci-lint configurations are prohibited",
				) {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
		})
	}
}

func TestGoSuppressionFindings(t *testing.T) {
	source := []byte(strings.Join([]string{
		"// #no" + "sec",
		"// #no" + "sec G304 -- bounded repository source",
		"//no" + "lint",
		"//no" + "lint:errcheck -- checked by the owner",
		"//no" + "lint:all -- broad suppression",
		"// gosec:disable",
		"//gosec:enable",
	}, "\n"))
	findings := goSuppressionFindings("source.go", source)
	if len(findings) != 5 {
		t.Fatalf("findings = %v", findings)
	}
}

func TestShellSuppressionFindings(t *testing.T) {
	source := []byte(strings.Join([]string{
		"#shellcheck disable=SC2086",
		"# shellcheck disable=SC2329 # Invoked by a registered trap",
	}, "\n"))
	findings := shellSuppressionFindings("source.sh", source)
	if len(findings) != 1 {
		t.Fatalf("findings = %v", findings)
	}
}

func TestReadSourceBoundsRepository(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(parent, "outside.rs"), []byte("outside"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, "source.rs"), []byte("inside"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Repeat([]byte{'x'}, maxSourceBytes+1)
	if err := os.WriteFile(
		filepath.Join(root, "oversized.rs"), oversized, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	source, err := readSource("source.rs")
	if err != nil || string(source) != "inside" {
		t.Fatalf("readSource(source.rs) = %q, %v", source, err)
	}
	for _, path := range []string{
		"../outside.rs",
		".",
		"oversized.rs",
	} {
		if _, err := readSource(path); err == nil {
			t.Fatalf("readSource(%q) succeeded", path)
		}
	}
}

func TestSourceFiles(t *testing.T) {
	t.Parallel()
	files, err := readInventory(strings.NewReader("first.go\x00second.rs\x00"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(files, []string{"first.go", "second.rs"}) {
		t.Fatalf("files = %v", files)
	}
	tests := []struct {
		name   string
		source io.Reader
	}{
		{"unterminated", strings.NewReader("first.go")},
		{"empty", strings.NewReader("\x00")},
		{
			"long path",
			strings.NewReader("aaaaaaaaa\x00"),
		},
		{
			"too many paths",
			strings.NewReader("a\x00b\x00"),
		},
		{
			"too many bytes",
			strings.NewReader("aa\x00bb\x00"),
		},
		{"read failure", failingReader{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			maxBytes, maxPaths, maxPathBytes := 64, 8, 8
			switch test.name {
			case "too many paths":
				maxPaths = 1
			case "too many bytes":
				maxBytes = 5
			}
			if _, err := readInventoryWithLimits(
				test.source, maxBytes, maxPaths, maxPathBytes,
			); err == nil {
				t.Fatal("readInventory accepted invalid input")
			}
		})
	}
}

func TestSourceFilesCommand(t *testing.T) {
	t.Parallel()
	files, err := inventorySourceFiles(
		&fakeInventoryCommand{output: strings.NewReader("main.go\x00")},
		func() {},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(files, "main.go") {
		t.Fatalf("source inventory does not contain sourcepolicy: %v", files)
	}
	tests := []struct {
		name    string
		command *fakeInventoryCommand
	}{
		{"pipe failure", &fakeInventoryCommand{pipeErr: errors.New("pipe failed")}},
		{"start failure", &fakeInventoryCommand{startErr: errors.New("start failed")}},
		{
			"read failure",
			&fakeInventoryCommand{output: failingReader{}},
		},
		{
			"wait failure",
			&fakeInventoryCommand{
				output:  strings.NewReader("main.go\x00"),
				waitErr: errors.New("wait failed"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := inventorySourceFiles(test.command, func() {})
			if err == nil {
				t.Fatal("inventorySourceFiles accepted a command failure")
			}
		})
	}
}

type fakeInventoryCommand struct {
	output   io.Reader
	pipeErr  error
	startErr error
	waitErr  error
}

func (command *fakeInventoryCommand) Start() error {
	return command.startErr
}

func (command *fakeInventoryCommand) StdoutPipe() (io.ReadCloser, error) {
	if command.pipeErr != nil {
		return nil, command.pipeErr
	}
	return io.NopCloser(command.output), nil
}

func (command *fakeInventoryCommand) Wait() error {
	return command.waitErr
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func TestGoSkipMethods(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		call     string
		findings int
	}{
		{"receiver", `t.Skip("unverified")`, 1},
		{"formatted receiver", `t.Skipf("%s", "unverified")`, 1},
		{"renamed receiver", `testCase.SkipNow()`, 1},
		{"method expression", `(*testing.T).Skip(t, "unverified")`, 1},
		{
			"custom method",
			`cursor{}.Skip(1)`,
			0,
		},
		{
			"custom function field",
			`fields{}.Skip("ordinary")`,
			0,
		},
		{"ordinary test", `t.Log("verified")`, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "fixture_test.go")
			parameter := "t"
			if test.name == "renamed receiver" {
				parameter = "testCase"
			}
			source := "package fixture\n\nimport \"testing\"\n\n" +
				"type cursor struct{}\n" +
				"func (cursor) Skip(int) {}\n\n" +
				"type fields struct { Skip func(...any) }\n\n" +
				"type cursorContract interface {\n" +
				"\tSkip(int)\n" +
				"\tSkipf(int, ...any)\n" +
				"\tSkipNow() int\n" +
				"}\n" +
				"func useCursor(value cursorContract) {\n" +
				"\tvalue.Skip(1)\n" +
				"\tvalue.Skipf(1)\n" +
				"\t_ = value.SkipNow()\n" +
				"}\n\n" +
				"func TestFixture(" + parameter + " *testing.T) {\n" +
				test.call + "\n}\n"
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			findings := goSkipFindings(path, []byte(source))
			if len(findings) != test.findings {
				t.Fatalf("findings = %v, want %d", findings, test.findings)
			}
		})
	}
}

func TestGoSkipAcrossFiles(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "helper.go")
	caller := filepath.Join(root, "caller_test.go")
	linux := filepath.Join(root, "platform_linux.go")
	windows := filepath.Join(root, "platform_windows.go")
	sources := map[string][]byte{
		helper: []byte(
			"package fixture\n\nimport \"testing\"\n\n" +
				"func testContext(t *testing.T) *testing.T { return t }\n" +
				"type skipper interface {\n" +
				"\tSkip(...any)\n" +
				"\tSkipf(string, ...any)\n" +
				"\tSkipNow()\n" +
				"}\n" +
				"func hideSkip(value skipper) {\n" +
				"\tvalue.Skip(\"disabled\")\n" +
				"\tvalue.Skipf(\"%s\", \"disabled\")\n" +
				"\tvalue.SkipNow()\n" +
				"}\n",
		),
		caller: []byte(
			"package fixture\n\nimport \"testing\"\n\n" +
				"func TestFixture(t *testing.T) {\n" +
				"\ttestContext(t).Skip(\"disabled\")\n" +
				"\thideSkip(t)\n}\n",
		),
		linux: []byte(
			"//go:build linux\n\npackage fixture\n\nconst platform = \"linux\"\n",
		),
		windows: []byte(
			"//go:build windows\n\npackage fixture\n\nconst platform = \"windows\"\n",
		),
	}
	for path, source := range sources {
		if err := os.WriteFile(path, source, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(root, "go.mod"),
		[]byte("module fixture.invalid/sourcepolicy\n\ngo 1.26.5\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{
			filepath.Base(helper),
			filepath.Base(caller),
			filepath.Base(linux),
			filepath.Base(windows),
		},
		os.ReadFile,
		[]buildTarget{
			{goos: "linux", goarch: "amd64"},
			{goos: "windows", goarch: "amd64"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("findings = %v, want four", findings)
	}
}

func TestGoCGOSkip(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "cgo_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		path: "//go:build cgo\n\npackage fixture\n\n" +
			"import \"testing\"\n\n" +
			"func TestFixture(t *testing.T) { t.Skip(\"disabled\") }\n",
	})
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{filepath.Base(path)},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH, cgo: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 ||
		!strings.Contains(findings[0], "Go tests must not skip cases") {
		t.Fatalf("findings = %v, want one CGO skip", findings)
	}
}

func TestPolicyTargetsCoverCGOModes(t *testing.T) {
	targets := policyTargets()
	expected := len(policyBuildTargets)*2 + len(policyRaceTargets)
	if len(targets) != expected {
		t.Fatalf("targets = %d, want %d", len(targets), expected)
	}
	for _, policyTarget := range policyBuildTargets {
		for _, cgo := range []bool{false, true} {
			found := slices.ContainsFunc(targets, func(target buildTarget) bool {
				return target.goos == policyTarget.goos &&
					target.goarch == policyTarget.goarch &&
					target.cgo == cgo
			})
			if !found {
				t.Fatalf(
					"missing target %s/%s with CGO=%t",
					policyTarget.goos,
					policyTarget.goarch,
					cgo,
				)
			}
		}
		key := policyTarget.goos + "/" + policyTarget.goarch
		foundRace := slices.ContainsFunc(targets, func(target buildTarget) bool {
			return target.goos == policyTarget.goos &&
				target.goarch == policyTarget.goarch &&
				target.cgo && target.race
		})
		if foundRace != policyRaceTargets[key] {
			t.Fatalf("race target %s = %t, want %t", key, foundRace, policyRaceTargets[key])
		}
	}
}

func TestGoSuccessfulExit(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		message string
	}{
		{
			"qualified",
			"import (\"os\"; \"testing\")\n" +
				"func init() { os.Exit(0) }\n" +
				"func fail() { os.Exit(2) }\n",
			"Go tests must not exit successfully",
		},
		{
			"dot imported",
			"import (. \"os\"; \"testing\")\n" +
				"func init() { Exit(0) }\n",
			"Go tests must not exit successfully",
		},
		{
			"syscall",
			"import (\"syscall\"; \"testing\")\n" +
				"func init() { syscall.Exit(0) }\n",
			"Go tests must not exit successfully",
		},
		{
			"aliased function",
			"import (\"os\"; \"testing\")\n" +
				"var exit = os.Exit\n" +
				"func init() { exit(0) }\n",
			"Go tests must not alias process exit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "exit_test.go")
			writeGoPolicyFixture(t, root, map[string]string{
				path: "package fixture\n\n" + test.source +
					"func TestFailure(t *testing.T) { t.Fatal(\"must run\") }\n",
			})
			t.Chdir(root)
			findings, err := goPackageSkipFindingsWithTargets(
				[]string{filepath.Base(path)},
				os.ReadFile,
				[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 ||
				!strings.Contains(findings[0], test.message) {
				t.Fatalf("findings = %v, want one %s", findings, test.message)
			}
		})
	}
}

func TestGoTestCannotInvokeMain(t *testing.T) {
	tests := []struct {
		name string
		main string
		test string
	}{
		{
			"direct",
			"func main() {}\n",
			"func TestEntry(t *testing.T) { main() }\n",
		},
		{
			"aliased",
			"func main() {}\n",
			"func TestEntry(t *testing.T) { entry := main; entry() }\n",
		},
		{
			"wrapped",
			"func main() {}\nfunc invokeMain() { main() }\n",
			"func TestEntry(t *testing.T) { invokeMain() }\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			mainPath := filepath.Join(root, "main.go")
			testPath := filepath.Join(root, "main_test.go")
			writeGoPolicyFixture(t, root, map[string]string{
				mainPath: "package main\n\n" + test.main,
				testPath: "package main\n\nimport \"testing\"\n\n" + test.test,
			})
			t.Chdir(root)
			findings, err := goPackageSkipFindingsWithTargets(
				[]string{filepath.Base(mainPath), filepath.Base(testPath)},
				os.ReadFile,
				[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) == 0 ||
				!strings.Contains(findings[0], "executable main") {
				t.Fatalf("findings = %v, want executable main finding", findings)
			}
		})
	}
}

func TestGoPolicyInspectsImportedHelpers(t *testing.T) {
	root := t.TempDir()
	helperDirectory := filepath.Join(root, "helper")
	if err := os.Mkdir(helperDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	helperPath := filepath.Join(helperDirectory, "helper.go")
	testPath := filepath.Join(root, "root_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		helperPath: "package helper\n\nimport \"testing\"\n\n" +
			"func Skip(t *testing.T) { t.Skip(\"hidden\") }\n",
		testPath: "package fixture\n\nimport (\n" +
			"\t\"testing\"\n" +
			"\t\"fixture.invalid/sourcepolicy/helper\"\n" +
			")\n\n" +
			"func TestEntry(t *testing.T) { helper.Skip(t) }\n",
	})
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{
			filepath.Base(testPath),
			filepath.Join("helper", filepath.Base(helperPath)),
		},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 ||
		!strings.Contains(findings[0], "Go tests must not skip cases") {
		t.Fatalf("findings = %v, want imported helper skip", findings)
	}
}

func TestGoPolicyInspectsNestedModules(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	testPath := filepath.Join(root, "root_test.go")
	helperPath := filepath.Join(nested, "helper.go")
	writeGoPolicyFixture(t, root, map[string]string{
		testPath: "package fixture\n\nimport (\n" +
			"\t\"testing\"\n\t\"fixture.invalid/nested\"\n)\n\n" +
			"func TestEntry(t *testing.T) { nested.Skip(t) }\n",
		helperPath: "package nested\n\nimport \"testing\"\n\n" +
			"func Skip(t *testing.T) { t.Skip(\"hidden\") }\n",
		filepath.Join(nested, "go.mod"): "module fixture.invalid/nested\n\ngo 1.26.5\n",
	})
	if err := os.WriteFile(
		filepath.Join(root, "go.mod"),
		[]byte("module fixture.invalid/sourcepolicy\n\ngo 1.26.5\n\n"+
			"require fixture.invalid/nested v0.0.0\n\n"+
			"replace fixture.invalid/nested => ./nested\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{"root_test.go", "nested/go.mod", "nested/helper.go"},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 ||
		!strings.Contains(findings[0], "Go tests must not skip cases") {
		t.Fatalf("findings = %v, want nested helper skip", findings)
	}
}

func TestGoPolicyPrevalidatesHelpers(t *testing.T) {
	failure := errors.New("invalid helper source")
	_, err := goPackageSkipFindingsWithTargets(
		[]string{"root_test.go", "helper/helper.go"},
		func(path string) ([]byte, error) {
			if path == "helper/helper.go" {
				return nil, failure
			}
			return []byte("package fixture\n"), nil
		},
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if !errors.Is(err, failure) {
		t.Fatalf("error = %v, want helper validation failure", err)
	}
}

func TestGoRaceSkip(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "race_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		path: "//go:build race\n\npackage fixture\n\nimport \"testing\"\n\n" +
			"func TestRace(t *testing.T) { t.Skip(\"hidden\") }\n",
	})
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{"race_test.go"},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH, cgo: true, race: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 ||
		!strings.Contains(findings[0], "Go tests must not skip cases") {
		t.Fatalf("findings = %v, want race skip", findings)
	}
}

func TestGoLinknameIsRejected(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "main_test.go")
	writeGoPolicyFixture(t, root, map[string]string{
		filepath.Join(root, "main.go"): "package main\n\nfunc main() {}\n",
		path: "package main\n\nimport (\n\t_ \"unsafe\"\n\t\"testing\"\n)\n\n" +
			"//go:linkname linkedMain main.main\n" +
			"func linkedMain()\n\n" +
			"func TestEntry(t *testing.T) { linkedMain() }\n",
	})
	t.Chdir(root)
	findings, err := goPackageSkipFindingsWithTargets(
		[]string{"main.go", "main_test.go"},
		os.ReadFile,
		[]buildTarget{{goos: runtime.GOOS, goarch: runtime.GOARCH}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 ||
		!strings.Contains(findings[0], "Go tests must not use go:linkname") {
		t.Fatalf("findings = %v, want go:linkname rejection", findings)
	}
}

func writeGoPolicyFixture(
	t *testing.T,
	root string,
	sources map[string]string,
) {
	t.Helper()
	for path, source := range sources {
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(root, "go.mod"),
		[]byte("module fixture.invalid/sourcepolicy\n\ngo 1.26.5\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func TestGoSkipCandidateFailures(t *testing.T) {
	t.Parallel()
	_, _, err := goCandidateDirectories(
		[]string{"broken_test.go"},
		func(string) ([]byte, error) {
			return []byte("package fixture\nfunc TestBroken("), nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "parse Go test") {
		t.Fatalf("parse error = %v", err)
	}

	readErr := errors.New("read failure")
	_, _, err = goCandidateDirectories(
		[]string{"unreadable_test.go"},
		func(string) ([]byte, error) { return nil, readErr },
	)
	if !errors.Is(err, readErr) {
		t.Fatalf("read error = %v, want %v", err, readErr)
	}
}

func TestGoBuildSelectionRejectsInvalidConstraint(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "invalid_test.go")
	if err := os.WriteFile(
		path,
		[]byte("//go:build linux &&\n\npackage fixture\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	_, err := goBuildSelection(
		[]string{path},
		map[string]bool{root: true},
		buildTarget{goos: "linux", goarch: "amd64"},
		map[string][]byte{
			path: []byte("//go:build linux &&\n\npackage fixture\n"),
		},
	)
	if err == nil || !strings.Contains(err.Error(), "match Go build constraints") {
		t.Fatalf("constraint error = %v", err)
	}
}

func TestGoBuildSelectionUsesOverlay(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "selected_test.go")
	if err := os.WriteFile(
		path,
		[]byte("//go:build windows\n\npackage fixture\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	patterns, err := goBuildSelection(
		[]string{path},
		map[string]bool{root: true},
		buildTarget{goos: "linux", goarch: "amd64"},
		map[string][]byte{
			path: []byte("//go:build linux\n\npackage fixture\n"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(patterns, []string{"file=" + filepath.ToSlash(path)}) {
		t.Fatalf("patterns = %v, want overlay-selected file", patterns)
	}
}

func TestValidTestMainSyntax(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		body  string
		valid bool
	}{
		{"exit run", "os.Exit(testingMain.Run())", true},
		{
			"setup then exit",
			"fmt.Println(\"setup\"); os.Exit(testingMain.Run())",
			true,
		},
		{
			"closure return",
			"func() { return }(); os.Exit(testingMain.Run())",
			true,
		},
		{
			"non-zero early exit",
			"os.Exit(2); os.Exit(testingMain.Run())",
			true,
		},
		{
			"custom exit field",
			"customExit.Exit(2); os.Exit(testingMain.Run())",
			true,
		},
		{"empty", "", false},
		{"return", "return", false},
		{
			"early return",
			"if true { return }; os.Exit(testingMain.Run())",
			false,
		},
		{"successful early exit", "os.Exit(0); os.Exit(testingMain.Run())", false},
		{"bare run", "testingMain.Run()", false},
		{"other exit", "fmt.Println(testingMain.Run())", false},
		{"missing argument", "os.Exit()", false},
		{"constant exit", "os.Exit(0)", false},
		{"run argument", "os.Exit(testingMain.Run(1))", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			files := token.NewFileSet()
			source := "package fixture\n" +
				"import (\"fmt\"; \"os\"; \"testing\")\n" +
				"type exits struct { Exit func(int) }\n" +
				"var customExit exits\n" +
				"func TestMain(testingMain *testing.M) {" + test.body + "}\n"
			file, err := parser.ParseFile(files, "fixture_test.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			info := goTypeInfo([]*ast.File{file}, files)
			function, ok := file.Decls[3].(*ast.FuncDecl)
			if !ok {
				t.Fatal("TestMain declaration is not a function")
			}
			if valid := validTestMainSyntax(function, info); valid != test.valid {
				t.Fatalf("valid = %t, want %t", valid, test.valid)
			}
			if !isTestingMain(function, info) {
				t.Fatal("testing TestMain signature rejected")
			}
		})
	}
}
