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
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	root := t.TempDir()
	goPath := filepath.Join(root, "skipped_test.go")
	rustPath := filepath.Join(root, "suppressed.rs")
	missingRustPath := filepath.Join(root, "missing.rs")
	if err := os.WriteFile(goPath, []byte(
		"package fixture\nimport \"testing\"\n"+
			"func TestFixture(t *testing.T) { t.SkipNow() }\n",
	), 0o600); err != nil {
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
			"Go skip",
			[]string{modeTestSkips},
			func() ([]string, error) { return []string{goPath}, nil },
			1,
			"Go tests must not skip",
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
	candidate, err := hasGoSkipSelector(
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

func TestGoSuppressionFindings(t *testing.T) {
	source := []byte(strings.Join([]string{
		"// #no" + "sec",
		"// #no" + "sec G304 -- bounded repository source",
		"//no" + "lint",
		"//no" + "lint:errcheck -- checked by the owner",
		"//no" + "lint:all -- broad suppression",
	}, "\n"))
	findings := goSuppressionFindings("source.go", source)
	if len(findings) != 3 {
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
	files, err := inventorySourceFiles("git", func(
		context.Context,
		string,
		...string,
	) inventoryCommand {
		return &fakeInventoryCommand{
			output: strings.NewReader("main.go\x00"),
		}
	})
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
			_, err := inventorySourceFiles("git", func(
				context.Context,
				string,
				...string,
			) inventoryCommand {
				return test.command
			})
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
	findings, err := goPackageSkipFindings(
		[]string{
			filepath.Base(helper),
			filepath.Base(caller),
			filepath.Base(linux),
			filepath.Base(windows),
		},
		os.ReadFile,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("findings = %v, want four", findings)
	}
}

func TestGoSkipCandidateFailures(t *testing.T) {
	t.Parallel()
	_, err := goCandidateDirectories(
		[]string{"broken_test.go"},
		func(string) ([]byte, error) {
			return []byte("package fixture\nfunc TestBroken("), nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "parse Go test") {
		t.Fatalf("parse error = %v", err)
	}

	readErr := errors.New("read failure")
	_, err = goCandidateDirectories(
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
	)
	if err == nil || !strings.Contains(err.Error(), "match Go build constraints") {
		t.Fatalf("constraint error = %v", err)
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
				"func TestMain(testingMain *testing.M) {" + test.body + "}\n"
			file, err := parser.ParseFile(files, "fixture_test.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			info := goTypeInfo([]*ast.File{file}, files)
			function, ok := file.Decls[1].(*ast.FuncDecl)
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

var cargoLintCases = []struct {
	name     string
	source   string
	findings int
}{
	{"Clippy string", "[lints.clippy]\nall = \"allow\"\n", 1},
	{
		"Clippy table",
		"[workspace.lints.clippy]\nneedless_return = { level = \"allow\" }\n",
		1,
	},
	{"Rust allow", "[lints.rust]\nunsafe_code = \"allow\"\n", 1},
	{
		"Rustdoc allow",
		"[lints.rustdoc]\nbroken_intra_doc_links = \"allow\"\n",
		1,
	},
	{
		"Cargo allow",
		"[workspace.lints.cargo]\nunknown_lints = \"allow\"\n",
		1,
	},
	{
		"custom tool allow",
		"[lints.custom]\nrule = \"allow\"\n",
		1,
	},
	{"deny", "[workspace.lints.clippy]\nall = \"deny\"\n", 0},
	{"workspace inheritance", "[lints]\nworkspace = true\n", 0},
	{
		"automatic tests disabled",
		"[package]\nname = \"fixture\"\nautotests = false\n",
		1,
	},
	{"target tests disabled", "[[bin]]\nname = \"fixture\"\ntest = false\n", 0},
	{"doctests disabled", "[lib]\ndoctest = false\n", 0},
	{"custom harness", "[[test]]\nname = \"fixture\"\nharness = false\n", 1},
	{
		"feature-gated test",
		"[[test]]\nname = \"fixture\"\nrequired-features = [\"hidden\"]\n",
		1,
	},
	{"package features", "[features]\nhidden = []\n", 1},
	{
		"optional dependency",
		"[dependencies]\nfixture = { version = \"1\", optional = true }\n",
		1,
	},
	{
		"target optional dependency",
		"[target.'cfg(windows)'.dev-dependencies]\n" +
			"fixture = { version = \"1\", optional = true }\n",
		1,
	},
	{
		"workspace optional dependency",
		"[workspace.dependencies]\n" +
			"fixture = { version = \"1\", optional = true }\n",
		1,
	},
	{
		"required dependency",
		"[dependencies]\nfixture = { version = \"1\" }\n",
		0,
	},
	{"test profile", "[profile.test]\ndebug-assertions = false\n", 1},
	{"ordinary target", "[[test]]\nname = \"fixture\"\npath = \"tests/fixture.rs\"\n", 0},
	{"patch", "[patch.crates-io]\nfixture = { path = \"../fixture\" }\n", 1},
	{"replace", "[replace]\n\"fixture:1.0.0\" = { path = \"../fixture\" }\n", 1},
	{"unrelated", "[package]\nname = \"fixture\"\n", 0},
	{"malformed", "[lints.clippy\n", 1},
}

func TestCargoLintAllowances(t *testing.T) {
	t.Parallel()
	for _, test := range cargoLintCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			findings := cargoLintFindings(
				"Cargo.toml",
				[]byte(test.source),
			)
			if len(findings) != test.findings {
				t.Fatalf("findings = %v, want %d", findings, test.findings)
			}
		})
	}
}

func TestCargoConfigurationAllowances(t *testing.T) {
	t.Parallel()
	for _, test := range cargoConfigurationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			findings := cargoConfigFindings(
				".cargo/config.toml",
				[]byte(test.source),
			)
			if len(findings) != test.findings {
				t.Fatalf("findings = %v, want %d", findings, test.findings)
			}
		})
	}
}

func cargoConfigurationCases() []struct {
	name     string
	source   string
	findings int
} {
	return []struct {
		name     string
		source   string
		findings int
	}{
		{"array allow", `[build]` + "\n" + `rustflags = ["-A", "clippy::all"]`, 1},
		{"compact allow", `[build]` + "\n" + `rustflags = ["-Aclippy::all"]`, 1},
		{"long allow", `[build]` + "\n" + `rustflags = "--allow warnings"`, 1},
		{
			"target cap",
			`[target.x86_64-pc-windows-msvc]` + "\n" +
				`rustflags = ["--cap-lints=allow"]`,
			1,
		},
		{"warn cap", `[build]` + "\n" + `rustflags = ["--cap-lints=warn"]`, 1},
		{"deny cap", `[build]` + "\n" + `rustflags = ["--cap-lints", "deny"]`, 1},
		{
			"array table override",
			`[[target]]` + "\n" + `runner = "untrusted"`,
			1,
		},
		{
			"rustdoc allow",
			`[build]` + "\n" + `rustdocflags = ["--allow=warnings"]`,
			1,
		},
		{"response file", `[build]` + "\n" + `rustflags = ["@args.txt"]`, 1},
		{"included config", `include = ["hostile.toml"]`, 1},
		{"command alias", `[alias]` + "\n" + `clippy = "bypass"`, 1},
		{
			"credential alias",
			`[credential-alias]` + "\n" + `private = ["credential.exe"]`,
			1,
		},
		{"source paths", `paths = ["../override"]`, 1},
		{"environment", `[env]` + "\n" + `RUSTFLAGS = "--cap-lints=allow"`, 1},
		{"source table", `[source.crates-io]` + "\n" + `replace-with = "mirror"`, 1},
		{
			"test profile",
			`[profile.test]` + "\n" + `debug-assertions = false`,
			1,
		},
		{"build warnings", `[build]` + "\n" + `warnings = "allow"`, 1},
		{"build target", `[build]` + "\n" + `target = "wasm32-unknown-unknown"`, 1},
		{
			"cfg injection",
			`[build]` + "\n" + `rustflags = ["--cfg", "skip_tests"]`,
			1,
		},
		{"rustc wrapper", `[build]` + "\n" + `rustc-wrapper = "wrapper.exe"`, 1},
		{
			"workspace wrapper",
			`[build]` + "\n" + `rustc-workspace-wrapper = "wrapper.exe"`,
			1,
		},
		{"rustc override", `[build]` + "\n" + `rustc = "rustc-proxy.exe"`, 1},
		{
			"target runner",
			`[target.x86_64-pc-windows-msvc]` + "\n" +
				`runner = "runner.exe"`,
			1,
		},
		{
			"target linker",
			`[target.x86_64-pc-windows-msvc]` + "\n" +
				`linker = "linker.exe"`,
			1,
		},
		{"linker", `[build]` + "\n" + `rustflags = ["-C", "link-arg=/Brepro"]`, 0},
		{"linker string", `[build]` + "\n" + `rustflags = "-C link-arg=/Brepro"`, 0},
		{"empty rustdoc flags", `[build]` + "\n" + `rustdocflags = []`, 0},
		{"malformed", `[build` + "\n", 1},
	}
}

func TestRustPolicyAttributes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		source   string
		mode     string
		findings int
	}{
		{"ignore", "#[ignore]\nfn test() {}", modeTestSkips, 1},
		{"conditional ignore", "#[cfg_attr(all(), ignore)]\nfn test() {}", modeTestSkips, 1},
		{"inner allow", "#![allow(clippy::all)]", modeSuppressions, 1},
		{"inner expect", "#![expect(clippy::all)]", modeSuppressions, 1},
		{
			"dynamic suppression",
			`macro_rules! lint { ($level:ident) => { #[$level(clippy::all)] fn f() {} } }`,
			modeSuppressions,
			1,
		},
		{
			"reasoned allow",
			`#[allow(clippy::needless_pass_by_value, reason = "FFI owns the value")]`,
			modeSuppressions,
			0,
		},
		{"comment", "// #[ignore]\nfn test() {}", modeTestSkips, 0},
		{"string", `const VALUE: &str = "#[ignore]";`, modeTestSkips, 0},
		{"include", `include!("skipped.inc");`, modeTestSkips, 1},
		{"include alias", `use std::include as load;`, modeTestSkips, 1},
		{
			"include forwarding",
			`macro_rules! load { ($path:expr) => { include!($path) } }`,
			modeTestSkips,
			1,
		},
		{"path module", `#[path = "skipped.inc"] mod skipped;`, modeTestSkips, 1},
		{
			"conditional path",
			`#[cfg_attr(all(), path = "skipped.inc")] mod skipped;`,
			modeTestSkips,
			1,
		},
		{
			"forwarded ignore",
			`macro_rules! make_test {
				($attribute:meta) => { #[test] #[$attribute] fn generated() {} };
			}
			make_test!(ignore);`,
			modeTestSkips,
			1,
		},
		{"include comment", `// include!("skipped.inc");`, modeTestSkips, 0},
		{"include string", `const VALUE: &str = "include!(ignored)";`, modeTestSkips, 0},
		{"include function", `fn include(value: u8) -> u8 { value }`, modeTestSkips, 0},
		{
			"ordinary include alias",
			`use helper::call as include; fn invoke() { include(); }`,
			modeTestSkips,
			0,
		},
		{"ignore function", `fn ignore(value: bool) -> bool { value }`, modeTestSkips, 0},
		{
			"ignore macro expression",
			`fn ignore() {} fn invoke() { evaluate!(ignore()); }`,
			modeTestSkips,
			0,
		},
		{"cfg path predicate", `#[cfg(path)] fn selected() {}`, modeTestSkips, 0},
		{"attribute string", `#[doc = "allow ignore"]`, modeSuppressions, 0},
		{"raw attribute string", `#[doc = r##"" allow ignore"##]`, modeSuppressions, 0},
		{"attribute comment", `#[cfg(/* allow ignore */ test)]`, modeSuppressions, 0},
		{"lifetime before attribute", "'a\n#[ignore]", modeTestSkips, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			findings := rustFindings("fixture.rs", []byte(test.source), test.mode)
			if len(findings) != test.findings {
				t.Fatalf("findings = %v, want %d", findings, test.findings)
			}
		})
	}
}

func TestCargoWorkspaceInventory(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"Cargo.toml": `[workspace]
members = ["worker/url-reference"]
exclude = ["worker/qualification-fixtures"]
`,
		"worker/url-reference/Cargo.toml":          "[package]\n",
		"worker/qualification-fixtures/Cargo.toml": "[package]\n",
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	readFile := func(path string) ([]byte, error) {
		return []byte(files[path]), nil
	}
	if findings := cargoWorkspaceInventoryFindings(paths, readFile); len(findings) != 0 {
		t.Fatalf("valid inventory findings = %v", findings)
	}
	paths = append(paths, "hidden/Cargo.toml")
	if findings := cargoWorkspaceInventoryFindings(paths, readFile); len(findings) != 1 {
		t.Fatalf("hidden manifest findings = %v, want 1", findings)
	}
	files["Cargo.toml"] = "[workspace]\nmembers = []\nexclude = []\n"
	if findings := cargoWorkspaceInventoryFindings(paths[:3], readFile); len(findings) != 2 {
		t.Fatalf("workspace mismatch findings = %v, want 2", findings)
	}
	if findings := cargoWorkspaceInventoryFindings(
		[]string{"Cargo.toml"},
		func(string) ([]byte, error) { return nil, errors.New("read failure") },
	); len(findings) != 1 {
		t.Fatalf("read findings = %v, want 1", findings)
	}
	if cargoStringListEquals([]any{"one", 2}, []string{"one", "two"}) {
		t.Fatal("mixed Cargo string list accepted")
	}
}

func TestRustLexicalBoundaries(t *testing.T) {
	t.Parallel()
	errorCases := []string{
		"/*",
		"#[",
		"#[/*",
		"#[\"unterminated",
	}
	for _, source := range errorCases {
		if _, err := rustAttributes([]byte(source)); err == nil {
			t.Errorf("rustAttributes(%q) accepted malformed source", source)
		}
	}
	validCases := []string{
		"#",
		"// comment\n#[test]",
		"/* outer /* nested */ comment */ #[test]",
		"#[cfg([nested])]",
	}
	for _, source := range validCases {
		if _, err := rustAttributes([]byte(source)); err != nil {
			t.Errorf("rustAttributes(%q) error = %v", source, err)
		}
	}
	characterCases := []string{
		"'",
		"'a",
		"'a'",
		"'🦀'",
		"'\\n'",
		"'\\",
	}
	for _, source := range characterCases {
		end, _ := skipRustCharacter([]byte(source), 0, 1)
		if end <= 0 || end > len(source) {
			t.Errorf("skipRustCharacter(%q) = %d", source, end)
		}
	}
	stringCases := []string{
		`"ordinary"`,
		"\"escaped\\\"quote\"",
		"\"line\nbreak\"",
		`"unterminated`,
	}
	for _, source := range stringCases {
		end, _ := skipRustString([]byte(source), 0, 1)
		if end != len(source) {
			t.Errorf("skipRustString(%q) = %d, want %d", source, end, len(source))
		}
	}
}

func TestClippySuppressionShape(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value string
		valid bool
	}{
		{`#[expect(clippy::unwrap_used, reason = "checked invariant")]`, true},
		{`#![allow(clippy::unwrap_used, reason = "crate scope")]`, false},
		{`#[allow(clippy::all, reason = "blanket")]`, false},
		{`#[allow(clippy::UPPER, reason = "invalid rule")]`, false},
		{`#[allow(clippy::unwrap_used)]`, false},
		{`#[allow(clippy::unwrap_used, reason = "")]`, false},
		{`#[cfg_attr(all(), allow(clippy::unwrap_used))]`, false},
	}
	for _, test := range tests {
		if validClippySuppression(test.value) != test.valid {
			t.Errorf("validClippySuppression(%q) != %t", test.value, test.valid)
		}
	}
}
