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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	modeSuppressions      = "suppressions"
	modeTestSkips         = "test-skips"
	maxSourceBytes        = 1 << 20
	maxInventoryBytes     = 16 << 20
	maxInventoryPaths     = 100_000
	maxInventoryPathBytes = 32 << 10
	maxGoBuildLoads       = 4
	nolintMarker          = "//no" + "lint"
	nosecMarker           = "#no" + "sec"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr, sourceFiles, readSource))
}

func run(
	args []string,
	stderr io.Writer,
	inventory func() ([]string, error),
	readFile func(string) ([]byte, error),
) int {
	if len(args) != 1 ||
		(args[0] != modeSuppressions && args[0] != modeTestSkips) {
		if _, err := fmt.Fprintln(
			stderr, "usage: sourcepolicy [suppressions|test-skips]",
		); err != nil {
			return 1
		}
		return 2
	}
	files, err := inventory()
	if err != nil {
		if _, writeErr := fmt.Fprintln(stderr, err); writeErr != nil {
			return 1
		}
		return 1
	}
	findings, err := policyFindings(files, args[0], readFile)
	if err != nil {
		if _, writeErr := fmt.Fprintln(stderr, err); writeErr != nil {
			return 1
		}
		return 1
	}
	if len(findings) == 0 {
		return 0
	}
	if _, err := fmt.Fprintln(stderr, strings.Join(findings, "\n")); err != nil {
		return 1
	}
	return 1
}

func policyFindings(
	files []string,
	mode string,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	var findings []string
	if mode == modeSuppressions {
		findings = append(
			findings,
			cargoWorkspaceInventoryFindings(files, readFile)...,
		)
	}
	if mode == modeTestSkips {
		goFindings, err := goPackageSkipFindings(files, readFile)
		if err != nil {
			return nil, err
		}
		findings = append(findings, goFindings...)
	}
	for _, path := range files {
		findings = append(findings, scanFile(path, mode, readFile)...)
	}
	return findings, nil
}

func scanFile(
	path, mode string,
	readFile func(string) ([]byte, error),
) []string {
	switch filepath.Ext(path) {
	case ".go":
		if mode != modeSuppressions {
			return nil
		}
		return readFindings(path, readFile, goSuppressionFindings)
	case ".rs":
		return readFindings(path, readFile, func(path string, source []byte) []string {
			return rustFindings(path, source, mode)
		})
	case ".toml", "":
		return tomlFindings(path, mode, readFile)
	case ".sh", ".bash", ".ps1":
		if mode != modeSuppressions {
			return nil
		}
		return readFindings(path, readFile, shellSuppressionFindings)
	case ".yml", ".yaml":
		if mode != modeSuppressions {
			return nil
		}
		return readFindings(path, readFile, workflowCargoConfigFindings)
	}
	return nil
}

func tomlFindings(
	path, mode string,
	readFile func(string) ([]byte, error),
) []string {
	if mode != modeSuppressions {
		return nil
	}
	switch {
	case filepath.Base(path) == "Cargo.toml":
		return readFindings(path, readFile, cargoLintFindings)
	case (filepath.Base(path) == "config.toml" ||
		filepath.Base(path) == "config") &&
		filepath.Base(filepath.Dir(path)) == ".cargo":
		return readFindings(path, readFile, cargoConfigFindings)
	default:
		return nil
	}
}

func readFindings(
	path string,
	readFile func(string) ([]byte, error),
	scan func(string, []byte) []string,
) []string {
	source, err := readFile(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", path, err)}
	}
	return scan(path, source)
}

func readSource(path string) (source []byte, err error) {
	root, err := os.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := root.Close(); err == nil {
			err = closeErr
		}
	}()
	file, err := root.Open(filepath.FromSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return nil, errors.New("source file is not a bounded regular file")
	}
	if info.Size() > maxSourceBytes {
		return nil, fmt.Errorf("source file exceeds %d bytes", maxSourceBytes)
	}
	source, err = io.ReadAll(io.LimitReader(file, maxSourceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(source) > maxSourceBytes {
		return nil, fmt.Errorf("source file exceeds %d bytes", maxSourceBytes)
	}
	return source, nil
}

func sourceFiles() ([]string, error) {
	git := os.Getenv("CELESTIA_GIT_BIN")
	if git == "" {
		git = "git"
	}
	return inventorySourceFiles(git, inventoryCommandContext)
}

type inventoryCommand interface {
	Start() error
	StdoutPipe() (io.ReadCloser, error)
	Wait() error
}

type inventoryCommandFactory func(
	context.Context,
	string,
	...string,
) inventoryCommand

func inventoryCommandContext(
	ctx context.Context,
	name string,
	args ...string,
) inventoryCommand {
	// #nosec G204,G702 -- The Git binary is an explicit repository control.
	return exec.CommandContext(ctx, name, args...)
}

func inventorySourceFiles(
	git string,
	commandFactory inventoryCommandFactory,
) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := commandFactory(
		ctx, git, "ls-files", "-co", "--exclude-standard", "-z",
	)
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("inventory source files: %w", err)
	}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("inventory source files: %w", err)
	}
	files, readErr := readInventory(output)
	if readErr != nil {
		cancel()
	}
	waitErr := command.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("inventory source files: %w", readErr)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("inventory source files: %w", waitErr)
	}
	return files, nil
}

func readInventory(source io.Reader) ([]string, error) {
	return readInventoryWithLimits(
		source,
		maxInventoryBytes,
		maxInventoryPaths,
		maxInventoryPathBytes,
	)
}

func readInventoryWithLimits(
	source io.Reader,
	maxBytes, maxPaths, maxPathBytes int,
) ([]string, error) {
	reader := bufio.NewReaderSize(source, maxPathBytes+1)
	files := make([]string, 0, 256)
	total := 0
	for {
		path, err := reader.ReadSlice(0)
		total += len(path)
		if total > maxBytes {
			return nil, errors.New("source inventory exceeds the byte limit")
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, errors.New("source inventory path exceeds the size limit")
		}
		if err == nil && len(path)-1 > maxPathBytes {
			return nil, errors.New("source inventory path exceeds the size limit")
		}
		if errors.Is(err, io.EOF) {
			if len(path) != 0 {
				return nil, errors.New("source inventory is not NUL terminated")
			}
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		path = path[:len(path)-1]
		if len(path) == 0 {
			return nil, errors.New("source inventory contains an empty path")
		}
		if len(files) == maxPaths {
			return nil, errors.New("source inventory exceeds the path limit")
		}
		files = append(files, string(path))
	}
}

func goSkipFindings(path string, source []byte) []string {
	if !strings.HasSuffix(path, "_test.go") {
		return nil
	}
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, path, source, 0)
	if err != nil {
		return []string{fmt.Sprintf("%s: parse Go test: %v", path, err)}
	}
	return goSkipFindingsInPackage(files, []*ast.File{file}, map[*ast.File]string{
		file: path,
	})
}

func goSkipFindingsInPackage(
	files *token.FileSet,
	packageFiles []*ast.File,
	names map[*ast.File]string,
) []string {
	info := goTypeInfo(packageFiles, files)
	var findings []string
	for _, file := range packageFiles {
		path := names[file]
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || !isTestingSkip(selector, info) {
				return true
			}
			position := files.Position(selector.Pos())
			findings = append(findings, fmt.Sprintf(
				"%s:%d: Go tests must not skip cases",
				path,
				position.Line,
			))
			return true
		})
	}
	return findings
}

func goTypeInfo(packageFiles []*ast.File, files *token.FileSet) *types.Info {
	info := &types.Info{
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Uses:       make(map[*ast.Ident]types.Object),
	}
	config := types.Config{Importer: importer.Default()}
	if _, checkErr := config.Check(
		packageFiles[0].Name.Name, files, packageFiles, info,
	); checkErr != nil {
		return info
	}
	return info
}

func isTestingSkip(selector *ast.SelectorExpr, info *types.Info) bool {
	if !isSkipMethod(selector.Sel.Name) {
		return false
	}
	if selection := info.Selections[selector]; selection != nil {
		return testingMethod(selection.Obj()) ||
			interfaceTestingSkip(selection)
	}
	return testingMethod(info.Uses[selector.Sel])
}

func interfaceTestingSkip(selection *types.Selection) bool {
	if _, ok := selection.Recv().Underlying().(*types.Interface); !ok {
		return false
	}
	function, ok := selection.Obj().(*types.Func)
	if !ok {
		return false
	}
	signature, ok := function.Type().(*types.Signature)
	if !ok || signature.Results().Len() != 0 {
		return false
	}
	switch function.Name() {
	case "Skip":
		return anyVariadicSignature(signature, 0)
	case "Skipf":
		return signature.Params().Len() == 2 &&
			types.Identical(
				signature.Params().At(0).Type(),
				types.Typ[types.String],
			) &&
			anyVariadicSignature(signature, 1)
	case "SkipNow":
		return !signature.Variadic() && signature.Params().Len() == 0
	default:
		return false
	}
}

func anyVariadicSignature(signature *types.Signature, index int) bool {
	if !signature.Variadic() || signature.Params().Len() != index+1 {
		return false
	}
	slice, ok := signature.Params().At(index).Type().(*types.Slice)
	return ok && types.Identical(
		types.Unalias(slice.Elem()),
		types.Unalias(types.Universe.Lookup("any").Type()),
	)
}

func isSkipMethod(name string) bool {
	return name == "Skip" || name == "Skipf" || name == "SkipNow"
}

func testingMethod(object types.Object) bool {
	function, ok := object.(*types.Func)
	return ok && function.Pkg() != nil && function.Pkg().Path() == "testing"
}

type rustAttribute struct {
	line int
	text string
}

func rustFindings(path string, source []byte, mode string) []string {
	if finding := rustExpansionFinding(path, source, mode); finding != "" {
		return []string{finding}
	}
	attributes, err := rustAttributes(source)
	if err != nil {
		return []string{fmt.Sprintf("%s: parse Rust attributes: %v", path, err)}
	}
	var findings []string
	for _, attribute := range attributes {
		findings = append(
			findings,
			rustAttributeFindings(path, attribute, mode)...,
		)
	}
	return findings
}

func rustExpansionFinding(path string, source []byte, mode string) string {
	tokens, valid := rustPolicyTokens(source)
	if !valid {
		return fmt.Sprintf("%s: parse Rust source: unterminated token", path)
	}
	if line, found := rustIncludeLine(tokens); found {
		return fmt.Sprintf("%s:%d: Rust include! is prohibited", path, line)
	}
	if line, found := rustMacroIgnoreLine(tokens); mode == modeTestSkips && found {
		return fmt.Sprintf(
			"%s:%d: Rust tests must not ignore cases", path, line,
		)
	}
	return ""
}

func rustIncludeLine(tokens []rustPolicyToken) (int, bool) {
	inUse := false
	for index, token := range tokens {
		switch token.text {
		case "use":
			inUse = true
		case ";":
			inUse = false
		case "include":
			if inUse ||
				index+1 < len(tokens) && tokens[index+1].text == "!" {
				return token.line, true
			}
		}
	}
	return 0, false
}

func rustMacroIgnoreLine(tokens []rustPolicyToken) (int, bool) {
	var macroDepth []bool
	for index, token := range tokens {
		switch token.text {
		case "(", "[", "{":
			inMacro := index > 0 && tokens[index-1].text == "!"
			if len(macroDepth) > 0 && macroDepth[len(macroDepth)-1] {
				inMacro = true
			}
			macroDepth = append(macroDepth, inMacro)
		case ")", "]", "}":
			if len(macroDepth) > 0 {
				macroDepth = macroDepth[:len(macroDepth)-1]
			}
		default:
			if token.text == "ignore" &&
				len(macroDepth) > 0 && macroDepth[len(macroDepth)-1] {
				return token.line, true
			}
		}
	}
	return 0, false
}

func rustAttributeFindings(
	path string,
	attribute rustAttribute,
	mode string,
) []string {
	words := rustAttributeIdentifiers([]byte(attribute.text))
	if rustAttributeSetsPath([]byte(attribute.text)) {
		return []string{fmt.Sprintf(
			"%s:%d: Rust path attributes are prohibited", path, attribute.line,
		)}
	}
	switch mode {
	case modeTestSkips:
		if contains(words, "ignore") {
			return []string{fmt.Sprintf(
				"%s:%d: Rust tests must not ignore cases", path, attribute.line,
			)}
		}
	case modeSuppressions:
		if strings.Contains(attribute.text, "$") {
			return []string{fmt.Sprintf(
				"%s:%d: dynamic Rust attributes are prohibited",
				path,
				attribute.line,
			)}
		}
		if (contains(words, "allow") || contains(words, "expect")) &&
			!validClippySuppression(attribute.text) {
			return []string{fmt.Sprintf(
				"%s:%d: invalid Clippy suppression", path, attribute.line,
			)}
		}
	}
	return nil
}

type rustPolicyToken struct {
	text string
	line int
}

func rustPolicyTokens(source []byte) ([]rustPolicyToken, bool) {
	var tokens []rustPolicyToken
	for index, line := 0, 1; index < len(source); {
		next, nextLine, valid := skipRustTrivia(source, index, line)
		index, line = next, nextLine
		if !valid || index >= len(source) {
			return tokens, valid
		}
		if rustTokenStart(source[index]) {
			index, line = skipRustToken(source, index, line)
			continue
		}
		start := index
		for index < len(source) && isRustIdentifierByte(source[index]) {
			index++
		}
		if start == index {
			tokens = append(tokens, rustPolicyToken{
				text: string(source[index]),
				line: line,
			})
			index++
			continue
		}
		tokens = append(tokens, rustPolicyToken{
			text: string(source[start:index]),
			line: line,
		})
	}
	return tokens, true
}

func rustAttributeSetsPath(source []byte) bool {
	tokens, valid := rustPolicyTokens(source)
	if !valid {
		return false
	}
	for index, token := range tokens {
		if token.text != "path" || index+1 >= len(tokens) ||
			tokens[index+1].text != "=" {
			continue
		}
		return true
	}
	return false
}

func rustAttributes(source []byte) ([]rustAttribute, error) {
	var attributes []rustAttribute
	for index, line := 0, 1; index < len(source); {
		next, nextLine, ok := skipRustTrivia(source, index, line)
		index, line = next, nextLine
		if !ok {
			return nil, errors.New("unterminated comment")
		}
		if index >= len(source) {
			break
		}
		if source[index] != '#' {
			index, line = skipRustToken(source, index, line)
			continue
		}
		attribute, nextIndex, nextLine, found, attributeErr :=
			readRustAttribute(source, index, line)
		if attributeErr != nil {
			return nil, attributeErr
		}
		if !found {
			index++
			continue
		}
		attributes = append(attributes, attribute)
		index, line = nextIndex, nextLine
	}
	return attributes, nil
}

func readRustAttribute(
	source []byte,
	index, line int,
) (rustAttribute, int, int, bool, error) {
	start, startLine := index, line
	index++
	if index < len(source) && source[index] == '!' {
		index++
	}
	if index >= len(source) || source[index] != '[' {
		return rustAttribute{}, index, line, false, nil
	}
	depth := 1
	for index++; index < len(source) && depth > 0; {
		nextIndex, nextLine, nextDepth, err :=
			advanceRustAttribute(source, index, line, depth)
		if err != nil {
			return rustAttribute{}, index, line, false, err
		}
		index, line, depth = nextIndex, nextLine, nextDepth
	}
	if depth != 0 {
		return rustAttribute{}, index, line, false,
			errors.New("unterminated attribute")
	}
	return rustAttribute{
		line: startLine,
		text: string(source[start:index]),
	}, index, line, true, nil
}

func advanceRustAttribute(
	source []byte,
	index, line, depth int,
) (int, int, int, error) {
	if source[index] == '\n' {
		return index + 1, line + 1, depth, nil
	}
	if rustTokenStart(source[index]) {
		index, line = skipRustToken(source, index, line)
		return index, line, depth, nil
	}
	if index+1 < len(source) && source[index] == '/' &&
		(source[index+1] == '/' || source[index+1] == '*') {
		var valid bool
		index, line, valid = skipRustTrivia(source, index, line)
		if !valid {
			return index, line, depth, errors.New("unterminated comment")
		}
		return index, line, depth, nil
	}
	switch source[index] {
	case '[':
		depth++
	case ']':
		depth--
	}
	return index + 1, line, depth, nil
}

func rustTokenStart(value byte) bool {
	switch value {
	case '"', '\'', 'r', 'b':
		return true
	default:
		return false
	}
}

func skipRustTrivia(source []byte, index, line int) (int, int, bool) {
	for index < len(source) {
		if unicode.IsSpace(rune(source[index])) {
			index, line = skipRustWhitespace(source, index, line)
			continue
		}
		if index+1 >= len(source) || source[index] != '/' {
			return index, line, true
		}
		if source[index+1] == '/' {
			index += 2
			for index < len(source) && source[index] != '\n' {
				index++
			}
			continue
		}
		if source[index+1] == '*' {
			var valid bool
			index, line, valid = skipRustBlockComment(source, index, line)
			if !valid {
				return index, line, false
			}
			continue
		}
		return index, line, true
	}
	return index, line, true
}

func skipRustWhitespace(source []byte, index, line int) (int, int) {
	for index < len(source) && unicode.IsSpace(rune(source[index])) {
		if source[index] == '\n' {
			line++
		}
		index++
	}
	return index, line
}

func skipRustBlockComment(source []byte, index, line int) (int, int, bool) {
	index += 2
	depth := 1
	for index < len(source) && depth > 0 {
		if source[index] == '\n' {
			line++
		}
		if index+1 < len(source) && source[index] == '/' &&
			source[index+1] == '*' {
			depth++
			index += 2
		} else if index+1 < len(source) && source[index] == '*' &&
			source[index+1] == '/' {
			depth--
			index += 2
		} else {
			index++
		}
	}
	return index, line, depth == 0
}

func skipRustToken(source []byte, index, line int) (int, int) {
	if end, ok := skipRustRawString(source, index); ok {
		return end, line + bytes.Count(source[index:end], []byte{'\n'})
	}
	if source[index] == 'b' && index+1 < len(source) &&
		(source[index+1] == '"' || source[index+1] == '\'') {
		index++
	}
	if source[index] == '\'' {
		return skipRustCharacter(source, index, line)
	}
	if source[index] != '"' {
		return index + 1, line
	}
	return skipRustString(source, index, line)
}

func skipRustString(source []byte, index, line int) (int, int) {
	index++
	escaped := false
	for index < len(source) {
		current := source[index]
		index++
		if current == '\n' {
			line++
		}
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
		} else if current == '"' {
			break
		}
	}
	return index, line
}

func skipRustRawString(source []byte, index int) (int, bool) {
	start := index
	if source[index] == 'b' {
		index++
	}
	if index >= len(source) || source[index] != 'r' {
		return start, false
	}
	index++
	hashes := 0
	for index < len(source) && source[index] == '#' {
		hashes++
		index++
	}
	if index >= len(source) || source[index] != '"' {
		return start, false
	}
	index++
	terminator := `"` + strings.Repeat("#", hashes)
	offset := bytes.Index(source[index:], []byte(terminator))
	if offset < 0 {
		return len(source), true
	}
	return index + offset + len(terminator), true
}

func skipRustCharacter(source []byte, index, line int) (int, int) {
	next := index + 1
	if next >= len(source) {
		return next, line
	}
	if source[next] == '\\' {
		next++
		for next < len(source) && source[next] != '\'' &&
			source[next] != '\n' {
			next++
		}
		if next < len(source) && source[next] == '\'' {
			return next + 1, line
		}
		return index + 1, line
	}
	_, size := utf8.DecodeRune(source[next:])
	if size > 0 && next+size < len(source) && source[next+size] == '\'' {
		return next + size + 1, line
	}
	return index + 1, line
}

func rustAttributeIdentifiers(source []byte) []string {
	var identifiers []string
	for index := 0; index < len(source); {
		if next, valid, found := rustAttributeComment(source, index); found {
			if !valid {
				return append(identifiers, "invalid_comment")
			}
			index = next
			continue
		}
		if source[index] == '"' || source[index] == '\'' ||
			source[index] == 'r' || source[index] == 'b' {
			next, _ := skipRustToken(source, index, 1)
			if next > index+1 {
				index = next
				continue
			}
		}
		if !isRustIdentifierByte(source[index]) {
			index++
			continue
		}
		start := index
		for index < len(source) && isRustIdentifierByte(source[index]) {
			index++
		}
		identifiers = append(identifiers, string(source[start:index]))
	}
	return identifiers
}

func rustAttributeComment(source []byte, index int) (int, bool, bool) {
	if index+1 >= len(source) || source[index] != '/' ||
		(source[index+1] != '/' && source[index+1] != '*') {
		return index, true, false
	}
	next, _, valid := skipRustTrivia(source, index, 1)
	return next, valid, true
}

func isRustIdentifierByte(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func contains(values []string, wanted string) bool {
	return slices.Contains(values, wanted)
}

func validClippySuppression(value string) bool {
	compact := strings.Join(strings.Fields(value), "")
	var body string
	switch {
	case strings.HasPrefix(compact, "#[allow(clippy::"):
		body = strings.TrimPrefix(compact, "#[allow(clippy::")
	case strings.HasPrefix(compact, "#[expect(clippy::"):
		body = strings.TrimPrefix(compact, "#[expect(clippy::")
	default:
		return false
	}
	rule, reason, ok := strings.Cut(body, `,reason="`)
	if !ok || rule == "" || rule == "all" || !validRustIdentifier(rule) {
		return false
	}
	return reason != `")]` && strings.HasSuffix(reason, `")]`)
}

func validRustIdentifier(value string) bool {
	for _, character := range value {
		if !unicode.IsLower(character) && !unicode.IsDigit(character) &&
			character != '_' {
			return false
		}
	}
	return true
}
