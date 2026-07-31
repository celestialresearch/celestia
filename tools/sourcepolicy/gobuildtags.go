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
	"fmt"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"slices"
	"strings"
)

func rejectUnsupportedBuildTags(path string, source []byte) error {
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, path, source, parser.ParseComments)
	if err != nil {
		kind := "source"
		if strings.HasSuffix(path, "_test.go") {
			kind = "test"
		}
		return fmt.Errorf("%s: parse Go %s: %w", path, kind, err)
	}
	legacyHeaderEnd := legacyBuildHeaderEnd(source)
	goBuildSeen := false
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if err := validateBuildComment(
				path, files, file.Package, comment, legacyHeaderEnd, &goBuildSeen,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateBuildComment(
	path string,
	files *token.FileSet,
	packagePosition token.Pos,
	comment *ast.Comment,
	legacyHeaderEnd int,
	goBuildSeen *bool,
) error {
	if comment.Pos() > packagePosition {
		return nil
	}
	text := strings.TrimSpace(comment.Text)
	goBuild := constraint.IsGoBuild(text)
	plusBuild := constraint.IsPlusBuild(text)
	if !goBuild && !plusBuild {
		return nil
	}
	if goBuild && *goBuildSeen {
		return fmt.Errorf("%s: multiple //go:build comments", path)
	}
	*goBuildSeen = *goBuildSeen || goBuild
	end := files.PositionFor(comment.End(), false).Offset
	if plusBuild && (end < 0 || end > legacyHeaderEnd) {
		return nil
	}
	expression, err := constraint.Parse(text)
	if err != nil {
		return fmt.Errorf("%s: parse Go build constraint: %w", path, err)
	}
	if unsupportedBuildTag(expression) {
		return fmt.Errorf("%s: ungoverned Go build constraints are unsupported", path)
	}
	return nil
}

func legacyBuildHeaderEnd(source []byte) int {
	headerEnd := 0
	offset := 0
	if bytes.HasPrefix(source, []byte{0xef, 0xbb, 0xbf}) {
		headerEnd = 3
		offset = 3
	}
	for offset < len(source) {
		next := bytes.IndexByte(source[offset:], '\n')
		lineEnd := len(source)
		if next >= 0 {
			lineEnd = offset + next + 1
		}
		line := bytes.TrimSpace(source[offset:lineEnd])
		switch {
		case len(line) == 0:
			headerEnd = lineEnd
		case bytes.HasPrefix(line, []byte("//")):
		default:
			return headerEnd
		}
		offset = lineEnd
	}
	return headerEnd
}

func unsupportedBuildTag(expression constraint.Expr) bool {
	switch value := expression.(type) {
	case *constraint.TagExpr:
		return !governedBuildTag(value.Tag)
	case *constraint.NotExpr:
		return unsupportedBuildTag(value.X)
	case *constraint.AndExpr:
		return unsupportedBuildTag(value.X) || unsupportedBuildTag(value.Y)
	case *constraint.OrExpr:
		return unsupportedBuildTag(value.X) || unsupportedBuildTag(value.Y)
	default:
		return false
	}
}

func governedBuildTag(tag string) bool {
	switch tag {
	case "cgo", "race", "unix":
		return true
	}
	if tag == build.Default.Compiler ||
		slices.Contains(build.Default.ReleaseTags, tag) {
		return true
	}
	if slices.Contains(build.Default.ToolTags, tag) &&
		!strings.HasPrefix(tag, "amd64.") &&
		!strings.HasPrefix(tag, "arm64.") {
		return true
	}
	for _, target := range policyBuildTargets {
		if tag == target.goos || tag == target.goarch {
			return true
		}
	}
	return false
}
