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
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"
)

type goBuildUnit struct {
	target   buildTarget
	patterns []string
	overlay  map[string][]byte
}

func snapshotGoSource(
	path string,
	readFile func(string) ([]byte, error),
) (string, []byte, bool, error) {
	if filepath.Ext(path) != ".go" {
		return "", nil, false, nil
	}
	source, err := readFile(path)
	if err != nil {
		return "", nil, false, fmt.Errorf("%s: %w", path, err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", nil, false, fmt.Errorf(
			"%s: resolve Go source: %w",
			path,
			err,
		)
	}
	if err := rejectUnsupportedBuildTags(path, source); err != nil {
		return "", nil, false, err
	}
	return absolute, source, true, nil
}

func runGoBuildUnits(units []goBuildUnit) ([]string, error) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		maxGoPolicyDuration,
	)
	defer cancel()
	return runGoBuildUnitsWith(ctx, units, packages.Load)
}

func runGoBuildUnitsWith(
	ctx context.Context,
	units []goBuildUnit,
	load packageLoader,
) ([]string, error) {
	type unitResult struct {
		findings []string
		err      error
	}
	results := make([]unitResult, len(units))
	limit := make(chan struct{}, maxGoBuildLoads)
	var wait sync.WaitGroup
	for index, unit := range units {
		wait.Go(func() {
			if err := ctx.Err(); err != nil {
				results[index].err = err
				return
			}
			select {
			case limit <- struct{}{}:
			case <-ctx.Done():
				results[index].err = ctx.Err()
				return
			}
			defer func() { <-limit }()
			if err := ctx.Err(); err != nil {
				results[index].err = err
				return
			}
			results[index].findings, results[index].err =
				goSkipFindingsForTargetWithOverlay(
					ctx,
					unit.target,
					unit.patterns,
					unit.overlay,
					load,
				)
		})
	}
	wait.Wait()
	var findings []string
	for _, result := range results {
		if result.err != nil {
			return nil, result.err
		}
		findings = append(findings, result.findings...)
	}
	slices.Sort(findings)
	return slices.Compact(findings), nil
}

type packageLoader func(
	*packages.Config,
	...string,
) ([]*packages.Package, error)

func goSkipFindingsForTargetWith(
	ctx context.Context,
	target buildTarget,
	patterns []string,
	load packageLoader,
) ([]string, error) {
	return goSkipFindingsForTargetWithOverlay(
		ctx, target, patterns, nil, load,
	)
}

func goSkipFindingsForTargetWithOverlay(
	ctx context.Context,
	target buildTarget,
	patterns []string,
	overlay map[string][]byte,
	load packageLoader,
) ([]string, error) {
	environment := goPolicyEnvironment(target)
	cgo := "0"
	if target.cgo {
		cgo = "1"
	}
	environment = append(
		environment,
		"GOOS="+target.goos,
		"GOARCH="+target.goarch,
		"CGO_ENABLED="+cgo,
		"GOPACKAGESDRIVER=off",
	)
	buildFlags := []string(nil)
	if target.race {
		buildFlags = []string{"-tags=race"}
	}
	repositoryRoot, err := filepath.Abs(".")
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	loaded, err := load(&packages.Config{
		Context: ctx,
		Mode: packages.NeedName | packages.NeedFiles |
			packages.NeedCompiledGoFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps |
			packages.NeedModule,
		Tests:      true,
		Env:        environment,
		BuildFlags: buildFlags,
		Overlay:    overlay,
	}, patterns...)
	if err != nil {
		return nil, fmt.Errorf(
			"load Go tests for %s/%s: %w", target.goos, target.goarch, err,
		)
	}
	var findings []string
	for _, loadedPackage := range policyPackages(loaded, repositoryRoot) {
		if len(loadedPackage.Errors) > 0 {
			return nil, fmt.Errorf(
				"load Go tests for %s/%s: %w",
				target.goos,
				target.goarch,
				loadedPackage.Errors[0],
			)
		}
		if loadedPackage.Name == "main" &&
			strings.HasSuffix(loadedPackage.PkgPath, ".test") {
			continue
		}
		inspector := goPolicyInspector{
			loaded:  loadedPackage,
			sources: inventoriedGoSources(overlay),
		}
		findings = append(findings, inspector.findings()...)
	}
	return findings, nil
}

func inventoriedGoSources(overlay map[string][]byte) map[string]bool {
	sources := make(map[string]bool, len(overlay))
	for path := range overlay {
		sources[filepath.Clean(path)] = true
	}
	return sources
}

func policyPackages(
	roots []*packages.Package,
	repositoryRoot string,
) []*packages.Package {
	queue := slices.Clone(roots)
	seen := make(map[string]bool)
	var result []*packages.Package
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == nil || seen[current.ID] {
			continue
		}
		seen[current.ID] = true
		result = append(result, current)
		for _, imported := range current.Imports {
			if packageInsideRepository(imported, repositoryRoot) {
				queue = append(queue, imported)
			}
		}
	}
	return result
}

func packageInsideRepository(
	loaded *packages.Package,
	repositoryRoot string,
) bool {
	if loaded == nil {
		return false
	}
	for _, path := range loaded.CompiledGoFiles {
		relative, err := filepath.Rel(repositoryRoot, path)
		if err == nil && relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
