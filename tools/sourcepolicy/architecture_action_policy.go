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
	"fmt"
	"sort"
	"strings"
)

const (
	actionPolicySplitDirectory  = "tools/actionpolicy/"
	maxActionPolicySplitBytes   = 4 << 20
	actionPolicySplitPackageSHA = "99a8a8bb5340b219cc1aed8466305977c0cc3f923b70b4ed5b5567fcac0498a5"
	actionPolicySplitSourceSHA  = "f4c8c84d06e77a1063f75b62588fd2ddf73c5ea241a7a2150d6d276609e0a18e"
	actionPolicySplitTargetSHA  = "430abb6d086ba41d0d92d26a7adbecf81dbe39eee384bc31c5ffcac8461ad01c"
)

var actionPolicySplitOwners = map[string]string{
	"actions.go":          "actions",
	"actions_test.go":     "actions",
	"aliases_test.go":     "aliases",
	"bounds_test.go":      "bounds",
	"doc.go":              "contract",
	"document.go":         "document",
	"document_test.go":    "document",
	"fuzz_test.go":        "fuzzing",
	"images_test.go":      "images",
	"main.go":             "runner",
	"main_test.go":        "runner",
	"permissions.go":      "permissions",
	"permissions_test.go": "permissions",
	"stream.go":           "stream",
	"yaml_test.go":        "YAML",
}

func actionPolicySplitFiles() []string {
	files := make([]string, 0, len(actionPolicySplitOwners))
	for file := range actionPolicySplitOwners {
		files = append(files, file)
	}
	sort.Strings(files)
	return files
}

func actionPolicySplitDeclarationFindings(
	files []string,
	readFile func(string) ([]byte, error),
) ([]string, error) {
	inventory, err := actionPolicySplitInventoryFor(files, readFile)
	if err != nil {
		return nil, err
	}
	var findings []string
	for label, pair := range map[string][2]string{
		"package, build and owner": {inventory.packages, actionPolicySplitPackageSHA},
		"source":                   {inventory.sources, actionPolicySplitSourceSHA},
		"test target":              {inventory.targets, actionPolicySplitTargetSHA},
	} {
		if pair[0] != pair[1] {
			findings = append(findings, fmt.Sprintf(
				"%s: %s inventory differs: %s",
				strings.TrimSuffix(actionPolicySplitDirectory, "/"), label, pair[0],
			))
		}
	}
	sort.Strings(findings)
	return findings, nil
}

func actionPolicySplitInventoryFor(
	files []string,
	readFile func(string) ([]byte, error),
) (attemptSplitInventory, error) {
	return ownedGoSplitInventoryFor(files, readFile, ownedGoSplitSpec{
		directory:        actionPolicySplitDirectory,
		packages:         []string{"main"},
		owners:           actionPolicySplitOwners,
		maxBytes:         maxActionPolicySplitBytes,
		label:            "action-policy",
		bindTargetBodies: true,
	})
}
