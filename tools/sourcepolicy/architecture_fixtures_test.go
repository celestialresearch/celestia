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
	"encoding/json"
	"os"
	"testing"
)

const architectureFixtureSchema = "celestia.source-policy.architecture-fixtures.v1"

type architectureFixtureSet struct {
	Schema string                `json:"schema_version"`
	Cases  []architectureFixture `json:"cases"`
}

type architectureFixture struct {
	Name     string `json:"name"`
	Mutation string `json:"mutation"`
	Rule     string `json:"rule"`
	Expected string `json:"expected"`
}

func TestArchitectureFixtures(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/architecture-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures architectureFixtureSet
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if fixtures.Schema != architectureFixtureSchema || len(fixtures.Cases) == 0 {
		t.Fatal("invalid architecture fixture set")
	}
	for _, fixture := range fixtures.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()
			actual := evaluateArchitectureFixture(fixture.Mutation)
			if actual != fixture.Expected {
				t.Fatalf("rule %s: result = %s, want %s", fixture.Rule, actual, fixture.Expected)
			}
		})
	}
}
