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
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestTestsInFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "inventory_test.go")
	source := `package fixture
import "testing"
func TestMain(*testing.M) {}
func TestMustRun(*testing.T) {}
func Testhelper(*testing.T) {}
func FuzzInput(*testing.F) {}
func ExampleVisible() {
	// Output:
}
func ExampleHidden() {}
`
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := testsInFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"TestMustRun", "FuzzInput", "ExampleVisible"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("testsInFile() = %v, want %v", got, want)
	}
}

func TestWriteCargoExecutables(t *testing.T) {
	t.Parallel()
	input := bytes.NewBufferString(
		`{"reason":"build-finished","profile":{"test":true},` +
			`"executable":"ignored"}` + "\n" +
			`{"reason":"compiler-artifact","profile":{"test":false},` +
			`"executable":"ignored"}` + "\n" +
			`{"reason":"compiler-artifact","profile":{"test":true},` +
			`"executable":""}` + "\n" +
			`{"reason":"compiler-artifact","profile":{"test":true},` +
			`"executable":"z"}` + "\n" +
			`{"reason":"compiler-artifact","profile":{"test":true},` +
			`"executable":"a"}` + "\n" +
			`{"reason":"compiler-artifact","profile":{"test":true},` +
			`"executable":"z"}` + "\n",
	)
	var output bytes.Buffer
	if err := writeCargoExecutables(input, &output); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "a\nz\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestWriteCargoExecutablesRejectsMalformedInput(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := writeCargoExecutables(
		bytes.NewBufferString("not-json\n"),
		&output,
	); err == nil {
		t.Fatal("malformed Cargo output was accepted")
	}
}

func TestRunTestInventory(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	handled, status := runTestInventory(
		[]string{modeCargoTestInventory},
		bytes.NewBufferString(
			`{"reason":"build-finished","success":true}`+"\n",
		),
		&output,
		&output,
	)
	if !handled || status != 0 {
		t.Fatalf("runTestInventory() = %t, %d", handled, status)
	}
	handled, _ = runTestInventory(nil, &output, &output, &output)
	if handled {
		t.Fatal("ordinary source-policy arguments were handled as inventory")
	}
}
