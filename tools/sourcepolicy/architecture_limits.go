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
	"errors"
)

const maxArchitectureInputBytes = 16 << 20

type architectureReadBudget struct {
	read      func(string) ([]byte, error)
	remaining int
}

func newArchitectureReadBudget(read func(string) ([]byte, error)) *architectureReadBudget {
	return &architectureReadBudget{
		read: read, remaining: maxArchitectureInputBytes,
	}
}

func (budget *architectureReadBudget) readFile(name string) ([]byte, error) {
	data, err := budget.read(name)
	if err != nil {
		return nil, err
	}
	if len(data) > budget.remaining {
		return nil, errors.New("architecture input exceeds its aggregate size bound")
	}
	budget.remaining -= len(data)
	return data, nil
}
