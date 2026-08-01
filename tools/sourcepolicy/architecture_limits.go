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
	"time"
)

const (
	maxArchitectureInputBytes = 16 << 20
	maxArchitectureDuration   = 30 * time.Second
)

type architectureReadBudget struct {
	read      func(string) ([]byte, error)
	now       func() time.Time
	deadline  time.Time
	remaining int
}

func newArchitectureReadBudget(
	read func(string) ([]byte, error),
	now func() time.Time,
) *architectureReadBudget {
	return &architectureReadBudget{
		read: read, now: now, deadline: now().Add(maxArchitectureDuration),
		remaining: maxArchitectureInputBytes,
	}
}

func (budget *architectureReadBudget) readFile(name string) ([]byte, error) {
	if err := budget.checkDeadline(); err != nil {
		return nil, err
	}
	data, err := budget.read(name)
	if err != nil {
		return nil, err
	}
	if len(data) > budget.remaining {
		return nil, errors.New("architecture input exceeds its aggregate size bound")
	}
	budget.remaining -= len(data)
	if err := budget.checkDeadline(); err != nil {
		return nil, err
	}
	return data, nil
}

func (budget *architectureReadBudget) checkDeadline() error {
	if !budget.now().Before(budget.deadline) {
		return errors.New("architecture evaluation deadline exceeded")
	}
	return nil
}
