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
	"errors"
	"sync/atomic"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestGoBuildUnitsShareDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	units := make([]goBuildUnit, maxGoBuildLoads+1)
	var calls atomic.Int32
	started := make(chan struct{}, maxGoBuildLoads)
	done := make(chan error, 1)
	go func() {
		_, err := runGoBuildUnitsWith(
			ctx, units,
			func(config *packages.Config, _ ...string) ([]*packages.Package, error) {
				calls.Add(1)
				started <- struct{}{}
				<-config.Context.Done()
				return nil, config.Context.Err()
			},
		)
		done <- err
	}()
	for range maxGoBuildLoads {
		<-started
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("load error = %v, want cancellation", err)
	}
	if got := calls.Load(); got != int32(maxGoBuildLoads) {
		t.Fatalf("package loads = %d, want %d", got, maxGoBuildLoads)
	}
}

func TestGoBuildUnitsCancelQueuedLoads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, maxGoBuildLoads+1)
	done := make(chan error, 1)
	units := make([]goBuildUnit, maxGoBuildLoads+1)
	go func() {
		_, err := runGoBuildUnitsWith(
			ctx,
			units,
			func(config *packages.Config, _ ...string) ([]*packages.Package, error) {
				started <- struct{}{}
				<-config.Context.Done()
				return nil, config.Context.Err()
			},
		)
		done <- err
	}()
	for range maxGoBuildLoads {
		<-started
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("load error = %v, want cancellation", err)
	}
	select {
	case <-started:
		t.Fatal("queued package load started after cancellation")
	default:
	}
}
