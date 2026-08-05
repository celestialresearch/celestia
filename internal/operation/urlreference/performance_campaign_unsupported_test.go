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

//go:build !windows || (windows && !amd64)

package urloperation

import (
	"errors"
	"os"
	"testing"

	"celestia.research/celestia/internal/execution/supervision"
)

const performanceReportEnvironment = "CELESTIA_OPERATION_PERFORMANCE_REPORT"

func TestOperationPerformanceCampaign(t *testing.T) {
	if os.Getenv(performanceReportEnvironment) == "" {
		t.Skipf("set %s to test unsupported campaign refusal", performanceReportEnvironment)
	}
	if _, err := New("C:/worker.exe", "C:/evidence"); !errors.Is(err, supervision.ErrUnavailable) {
		t.Fatalf("operation constructor error=%v", err)
	}
	t.Fatal("operation performance campaign requires windows/amd64")
}
