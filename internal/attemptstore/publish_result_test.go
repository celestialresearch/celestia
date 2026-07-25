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

package attemptstore

import (
	"errors"
	"testing"
)

func TestPublishResultDistinguishesReleaseFailure(t *testing.T) {
	publicationErr := errors.New("publication")
	releaseErr := errors.New("release")
	if err := publishResult(nil, nil); err != nil {
		t.Fatalf("successful publication failed: %v", err)
	}
	if err := publishResult(publicationErr, nil); !errors.Is(err, publicationErr) {
		t.Fatalf("publication failure lost: %v", err)
	}
	if err := publishResult(nil, releaseErr); !errors.Is(err, ErrRelease) {
		t.Fatalf("release failure not classified: %v", err)
	}
	err := publishResult(publicationErr, releaseErr)
	if !errors.Is(err, publicationErr) || errors.Is(err, ErrRelease) {
		t.Fatalf("combined failure lost: %v", err)
	}
}
