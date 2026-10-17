//go:build fixturetest

package bootstrapmaterial_test

import (
	"context"
	"os"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func TestJournalPublicationRetainsOriginalRootCall(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("this actual root-call filesystem boundary requires a root QA process")
	}
	bootstrapmaterial.ExerciseJournalPublicationRootCall(t, func(ctx context.Context) (func(context.Context) error, error) {
		call, err := rootoci.RootCall(ctx)
		return call.Guard, err
	}, rootoci.ErrUnauthorized)
}
