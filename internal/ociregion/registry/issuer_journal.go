package registry

import (
	"context"
	"net/http"

	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// IssuerJournal is the finite protected operation store. A missing whole store
// is an error; only a genuinely new key returns jetstream.ErrKeyNotFound.
// CompareAndSwap must retain all original credential operation history.
type IssuerJournal interface {
	BeginEffect(*http.Request) (func(*http.Response, error, bool) error, error)
	Load(context.Context, string) (region.OCIRIssuanceState, uint64, error)
	CompareAndSwap(context.Context, string, region.OCIRIssuanceState, uint64) (uint64, error)
}
