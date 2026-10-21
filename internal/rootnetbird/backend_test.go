package rootnetbird

import (
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func TestNetBirdBackendRejectsUnsupervisedCaller(t *testing.T) {
	backend := &Backend{factory: new(ociclient.Factory)}
	request := rootoci.NetBirdIntentRequest{Cell: "GRU", IntentRevision: 123,
		OperationID: entityid.New(), RuntimeID: entityid.New(), OwnerID: entityid.New(), Epoch: 1,
		LeaseRevision: 122, ExpiresAt: time.Now().Add(time.Minute)}
	// Plausible caller claims cannot create the privately supervised Call.
	if _, err := backend.AuthorizeNetBirdIntent(t.Context(), rootoci.Call{}, request); !errors.Is(err, rootoci.ErrUnauthorized) {
		t.Fatalf("unsupervised source request = %v", err)
	}
	request.IntentRevision = 0
	if _, err := backend.AuthorizeNetBirdIntent(t.Context(), rootoci.Call{}, request); !errors.Is(err, rootoci.ErrUnauthorized) {
		t.Fatalf("unsupervised preparation = %v", err)
	}
	if err := backend.Bind(Sources{}); !errors.Is(err, rootoci.ErrUnauthorized) {
		t.Fatalf("empty source binding = %v", err)
	}
	if _, err := New(nil); !errors.Is(err, rootoci.ErrUnauthorized) {
		t.Fatalf("ambient constructor = %v", err)
	}
}
