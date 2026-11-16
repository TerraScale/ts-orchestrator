package rootfoundation

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// ResourceAuthority is derived inside root from exact accepted config and a
// current root-signed amendment. Digests alone do not confer authority.
type ResourceAuthority struct {
	Source     ociresource.ResourceSource
	Specs      map[string]string
	PruneKinds map[string]bool
}

// ResourceStore keeps amendment operations in the existing protected own-cell
// object. It never projects foundation resources into amendment ownership.
type ResourceStore struct {
	backend      *Backend
	call         rootoci.Call
	receipt      rootoci.FoundationReceipt
	authority    ResourceAuthority
	store        region.FoundationStore
	observations interface {
		PutStatus(context.Context, ociresource.Status) error
		GetStatus(context.Context, ociresource.Key) (ociresource.Status, bool, error)
	}
}
