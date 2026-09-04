package main

import (
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/estatepublisher"
)

// newEstatePublisher is the single command-level composition seam for I-11.
// The parent runtime supplies the ordinary public document client, one
// coherent estate snapshot source, and the live control-plane authority
// fence. No environment lookup, transport, or fallback source is hidden here.
func newEstatePublisher(
	client estatepublisher.PublicDocumentClient,
	snapshot estatepublisher.SnapshotSource,
	authority estatepublisher.Authority,
) (*estatepublisher.Publisher, error) {
	if client == nil {
		return nil, errors.New("orchestrator: estate publisher client is required")
	}
	if snapshot == nil {
		return nil, errors.New("orchestrator: estate publisher snapshot is required")
	}
	if authority == nil {
		return nil, errors.New("orchestrator: estate publisher authority is required")
	}
	return estatepublisher.NewProductionPublisher(estatepublisher.Config{
		Client:    client,
		Snapshot:  snapshot,
		Authority: authority,
	})
}
