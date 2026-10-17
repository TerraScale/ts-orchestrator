package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// CapacityPoolCells describes authenticated home RPC subscription scope only.
// Every mutation still requires the independent original pool lifecycle proof;
// this list conveys neither purchase, membership nor deletion authority.
func (r FoundationResolver) CapacityPoolCells(ctx context.Context) ([]string, error) {
	reader, ok := r.Footprint.(*SignedFootprint)
	if !ok || reader == nil || reader.factory == nil {
		return nil, errors.New("pool routing requires the original signed home SDK source")
	}
	if _, err := r.ProtectedCapacityStore(reader.factory); err != nil {
		return nil, err
	}
	wire, err := reader.readGrant(ctx)
	if err != nil {
		return nil, err
	}
	_, expires, err := reader.verifyGrant(wire)
	if err != nil {
		return nil, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return nil, err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	if len(grant.WorkerProfiles) == 0 || len(grant.WorkerProfiles) > 512 {
		return nil, errors.New("pool routing lacks bounded signed managed-worker scope")
	}
	var cells []string
	for _, profile := range grant.WorkerProfiles {
		if err := ValidateWorkerProfile(grant, profile); err != nil {
			return nil, err
		}
		cells = append(cells, profile.Cell)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !time.Now().Before(expires) {
		return nil, errors.New("pool routing source expired during observation")
	}
	slices.Sort(cells)
	return slices.Compact(cells), nil
}
