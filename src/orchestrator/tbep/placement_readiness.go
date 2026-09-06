package tbep

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"

	"google.golang.org/grpc/metadata"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func ValidateReadinessRequest(request *pb.PlacementControlServiceReadinessRequest) error {
	if request == nil || !validMetadata(request.OperationId, 128) || !validMetadata(request.Tenant, 64) || !validMetadata(request.Project, 64) || !validMetadata(request.Database, 64) {
		return errors.New("TBEP readiness requires exact operation and database scope")
	}
	nonce, err := hex.DecodeString(request.Nonce)
	if err != nil || len(nonce) != 32 || strings.ToLower(request.Nonce) != request.Nonce {
		return errors.New("TBEP readiness requires a fresh 32-byte hex challenge")
	}
	return nil
}

// ValidateReadinessEnvelope bounds only the transport envelope. The provisioning
// owner verifies the member signature and exact tuple, nonce, frontier, physical
// checkpoint and causal cut across all required members before declaring ready.
func ValidateReadinessEnvelope(response *pb.PlacementControlServiceReadinessResponse) error {
	if response == nil || len(response.SignedReceipt) == 0 || len(response.SignedReceipt) > 64<<10 {
		return errors.New("TBEP readiness returned no bounded signed evidence")
	}
	var envelope struct {
		KeyID     string `json:"key_id"`
		Payload   []byte `json:"payload"`
		Signature []byte `json:"signature"`
	}
	if json.Unmarshal(response.SignedReceipt, &envelope, json.RejectUnknownMembers(true)) != nil || !validMetadata(envelope.KeyID, 256) || len(envelope.Payload) == 0 || len(envelope.Payload) > 32<<10 || len(envelope.Signature) != 64 {
		return errors.New("TBEP readiness signature envelope invalid")
	}
	return nil
}
func (c *PlacementClient) Readiness(ctx context.Context, request *pb.PlacementControlServiceReadinessRequest) (*pb.PlacementControlServiceReadinessResponse, error) {
	if err := ValidateReadinessRequest(request); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.transport.timeout)
	defer cancel()
	response, err := c.rpc.Readiness(metadata.NewOutgoingContext(ctx, c.transport.scope.Copy()), request)
	if err != nil {
		return nil, err
	}
	if err := ValidateReadinessEnvelope(response); err != nil {
		return nil, err
	}
	return response, nil
}
