package tbep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"

	"google.golang.org/grpc/metadata"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// AcceptanceBinding validates request identity and extracts an expected receipt.
// It does not verify the grant signature or grant membership: the issuer's
// durable journal and the engine's independently pinned verifier own authority.
func AcceptanceBinding(operationID string, request *pb.PlacementControlServiceAcceptRequest) (*pb.PlacementControlServiceAcceptResponse, error) {
	if !validMetadata(operationID, 128) || request == nil || request.ProposalRevision == 0 || len(request.Proof) == 0 || len(request.Proof) > 256<<10 {
		return nil, errors.New("TBEP accepted placement request is incomplete or exceeds bounds")
	}
	var signed placementtransition.Signed
	if json.Unmarshal(request.Proof, &signed, json.RejectUnknownMembers(true)) != nil || signed.KeyID == "" || len(signed.Signature) != 64 || len(signed.Payload) == 0 {
		return nil, errors.New("TBEP accepted placement proof envelope is malformed")
	}
	var proof placementtransition.Proof
	if json.Unmarshal(signed.Payload, &proof, json.RejectUnknownMembers(true)) != nil || proof.SchemaVersion != 1 || proof.Kind != "accepted_epoch" || proof.Request.OperationID != operationID || proof.Request.Epoch == 0 || proof.Request.Generation == 0 || proof.AuthorityEpoch == 0 || proof.JournalRevision == 0 {
		return nil, errors.New("TBEP accepted placement proof does not bind the operation")
	}
	sum := sha256.Sum256(signed.Payload)
	return &pb.PlacementControlServiceAcceptResponse{ProposalRevision: request.ProposalRevision, Epoch: proof.Request.Epoch, Generation: proof.Request.Generation, ProofDigest: hex.EncodeToString(sum[:]), Status: pb.PlacementAcceptanceStatus_PLACEMENT_ACCEPTANCE_STATUS_ADMITTED_CATCHING_UP}, nil
}
func ValidateAcceptanceReceipt(response, expected *pb.PlacementControlServiceAcceptResponse) error {
	if response == nil || expected == nil || response.ProposalRevision != expected.ProposalRevision || response.Epoch != expected.Epoch || response.Generation != expected.Generation || response.ProofDigest != expected.ProofDigest || response.Status != pb.PlacementAcceptanceStatus_PLACEMENT_ACCEPTANCE_STATUS_ADMITTED_CATCHING_UP {
		return errors.New("TBEP accepted placement receipt differs from issued proof")
	}
	return nil
}

// Accept sends a durably issued proof once using its embedded operation ID.
// Unknown outcomes must retry these exact bytes and revision. A receipt permits
// catch-up only; it never establishes physical or causal data readiness.
func (c *PlacementClient) Accept(ctx context.Context, operationID string, request *pb.PlacementControlServiceAcceptRequest) (*pb.PlacementControlServiceAcceptResponse, error) {
	expected, err := AcceptanceBinding(operationID, request)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.transport.timeout)
	defer cancel()
	scope := c.transport.scope.Copy()
	scope.Set("x-tb-idempotency-key", operationID)
	response, err := c.rpc.Accept(metadata.NewOutgoingContext(ctx, scope), request)
	if err != nil {
		return nil, err
	}
	if err := ValidateAcceptanceReceipt(response, expected); err != nil {
		return nil, err
	}
	return response, nil
}
func (c *PlacementClient) GetAccepted(ctx context.Context) (*pb.PlacementControlServiceGetAcceptedResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.transport.timeout)
	defer cancel()
	response, err := c.rpc.GetAccepted(metadata.NewOutgoingContext(ctx, c.transport.scope.Copy()), &pb.PlacementControlServiceGetAcceptedRequest{})
	if err != nil {
		return nil, err
	}
	if response == nil || response.ProposalRevision == 0 || response.Generation == 0 || response.Epoch == 0 || response.Status != pb.PlacementAcceptanceStatus_PLACEMENT_ACCEPTANCE_STATUS_ADMITTED_CATCHING_UP {
		return nil, errors.New("TBEP returned invalid accepted placement observation")
	}
	digest, err := hex.DecodeString(response.ProofDigest)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != response.ProofDigest {
		return nil, errors.New("TBEP returned invalid accepted proof digest")
	}
	return response, nil
}
