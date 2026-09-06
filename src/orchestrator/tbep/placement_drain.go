package tbep

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"

	"google.golang.org/grpc/metadata"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func DrainBinding(operationID string, request *pb.PlacementDrainRequest) (placementtransition.Prepared, error) {
	var prepared placementtransition.Prepared
	if !validMetadata(operationID, 128) || request == nil || len(request.PreparedTransition) == 0 || len(request.PreparedTransition) > 256<<10 {
		return prepared, errors.New("TBEP drain request is invalid")
	}
	var envelope placementtransition.Signed
	if json.Unmarshal(request.PreparedTransition, &envelope, json.RejectUnknownMembers(true)) != nil || envelope.KeyID == "" || len(envelope.Signature) != 64 || len(envelope.Payload) == 0 || json.Unmarshal(envelope.Payload, &prepared, json.RejectUnknownMembers(true)) != nil {
		return prepared, errors.New("TBEP drain prepare envelope is invalid")
	}
	if prepared.SchemaVersion != 1 || prepared.Kind != "prepared_epoch" || prepared.Request.OperationID != operationID || prepared.Request.PriorEpoch == 0 || prepared.PriorGeneration == 0 || prepared.AuthorityEpoch == 0 || prepared.JournalRevision == 0 || prepared.PreviousProofDigest == "" || prepared.LeaseID == "" {
		return prepared, errors.New("TBEP drain prepare is not bound to predecessor and operation")
	}
	digest, err := placementtransition.RequestDigest(prepared.Request)
	if err != nil || digest != prepared.RequestDigest {
		return prepared, errors.New("TBEP drain prepare request digest differs")
	}
	return prepared, nil
}
func ValidateDrainReceipt(response *pb.PlacementDrainResponse, prepared placementtransition.Prepared, memberIdentity string) error {
	if response == nil || len(response.SignedReceipt) == 0 || len(response.SignedReceipt) > 64<<10 {
		return errors.New("TBEP drain returned invalid signed receipt")
	}
	var signed placementtransition.Signed
	var receipt placementtransition.DrainReceipt
	if json.Unmarshal(response.SignedReceipt, &signed, json.RejectUnknownMembers(true)) != nil || signed.KeyID != memberIdentity || len(signed.Signature) != 64 || json.Unmarshal(signed.Payload, &receipt, json.RejectUnknownMembers(true)) != nil {
		return errors.New("TBEP drain receipt is not bound to pinned member")
	}
	if receipt.Kind != "old_epoch_drained_fenced" || receipt.MemberIdentity != memberIdentity || receipt.ScopeID != prepared.Request.ScopeID || receipt.PriorEpoch != prepared.Request.PriorEpoch || receipt.PriorGeneration != prepared.PriorGeneration || receipt.RequestDigest != prepared.RequestDigest || len(receipt.FrontierDigest) != 64 {
		return errors.New("TBEP drain receipt differs from prepared transition")
	}
	frontier, err := hex.DecodeString(receipt.FrontierDigest)
	if err != nil || len(frontier) != 32 || hex.EncodeToString(frontier) != receipt.FrontierDigest {
		return errors.New("TBEP drain frontier digest is malformed")
	}
	return nil
}
func (c *PlacementClient) Drain(ctx context.Context, operationID string, request *pb.PlacementDrainRequest) (*pb.PlacementDrainResponse, error) {
	prepared, err := DrainBinding(operationID, request)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.transport.timeout)
	defer cancel()
	scope := c.transport.scope.Copy()
	scope.Set("x-tb-idempotency-key", operationID)
	response, err := c.rpc.Drain(metadata.NewOutgoingContext(ctx, scope), request)
	if err != nil {
		return nil, err
	}
	if err := ValidateDrainReceipt(response, prepared, c.serverIdentity); err != nil {
		return nil, err
	}
	return response, nil
}
