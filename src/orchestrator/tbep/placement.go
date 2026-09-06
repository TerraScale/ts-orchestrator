package tbep

import (
	"cmp"
	"context"
	"errors"
	"slices"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// PlacementClient stages host-local pending control intent. A receipt never
// establishes catch-up, accepted membership, writer authority, or readiness.
type PlacementClient struct {
	transport      *Client
	rpc            pb.PlacementControlServiceClient
	serverIdentity string
}

func NewPlacement(config Config) (*PlacementClient, error) {
	if config.Tenant != "" || config.Project != "" || config.Database != "" {
		return nil, errors.New("TBEP placement requires host scope without database metadata")
	}
	transport, err := newClient(config, false)
	if err != nil {
		return nil, err
	}
	return &PlacementClient{transport: transport, rpc: pb.NewPlacementControlServiceClient(transport.conn), serverIdentity: config.ServerIdentity}, nil
}
func (c *PlacementClient) Close() error           { return c.transport.Close() }
func (c *PlacementClient) Principal() string      { return c.transport.principal }
func (c *PlacementClient) ServerIdentity() string { return c.serverIdentity }

// CanonicalPlacement clones and orders a bounded proposal without mutating the
// caller. Empty assignments permit explicitly authorized empty-cluster bootstrap;
// they do not imply genesis. The producer validates identities, residency and roles.
func CanonicalPlacement(proposal *pb.PlacementProposal) (*pb.PlacementProposal, error) {
	if proposal == nil || proposal.Environment == "" || proposal.Cluster == "" || proposal.Generation == 0 || proposal.Epoch == 0 || len(proposal.Regions) < 1 || len(proposal.Regions) > 3 || len(proposal.Assignments) > 1024 || proto.Size(proposal) > 480<<10 {
		return nil, errors.New("TBEP placement proposal is incomplete or exceeds bounds")
	}
	result := proto.Clone(proposal).(*pb.PlacementProposal)
	for _, region := range result.Regions {
		if region == nil || len(region.Members) != 2 {
			return nil, errors.New("TBEP placement requires two seats per region")
		}
		slices.Sort(region.Members)
	}
	for _, assignment := range result.Assignments {
		if assignment == nil {
			return nil, errors.New("TBEP placement assignment is missing")
		}
	}
	slices.SortFunc(result.Regions, func(a, b *pb.PlacementRegionSeats) int { return cmp.Compare(a.Region, b.Region) })
	slices.SortFunc(result.Assignments, func(a, b *pb.PlacementDatabaseAssignment) int {
		return cmp.Or(cmp.Compare(a.Tenant, b.Tenant), cmp.Compare(a.Project, b.Project), cmp.Compare(a.Database, b.Database), cmp.Compare(a.Region, b.Region))
	})
	return result, nil
}

// Stage sends once. After any unknown outcome the durable publisher must reuse
// the same operation ID, expected revision and canonical proposal.
func (c *PlacementClient) Stage(ctx context.Context, operationID string, request *pb.PlacementStageRequest) (*pb.PlacementProposalResponse, error) {
	if !validMetadata(operationID, 128) || request == nil {
		return nil, errors.New("TBEP placement operation identity and request required")
	}
	proposal, err := CanonicalPlacement(request.Proposal)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.transport.timeout)
	defer cancel()
	scope := c.transport.scope.Copy()
	scope.Set("x-tb-idempotency-key", operationID)
	ctx = metadata.NewOutgoingContext(ctx, scope)
	response, err := c.rpc.Stage(ctx, &pb.PlacementStageRequest{ExpectedRevision: request.ExpectedRevision, Proposal: proposal})
	if err != nil {
		return nil, err
	}
	if response.GetRevision() != request.ExpectedRevision+1 || request.ExpectedRevision == ^uint64(0) {
		return nil, errors.New("TBEP placement receipt revision differs from requested transition")
	}
	if err := ValidatePlacementReceipt(response, proposal); err != nil {
		return nil, err
	}
	return response, nil
}

func ValidatePlacementReceipt(response *pb.PlacementProposalResponse, proposal *pb.PlacementProposal) error {
	if response == nil || response.Revision == 0 || response.Status != pb.PlacementProposalStatus_PLACEMENT_PROPOSAL_STATUS_PENDING {
		return errors.New("TBEP placement returned invalid pending receipt")
	}
	actual, err := CanonicalPlacement(response.Proposal)
	if err != nil {
		return err
	}
	expected, err := CanonicalPlacement(proposal)
	if err != nil {
		return err
	}
	if !proto.Equal(actual, expected) {
		return errors.New("TBEP placement receipt differs from durable intent")
	}
	return nil
}

func ValidatePlacementGetResponse(response *pb.PlacementProposalResponse) error {
	if response == nil || response.Revision == 0 || response.Status != pb.PlacementProposalStatus_PLACEMENT_PROPOSAL_STATUS_PENDING {
		return errors.New("TBEP placement returned invalid pending response")
	}
	_, err := CanonicalPlacement(response.Proposal)
	return err
}

// Get observes only the latest pending proposal; it cannot resolve a historic
// operation after a later proposal. Stage's idempotent receipt resolves retries.
func (c *PlacementClient) Get(ctx context.Context) (*pb.PlacementProposalResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.transport.timeout)
	defer cancel()
	response, err := c.rpc.Get(metadata.NewOutgoingContext(ctx, c.transport.scope.Copy()), &pb.PlacementGetRequest{})
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("TBEP placement returned empty response")
	}
	if err := ValidatePlacementGetResponse(response); err != nil {
		return nil, err
	}
	return response, nil
}
