// Package placementpublisher delivers durable placement control intent to each
// host. Engine pending receipts never grant serving or writer authority.
package placementpublisher

import (
	"bytes"
	"context"
	"errors"
	"net/url"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

var (
	ErrInvalidConfig        = errors.New("placement publisher: invalid configuration or intent")
	ErrPlacementEpochFenced = errors.New("placement publisher: global authority fenced")
	ErrIntentMissing        = errors.New("placement publisher: accepted intent missing")
)

// Record is bounded control metadata. Request and Receipt hold producer protobuf
// bytes, never customer documents. An empty Receipt means an unresolved outcome.
type Record struct {
	OperationID    string
	ServerIdentity string
	Principal      string
	Request        []byte
	Receipt        []byte
}

func validToken(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func validIdentity(value string) bool {
	if !validToken(value) {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "spiffe" && u.Host != "" && u.Hostname() == u.Host && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.RawPath == "" && u.Path != "" && u.String() == value
}

func NewRecord(operationID, serverIdentity, principal string, request *pb.PlacementStageRequest) (Record, error) {
	if !validToken(operationID) || !validIdentity(serverIdentity) || !validIdentity(principal) || request == nil {
		return Record{}, ErrInvalidConfig
	}
	proposal, err := tbep.CanonicalPlacement(request.Proposal)
	if err != nil {
		return Record{}, err
	}
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&pb.PlacementStageRequest{ExpectedRevision: request.ExpectedRevision, Proposal: proposal})
	if err != nil {
		return Record{}, err
	}
	return Record{OperationID: operationID, ServerIdentity: serverIdentity, Principal: principal, Request: data}, nil
}
func decodeRecord(record Record) (*pb.PlacementStageRequest, error) {
	if len(record.Request) == 0 || len(record.Request) > 480<<10 || len(record.Receipt) > 512<<10 {
		return nil, ErrInvalidConfig
	}
	request := new(pb.PlacementStageRequest)
	if proto.Unmarshal(record.Request, request) != nil {
		return nil, ErrInvalidConfig
	}
	canonical, err := NewRecord(record.OperationID, record.ServerIdentity, record.Principal, request)
	if err != nil || !bytes.Equal(canonical.Request, record.Request) {
		return nil, ErrInvalidConfig
	}
	if len(record.Receipt) > 0 {
		receipt := new(pb.PlacementProposalResponse)
		if proto.Unmarshal(record.Receipt, receipt) != nil || tbep.ValidatePlacementReceipt(receipt, request.Proposal) != nil {
			return nil, ErrInvalidConfig
		}
	}
	return request, nil
}
func sameIntent(a, b Record) bool {
	return a.OperationID == b.OperationID && a.ServerIdentity == b.ServerIdentity && a.Principal == b.Principal && bytes.Equal(a.Request, b.Request)
}

// Journal mutations must be fenced atomically against global authority. Read
// must return the latest committed state, not an eventually consistent cache.
type Journal interface {
	Accept(context.Context, Record) error
	Load(context.Context, string) (Record, error)
	Acknowledge(context.Context, Record, *pb.PlacementProposalResponse) error
}
type Target interface {
	Stage(context.Context, string, *pb.PlacementStageRequest) (*pb.PlacementProposalResponse, error)
	Principal() string
	ServerIdentity() string
}
type Publisher struct {
	journal Journal
	target  Target
	check   func(context.Context) error
}

func New(journal Journal, target Target, checkEffectAuthority func(context.Context) error) (*Publisher, error) {
	if journal == nil || target == nil || checkEffectAuthority == nil || !validIdentity(target.Principal()) || !validIdentity(target.ServerIdentity()) {
		return nil, ErrInvalidConfig
	}
	return &Publisher{journal: journal, target: target, check: checkEffectAuthority}, nil
}

// Accept persists the exact target and request before any RPC. The authority
// owner must validate the requested placement/residency policy before calling.
func (p *Publisher) Accept(ctx context.Context, operationID string, request *pb.PlacementStageRequest) error {
	record, err := NewRecord(operationID, p.target.ServerIdentity(), p.target.Principal(), request)
	if err != nil {
		return err
	}
	if err := p.check(ctx); err != nil {
		return err
	}
	return p.journal.Accept(ctx, record)
}

// Reconcile resolves the accepted operation, including after a process restart.
// Failure leaves the exact request retryable. It never increments a revision,
// chooses a new operation ID, or treats a newer Get head as an old receipt.
func (p *Publisher) Reconcile(ctx context.Context) (*pb.PlacementProposalResponse, error) {
	record, err := p.journal.Load(ctx, p.target.ServerIdentity())
	if err != nil {
		return nil, err
	}
	request, err := decodeRecord(record)
	if err != nil {
		return nil, err
	}
	if record.Principal != p.target.Principal() || record.ServerIdentity != p.target.ServerIdentity() {
		return nil, ErrInvalidConfig
	}
	if len(record.Receipt) > 0 {
		result := new(pb.PlacementProposalResponse)
		if proto.Unmarshal(record.Receipt, result) != nil {
			return nil, ErrInvalidConfig
		}
		return result, nil
	}
	if err := p.check(ctx); err != nil {
		return nil, err
	}
	result, err := p.target.Stage(ctx, record.OperationID, request)
	if err != nil {
		return nil, err
	}
	if err := tbep.ValidatePlacementReceipt(result, request.Proposal); err != nil {
		return nil, err
	}
	if err := p.journal.Acknowledge(ctx, record, result); err != nil {
		return nil, err
	}
	return result, nil
}
