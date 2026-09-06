package authbootstrap

import (
	"context"
	"encoding/json/v2"
	"errors"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type Record struct {
	Request  []byte
	Receipts map[string][]byte
}
type State struct{ Groups map[string]Record }
type Journal struct {
	durable *authorityjournal.Journal[State]
}

func NewJournal(config authorityjournal.Config) (*Journal, error) {
	config.StateKey = "auth.bootstrap"
	durable, err := authorityjournal.New(config, func() State { return State{Groups: map[string]Record{}} }, func(state State) error {
		if state.Groups == nil || len(state.Groups) > 32 {
			return ErrInvalid
		}
		for key, record := range state.Groups {
			request, err := decode(record)
			if err != nil || request.Grant.GroupId != key {
				return ErrInvalid
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Journal{durable}, nil
}
func decode(record Record) (*pb.AuthGroupBootstrapServiceBootstrapRequest, error) {
	if len(record.Request) == 0 || len(record.Request) > 32<<10 || record.Receipts == nil {
		return nil, ErrInvalid
	}
	request := new(pb.AuthGroupBootstrapServiceBootstrapRequest)
	if proto.Unmarshal(record.Request, request) != nil || !validID(request.OperationId) {
		return nil, ErrInvalid
	}
	grant, err := CanonicalGrant(request.Grant, false)
	if err != nil || !proto.Equal(grant, request.Grant) {
		return nil, ErrInvalid
	}
	for target, data := range record.Receipts {
		receipt := new(pb.AuthGroupBootstrapServiceBootstrapResponse)
		if proto.Unmarshal(data, receipt) != nil || ValidateReceipt(receipt, request, target) != nil {
			return nil, ErrInvalid
		}
	}
	return request, nil
}
func (journal *Journal) Load(ctx context.Context, groupID string) (record Record, err error) {
	err = journal.durable.Transact(ctx, false, func(state *State) error {
		var found bool
		record, found = state.Groups[groupID]
		if !found {
			return ErrMissing
		}
		_, err := decode(record)
		return err
	})
	return
}

// Accept binds the full grant once. Even an acknowledged grant can never be
// replaced: disk loss must use recovery, never another genesis incarnation.
func (journal *Journal) Accept(ctx context.Context, grant *pb.AuthGroupBootstrapGrant) error {
	canonical, err := CanonicalGrant(grant, true)
	if err != nil {
		return err
	}
	for _, v := range canonical.Voters {
		if !validIncarnation(v.StorageIncarnation) {
			return ErrInvalid
		}
	}
	if canonical.AuthorityRevision != 0 {
		return ErrInvalid
	}
	return journal.durable.TransactRevision(ctx, true, func(state *State, revision uint64) error {
		if old, ok := state.Groups[canonical.GroupId]; ok {
			request, err := decode(old)
			if err != nil {
				return err
			}
			candidate := proto.Clone(canonical).(*pb.AuthGroupBootstrapGrant)
			candidate.AuthorityRevision = request.Grant.AuthorityRevision
			if !proto.Equal(candidate, request.Grant) {
				return ErrConflict
			}
			return nil
		}
		if len(state.Groups) >= 32 {
			return ErrConflict
		}
		for _, old := range state.Groups {
			request, err := decode(old)
			if err != nil {
				return err
			}
			if request.Grant.Environment == canonical.Environment && request.Grant.Cluster == canonical.Cluster && request.Grant.Tenant == canonical.Tenant && request.Grant.Project == canonical.Project && request.Grant.Database == canonical.Database {
				return ErrConflict
			}
		}
		candidate := proto.Clone(canonical).(*pb.AuthGroupBootstrapGrant)
		candidate.AuthorityRevision = revision
		request := &pb.AuthGroupBootstrapServiceBootstrapRequest{OperationId: candidate.GroupId, Grant: candidate}
		data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request)
		if err != nil {
			return err
		}
		state.Groups[candidate.GroupId] = Record{Request: data, Receipts: map[string][]byte{}}
		// Every accepted grant reserves enough room for all full-echo receipts.
		reserved := State{Groups: map[string]Record{}}
		for key, record := range state.Groups {
			req, err := decode(record)
			if err != nil {
				return err
			}
			copyRecord := Record{Request: record.Request, Receipts: map[string][]byte{}}
			for _, v := range req.Grant.Voters {
				copyRecord.Receipts[v.SpiffeUri] = make([]byte, len(record.Request)+256)
			}
			reserved.Groups[key] = copyRecord
		}
		encoded, err := json.Marshal(reserved)
		if err != nil || len(encoded) > authorityjournal.MaximumStateBytes {
			return ErrInvalid
		}
		return nil
	})
}
func (journal *Journal) Acknowledge(ctx context.Context, request *pb.AuthGroupBootstrapServiceBootstrapRequest, target string, receipt *pb.AuthGroupBootstrapServiceBootstrapResponse) error {
	if err := ValidateReceipt(receipt, request, target); err != nil {
		return err
	}
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(receipt)
	if err != nil {
		return err
	}
	return journal.durable.Transact(ctx, true, func(state *State) error {
		record, ok := state.Groups[request.Grant.GroupId]
		if !ok {
			return ErrMissing
		}
		actual, err := decode(record)
		if err != nil {
			return err
		}
		if !proto.Equal(actual, request) {
			return ErrConflict
		}
		if old, ok := record.Receipts[target]; ok {
			prior := new(pb.AuthGroupBootstrapServiceBootstrapResponse)
			if proto.Unmarshal(old, prior) != nil || !proto.Equal(prior, receipt) {
				return ErrConflict
			}
			return nil
		}
		record.Receipts[target] = data
		state.Groups[request.Grant.GroupId] = record
		return nil
	})
}

type Durable interface {
	Load(context.Context, string) (Record, error)
	Accept(context.Context, *pb.AuthGroupBootstrapGrant) error
	Acknowledge(context.Context, *pb.AuthGroupBootstrapServiceBootstrapRequest, string, *pb.AuthGroupBootstrapServiceBootstrapResponse) error
}
type Target interface {
	Principal() string
	ServerIdentity() string
	Identity(context.Context) (*pb.AuthGroupBootstrapServiceIdentityResponse, error)
	Bootstrap(context.Context, *pb.AuthGroupBootstrapServiceBootstrapRequest) (*pb.AuthGroupBootstrapServiceBootstrapResponse, error)
}
type Service struct {
	journal Durable
	targets map[string]Target
	check   func(context.Context) error
}

func New(journal Durable, targets []Target, check func(context.Context) error) (*Service, error) {
	if journal == nil || len(targets) == 0 || check == nil {
		return nil, ErrInvalid
	}
	result := &Service{journal: journal, targets: map[string]Target{}, check: check}
	for _, target := range targets {
		if target == nil || !validIdentity(target.Principal()) || !validIdentity(target.ServerIdentity()) || result.targets[target.ServerIdentity()] != nil {
			return nil, ErrInvalid
		}
		result.targets[target.ServerIdentity()] = target
	}
	return result, nil
}

// Reconcile discovers incarnations only while no grant exists. All retries and
// restarts replay the accepted request, including after an RPC outcome is lost.
func (service *Service) Reconcile(ctx context.Context, template *pb.AuthGroupBootstrapGrant) error {
	canonical, err := CanonicalGrant(template, true)
	if err != nil || canonical.AuthorityRevision != 0 {
		return ErrInvalid
	}
	for _, v := range canonical.Voters {
		if service.targets[v.SpiffeUri] == nil {
			return ErrInvalid
		}
	}
	record, err := service.journal.Load(ctx, canonical.GroupId)
	if errors.Is(err, ErrMissing) {
		if err := service.check(ctx); err != nil {
			return err
		}
		for _, v := range canonical.Voters {
			identity, err := service.targets[v.SpiffeUri].Identity(ctx)
			if err != nil {
				return err
			}
			if identity == nil || identity.Environment != canonical.Environment || identity.Cluster != canonical.Cluster || identity.Member != v.Member || !validIncarnation(identity.StorageIncarnation) || (v.StorageIncarnation != "" && v.StorageIncarnation != identity.StorageIncarnation) {
				return ErrConflict
			}
			v.StorageIncarnation = identity.StorageIncarnation
		}
		if err := service.check(ctx); err != nil {
			return err
		}
		if err := service.journal.Accept(ctx, canonical); err != nil {
			return err
		}
		record, err = service.journal.Load(ctx, canonical.GroupId)
	}
	if err != nil {
		return err
	}
	request, err := decode(record)
	if err != nil {
		return err
	}
	if !sameTemplate(request.Grant, canonical) {
		return ErrConflict
	}
	var failures []error
	for _, v := range request.Grant.Voters {
		if _, done := record.Receipts[v.SpiffeUri]; done {
			continue
		}
		if err := service.check(ctx); err != nil {
			return err
		}
		receipt, err := service.targets[v.SpiffeUri].Bootstrap(ctx, request)
		if err == nil {
			err = service.journal.Acknowledge(ctx, request, v.SpiffeUri, receipt)
		}
		if errors.Is(err, authorityjournal.ErrFenced) {
			return err
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
