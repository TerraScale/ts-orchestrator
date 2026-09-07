package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/placementrelocation"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// Dynamic targets come from the same fenced enrollment and OCI ownership
// journals that admitted the host. The initial two-seat topology cannot supply
// the credentials or receipt keys for a newly added survivor.
type productionRelocationTargets struct {
	connection *nats.Conn
	enrolled   func(context.Context) (enrollment.State, error)
	gateways   map[string]ocireconcile.ComputeGateway
	ownership  provider.DurableOwnershipEvidence
	Pending    placementpublisher.Journal
	plans      *placementrelocation.Journal
	admission  *databaseadmission.NATSJournal
	issuer     interface {
		Prepare(context.Context, placementtransition.Request) (placementtransition.Signed, error)
	}
	check                func(context.Context) error
	environment, cluster string
}

type productionRelocationTarget struct {
	Member       enrollment.Record
	Observed     hostremoval.MemberObservation
	Remote       *placementpublisher.RemoteTarget
	Publisher    *placementpublisher.Publisher
	ReadinessKey databaseadmission.ReadinessKey
}

func newProductionRelocationTargets(session globalWorkerSession, config productionDatabaseConfig, gateways map[string]ocireconcile.ComputeGateway, ownership provider.DurableOwnershipEvidence, pending placementpublisher.Journal, issuer interface {
	Prepare(context.Context, placementtransition.Request) (placementtransition.Signed, error)
}, admission *databaseadmission.NATSJournal) (*productionRelocationTargets, error) {
	if session.Connection == nil || config.Environment == "" || config.Cluster == "" || len(gateways) == 0 || ownership == nil || !ownership.AuthoritativeDurable() || pending == nil || issuer == nil || admission == nil {
		return nil, placementrelocation.ErrInvalid
	}
	authority := authorityjournal.Config{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId}
	enrolled, err := enrollment.NewJournal(authority)
	if err != nil {
		return nil, err
	}
	plans, err := placementrelocation.New(authority)
	if err != nil {
		return nil, err
	}
	return &productionRelocationTargets{connection: session.Connection, enrolled: enrolled.Read, gateways: gateways, ownership: ownership, Pending: pending, plans: plans, admission: admission, issuer: issuer, check: session.CheckEffectAuthority, environment: config.Environment, cluster: config.Cluster}, nil
}

func (f *productionRelocationTargets) enrolledMember(ctx context.Context, identity string, retired bool) (enrollment.Record, error) {
	if f == nil || f.enrolled == nil || f.check == nil || identity == "" {
		return enrollment.Record{}, placementrelocation.ErrInvalid
	}
	if err := f.check(ctx); err != nil {
		return enrollment.Record{}, err
	}
	state, err := f.enrolled(ctx)
	if err != nil {
		return enrollment.Record{}, err
	}
	var result enrollment.Record
	accept := func(member enrollment.Record) error {
		if enrollment.Identity(member, "member") != identity {
			return nil
		}
		if result.MemberID != "" || member.Environment != f.environment || member.Cluster != f.cluster || member.Public == nil || member.Generation == 0 || member.MemberID == "" || member.Slot < 1 || member.Retirement != nil && !retired {
			return placementrelocation.ErrConflict
		}
		result = member
		return nil
	}
	for _, member := range state.Records {
		if err := accept(member); err != nil {
			return enrollment.Record{}, err
		}
	}
	if retired {
		for _, member := range state.Retired {
			if err := accept(member); err != nil {
				return enrollment.Record{}, err
			}
		}
	}
	if result.MemberID == "" {
		return enrollment.Record{}, placementrelocation.ErrMissing
	}
	if err := f.check(ctx); err != nil {
		return enrollment.Record{}, err
	}
	return result, nil
}

// MemberKey resolves historical old-member receipts from durable enrollment,
// including retired records. Live OCI availability cannot erase a trusted key.
func (f *productionRelocationTargets) MemberKey(ctx context.Context, identity string) (ed25519.PublicKey, error) {
	member, err := f.enrolledMember(ctx, identity, true)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(member.Public.PublicKeys["receipt"])
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, placementrelocation.ErrInvalid
	}
	return ed25519.PublicKey(key), nil
}

func (f *productionRelocationTargets) Resolve(ctx context.Context, identity string) (*productionRelocationTarget, error) {
	member, err := f.enrolledMember(ctx, identity, false)
	if err != nil {
		return nil, err
	}
	gateway := f.gateways[member.Region]
	if gateway == nil || f.ownership == nil || !f.ownership.AuthoritativeDurable() {
		return nil, placementrelocation.ErrInvalid
	}
	listed, err := gateway.ListMembers(ctx)
	if err != nil {
		return nil, err
	}
	var observed hostremoval.MemberObservation
	observer := newProductionDurableMemberObserver(f.ownership, gateway)
	if observer == nil {
		return nil, placementrelocation.ErrInvalid
	}
	for _, candidate := range listed {
		if candidate.Index != member.Slot {
			continue
		}
		if observed.ResourceID != "" || candidate.ID == "" || candidate.LifecycleState != "RUNNING" {
			return nil, placementrelocation.ErrConflict
		}
		candidate.Region = member.Region
		current, err := observer(ctx, candidate)
		if err != nil {
			return nil, err
		}
		if current.Identity != identity || current.Generation != member.Generation || current.Region != member.Region || current.Slot != member.Slot || current.ResourceID != candidate.ID {
			return nil, placementrelocation.ErrConflict
		}
		observed = current
	}
	if observed.ResourceID == "" || !nkeys.IsValidPublicUserKey(member.Public.PublicKeys["placement"]) || !nkeys.IsValidPublicUserKey(member.Public.PublicKeys["database"]) {
		return nil, placementrelocation.ErrInvalid
	}
	public, err := f.MemberKey(ctx, identity)
	if err != nil {
		return nil, err
	}
	remote, err := placementpublisher.NewRemoteTarget(f.connection, identity, enrollment.Identity(member, "placement-nats"), 10*time.Second)
	if err != nil {
		return nil, err
	}
	publisher, err := placementpublisher.New(f.Pending, remote, f.check)
	if err != nil {
		return nil, err
	}
	if err := f.check(ctx); err != nil {
		return nil, err
	}
	return &productionRelocationTarget{Member: member, Observed: observed, Remote: remote, Publisher: publisher, ReadinessKey: databaseadmission.ReadinessKey{KeyID: identity, PublicKey: public}}, nil
}

func (f *productionRelocationTargets) Stage(ctx context.Context, identity, operation string, stage *pb.PlacementStageRequest) (*pb.PlacementProposalResponse, error) {
	retained, err := f.plans.Load(ctx, operation)
	if err != nil {
		return nil, err
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(stage)
	if err != nil || !slices.ContainsFunc(retained.Plan.Targets, func(t placementrelocation.Target) bool {
		return t.ServerIdentity == identity && bytes.Equal(t.Proposal, encoded)
	}) {
		return nil, placementrelocation.ErrConflict
	}
	target, err := f.Resolve(ctx, identity)
	if err != nil {
		return nil, err
	}
	if err := target.Publisher.Accept(ctx, operation, stage); err != nil {
		return nil, err
	}
	return target.Publisher.Reconcile(ctx)
}

func (f *productionRelocationTargets) Deliver(ctx context.Context, identity, operation string, revision uint64, proof placementtransition.Signed) (*pb.PlacementAcceptanceResponse, error) {
	retained, err := f.plans.Load(ctx, operation)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(retained.Accepted.Payload, proof.Payload) || !bytes.Equal(retained.Accepted.Signature, proof.Signature) || retained.Accepted.KeyID != proof.KeyID {
		return nil, placementrelocation.ErrConflict
	}
	valid := false
	for _, planned := range retained.Plan.Targets {
		if planned.ServerIdentity == identity {
			stage := newPlacementStageRequest(planned.Proposal)
			valid = stage != nil && revision == stage.ExpectedRevision+1
		}
	}
	if !valid {
		return nil, placementrelocation.ErrConflict
	}
	target, err := f.Resolve(ctx, identity)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	return target.Remote.Accept(ctx, operation, &pb.PlacementAcceptRequest{ProposalRevision: revision, Proof: encoded})
}

func (f *productionRelocationTargets) Drain(ctx context.Context, request placementtransition.Request, prior placementtransition.Proof) ([]placementtransition.Signed, error) {
	prepared, err := f.issuer.Prepare(ctx, request)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(prepared)
	if err != nil {
		return nil, err
	}
	receipts := make([]placementtransition.Signed, 0, len(prior.Request.Members))
	for _, member := range prior.Request.Members {
		target, err := f.Resolve(ctx, member.Identity)
		if err != nil {
			return nil, err
		}
		response, err := target.Remote.Drain(ctx, request.OperationID, &pb.PlacementDrainRequest{PreparedTransition: encoded})
		if err != nil {
			return nil, err
		}
		var signed placementtransition.Signed
		if response == nil || json.Unmarshal(response.SignedReceipt, &signed, json.RejectUnknownMembers(true)) != nil {
			return nil, placementrelocation.ErrInvalid
		}
		// Issue authenticates the old epoch, requested successor and final frontier.
		receipts = append(receipts, signed)
	}
	return receipts, nil
}

func (f *productionRelocationTargets) Install(ctx context.Context, plan placementrelocation.Plan) error {
	if placementrelocation.ValidatePlan(plan) != nil {
		return placementrelocation.ErrInvalid
	}
	retained, err := f.plans.Load(ctx, plan.OperationID)
	if err != nil {
		return err
	}
	want, _ := placementrelocation.Digest(plan)
	actual, _ := placementrelocation.Digest(retained.Plan)
	if want != actual {
		return placementrelocation.ErrConflict
	}
	for _, record := range plan.Records {
		for _, planned := range plan.Targets {
			if !slices.Contains(record.Request.Regions, planned.Region) {
				continue
			}
			target, err := f.Resolve(ctx, planned.ServerIdentity)
			if err != nil {
				return err
			}
			if target.Member.MemberID != planned.MemberID || strings.ToUpper(target.Member.Region) != planned.Region {
				return placementrelocation.ErrConflict
			}
			// Reuse the original admitted wrapped DEKs; generating a replacement key
			// would make the existing physical database unreadable.
			entries := make([]keylease.Entry, 0, 3)
			for _, entry := range record.Wrapped {
				if entry.Binding.Region == planned.Region {
					entries = append(entries, entry)
				}
			}
			if len(entries) != 3 {
				return placementrelocation.ErrInvalid
			}
			installTarget := databaseadmission.Target{ServerIdentity: planned.ServerIdentity, MemberID: planned.MemberID, Region: planned.Region}
			if err := f.check(ctx); err != nil {
				return err
			}
			if err := databaseadmission.RemoteInstall(f.connection)(ctx, record, installTarget, entries); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *productionRelocationTargets) Ready(ctx context.Context, operation string, records []databaseadmission.Record) ([]databaseadmission.Record, error) {
	result := slices.Clone(records)
	for i, record := range result {
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		nonce := hex.EncodeToString(random[:])
		keys := make(map[string]databaseadmission.ReadinessKey, len(record.Targets))
		receipts := make([]databaseadmission.SignedReadiness, 0, len(record.Targets))
		for _, member := range record.Targets {
			target, err := f.Resolve(ctx, member.ServerIdentity)
			if err != nil {
				return nil, err
			}
			response, err := target.Remote.Readiness(ctx, &pb.PlacementReadinessRequest{Tenant: record.Request.TenantID, Project: record.Request.ProjectID, Database: record.DatabaseID, OperationId: operation, Nonce: nonce})
			if err != nil {
				return nil, err
			}
			if tbep.ValidateReadinessEnvelope(response) != nil {
				return nil, placementrelocation.ErrInvalid
			}
			var signed databaseadmission.SignedReadiness
			if json.Unmarshal(response.SignedReceipt, &signed, json.RejectUnknownMembers(true)) != nil {
				return nil, placementrelocation.ErrInvalid
			}
			keys[member.ServerIdentity] = target.ReadinessKey
			receipts = append(receipts, signed)
		}
		if err := databaseadmission.ValidateRelocationReadiness(record, operation, receipts, nonce, keys, time.Now().UTC()); err != nil {
			return nil, err
		}
		result[i].ReadinessNonce, result[i].ReadyEvidence, result[i].State = nonce, receipts, "ready"
	}
	if err := f.check(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func (f *productionRelocationTargets) Usage(ctx context.Context, operation string, records []databaseadmission.Record) error {
	if operation == "" || len(records) == 0 {
		return placementrelocation.ErrInvalid
	}
	_, resources, err := f.admission.LifecycleResources(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		if len(record.PlacementTargets) == 0 {
			return placementrelocation.ErrInvalid
		}
		deliveries, err := planDatabaseUsage(record, records, resources, record.PlacementTargets[0].AcceptedProofDigest, time.Now().UTC())
		if err != nil {
			return err
		}
		for _, delivery := range deliveries {
			if _, err := f.Resolve(ctx, delivery.Target.ServerIdentity); err != nil {
				return err
			}
			if err := databaseadmission.RemoteUsageRegistration(f.connection)(ctx, delivery.Target, delivery.Registration); err != nil {
				return err
			}
		}
	}
	return f.check(ctx)
}
