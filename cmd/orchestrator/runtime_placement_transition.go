package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type productionPlacementTransitionFile struct {
	ProofKeyID      string                                `json:"proof_key_id"`
	ProofKeyFile    string                                `json:"proof_key_file"`
	GenesisKeyFiles map[string]string                     `json:"genesis_key_files"`
	MemberKeyFiles  map[string]string                     `json:"member_key_files"`
	GenesisGrants   map[string]placementtransition.Signed `json:"genesis_grants"`
	Bootstrap       *productionPlacementBootstrap         `json:"bootstrap"`
}
type productionPlacementBootstrap struct {
	OperationID string                               `json:"operation_id"`
	Environment string                               `json:"environment"`
	Targets     []productionPlacementBootstrapTarget `json:"targets"`
}
type productionPlacementBootstrapTarget struct {
	ServerIdentity string `json:"server_identity"`
	MemberID       string `json:"member_id"`
	Region         string `json:"region"`
	Proposal       []byte `json:"proposal"`
}
type productionPlacementTransitionConfig struct {
	Issuer        placementtransition.Config
	GenesisGrants map[string]placementtransition.Signed
	Targets       []productionPlacementTarget
	Bootstrap     *productionPlacementBootstrap
	// Drain must return authenticated, durable engine fence receipts. Delivery
	// only acknowledges accepted membership; it must never imply serving ready.
	Drain   func(context.Context, placementtransition.Request, placementtransition.Proof) ([]placementtransition.Signed, error)
	Deliver func(context.Context, string, string, uint64, placementtransition.Signed) error
}

func (f productionPlacementTransitionFile) load() (productionPlacementTransitionConfig, error) {
	out := productionPlacementTransitionConfig{Issuer: placementtransition.Config{ProofKeyID: f.ProofKeyID, GenesisKeys: map[string]ed25519.PublicKey{}, MemberKeys: map[string]ed25519.PublicKey{}}, GenesisGrants: map[string]placementtransition.Signed{}}
	out.Bootstrap = f.Bootstrap
	if f.ProofKeyID == "" || len(f.GenesisKeyFiles) == 0 || len(f.MemberKeyFiles) == 0 {
		return out, placementtransition.ErrInvalid
	}
	key, err := bootstrapcredentials.ReadFile(f.ProofKeyFile, true, ed25519.PrivateKeySize)
	if err != nil {
		return out, err
	}
	defer clear(key)
	switch len(key) {
	case ed25519.SeedSize:
		out.Issuer.ProofKey = ed25519.NewKeyFromSeed(key)
	case ed25519.PrivateKeySize:
		if !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) {
			return out, placementtransition.ErrInvalid
		}
		out.Issuer.ProofKey = slices.Clone(key)
	default:
		return out, placementtransition.ErrInvalid
	}
	for id, path := range f.GenesisKeyFiles {
		k, e := bootstrapcredentials.ReadFile(path, false, ed25519.PublicKeySize)
		if e != nil || len(k) != ed25519.PublicKeySize {
			return out, placementtransition.ErrInvalid
		}
		out.Issuer.GenesisKeys[id] = k
	}
	for id, path := range f.MemberKeyFiles {
		k, e := bootstrapcredentials.ReadFile(path, false, ed25519.PublicKeySize)
		if e != nil || len(k) != ed25519.PublicKeySize {
			return out, placementtransition.ErrInvalid
		}
		out.Issuer.MemberKeys[id] = k
	}
	for op, signed := range f.GenesisGrants {
		var grant placementtransition.GenesisGrant
		key := out.Issuer.GenesisKeys[signed.KeyID]
		if op == "" || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte("terrabase-placement-transition-v1\x00"), signed.Payload...), signed.Signature) || json.Unmarshal(signed.Payload, &grant, json.RejectUnknownMembers(true)) != nil || grant.Kind != "genesis_grant" || grant.GrantID == "" || len(grant.RequestDigest) != 64 {
			return out, placementtransition.ErrInvalid
		}
		if _, err := hex.DecodeString(grant.RequestDigest); err != nil {
			return out, placementtransition.ErrInvalid
		}
		signed.Payload = slices.Clone(signed.Payload)
		signed.Signature = slices.Clone(signed.Signature)
		out.GenesisGrants[op] = signed
	}
	return out, nil
}

type transitionIssuer interface {
	Issue(context.Context, placementtransition.Request, *placementtransition.Signed, []placementtransition.Signed) (placementtransition.Signed, error)
	Load(context.Context, string) (placementtransition.Signed, error)
	Head(context.Context, string) (placementtransition.Signed, error)
}
type productionPlacementTransition struct {
	config              productionPlacementTransitionConfig
	issuer              transitionIssuer
	pending             placementpublisher.Journal
	check               func(context.Context) error
	bootstrapPublishers map[string]*placementpublisher.Publisher
	completion          func(context.Context, string, string, bool) error
	registerUsage       func(context.Context, databaseadmission.Record, string) error
}

func newProductionPlacementTransition(config productionPlacementTransitionConfig, session globalWorkerSession) (*productionPlacementTransition, error) {
	if len(config.Targets) == 0 {
		return nil, errors.New("runtime transition: admitted targets required")
	}
	targets := map[string]*placementpublisher.RemoteTarget{}
	for _, identity := range config.Targets {
		if targets[identity.ServerIdentity] != nil {
			return nil, placementtransition.ErrInvalid
		}
		target, err := placementpublisher.NewRemoteTarget(session.Connection, identity.ServerIdentity, identity.Principal, 10*time.Second)
		if err != nil {
			return nil, err
		}
		targets[identity.ServerIdentity] = target
	}
	config.Deliver = func(ctx context.Context, identity, operation string, revision uint64, proof placementtransition.Signed) error {
		target := targets[identity]
		if target == nil {
			return placementtransition.ErrInvalid
		}
		payload, err := json.Marshal(proof)
		if err != nil {
			return err
		}
		_, err = target.Accept(ctx, operation, &pb.PlacementAcceptRequest{ProposalRevision: revision, Proof: payload})
		return err
	}
	config.Issuer.Authority = authorityjournal.Config{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId}
	issuer, err := placementtransition.New(config.Issuer)
	if err != nil {
		return nil, err
	}
	config.Drain = func(ctx context.Context, request placementtransition.Request, prior placementtransition.Proof) ([]placementtransition.Signed, error) {
		prepared, err := issuer.Prepare(ctx, request)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(prepared)
		if err != nil {
			return nil, err
		}
		receipts := []placementtransition.Signed{}
		var failures []error
		for _, member := range prior.Request.Members {
			target := targets[member.Identity]
			if target == nil {
				failures = append(failures, errors.New("runtime transition: old member is not in admitted transport inventory"))
				continue
			}
			if err := session.CheckEffectAuthority(ctx); err != nil {
				return nil, err
			}
			response, err := target.Drain(ctx, request.OperationID, &pb.PlacementDrainRequest{PreparedTransition: encoded})
			if err != nil {
				failures = append(failures, err)
				continue
			}
			var signed placementtransition.Signed
			if json.Unmarshal(response.SignedReceipt, &signed, json.RejectUnknownMembers(true)) != nil {
				return nil, placementtransition.ErrInvalid
			}
			receipts = append(receipts, signed)
		}
		// An unreachable old seat does not prevent a survivor quorum. Issue
		// authenticates receipts and requires every old Region to be covered.
		if len(receipts) == 0 {
			return nil, errors.Join(failures...)
		}
		return receipts, nil
	}
	pending, err := placementpublisher.NewNATSJournal(placementpublisher.NATSJournalConfig{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId})
	if err != nil {
		return nil, err
	}
	result := &productionPlacementTransition{config: config, issuer: issuer, pending: pending, check: session.CheckEffectAuthority, bootstrapPublishers: map[string]*placementpublisher.Publisher{}}
	result.completion = func(ctx context.Context, operation, digest string, write bool) error {
		sum := sha256.Sum256([]byte(operation))
		c := config.Issuer.Authority
		c.StateKey = "placement.delivered." + hex.EncodeToString(sum[:])
		journal, err := authorityjournal.New(c, func() string { return "" }, func(s string) error {
			if s != "" && len(s) != 64 {
				return placementtransition.ErrInvalid
			}
			return nil
		})
		if err != nil {
			return err
		}
		return journal.Transact(ctx, write, func(stored *string) error {
			if *stored != "" {
				if *stored != digest {
					return placementtransition.ErrConflict
				}
				return nil
			}
			if !write {
				return placementtransition.ErrMissing
			}
			*stored = digest
			return nil
		})
	}
	for identity, target := range targets {
		publisher, err := placementpublisher.New(pending, target, session.CheckEffectAuthority)
		if err != nil {
			return nil, err
		}
		result.bootstrapPublishers[identity] = publisher
	}
	return result, nil
}

func transitionRequest(record databaseadmission.Record) (placementtransition.Request, error) {
	r := placementtransition.Request{OperationID: databaseadmission.PlacementOperationID(record.Request)}
	if len(record.PlacementTargets) == 0 {
		return r, placementtransition.ErrInvalid
	}
	expected := map[string]string{}
	for _, target := range record.PlacementTargets {
		stage := new(pb.PlacementStageRequest)
		if !target.Proposed || proto.Unmarshal(target.Proposal, stage) != nil {
			return r, placementtransition.ErrInvalid
		}
		proposal, err := tbep.CanonicalPlacement(stage.Proposal)
		if err != nil {
			return r, err
		}
		canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(proposal)
		if err != nil {
			return r, err
		}
		scope := proposal.Environment + "/" + proposal.Cluster
		if r.ScopeID == "" {
			r.ScopeID = scope
			r.Epoch = proposal.Epoch
			r.Generation = proposal.Generation
		} else if r.ScopeID != scope || r.Epoch != proposal.Epoch || r.Generation != proposal.Generation {
			return r, placementtransition.ErrConflict
		}
		if proposal.Environment != record.Request.Environment || target.ServerIdentity != "spiffe://terrascale.tech/"+proposal.Environment+"/terrabase-member/"+proposal.Cluster+"/"+target.MemberID {
			return r, placementtransition.ErrInvalid
		}
		for _, region := range proposal.Regions {
			for _, member := range region.Members {
				identity := "spiffe://terrascale.tech/" + proposal.Environment + "/terrabase-member/" + proposal.Cluster + "/" + member
				if old, ok := expected[identity]; ok && old != region.Region {
					return r, placementtransition.ErrInvalid
				}
				expected[identity] = region.Region
			}
		}
		sum := sha256.Sum256(canonical)
		r.Members = append(r.Members, placementtransition.Member{Identity: target.ServerIdentity, Region: target.Region, PlacementDigest: hex.EncodeToString(sum[:])})
	}
	if len(expected) != len(r.Members) {
		return r, errors.New("runtime transition: immutable plan omits scope members")
	}
	for _, m := range r.Members {
		if expected[m.Identity] != m.Region {
			return r, placementtransition.ErrInvalid
		}
	}
	slices.SortFunc(r.Members, func(a, b placementtransition.Member) int { return cmp.Compare(a.Identity, b.Identity) })
	_, err := placementtransition.RequestDigest(r)
	return r, err
}

// Activate is the database pipeline's accepted-membership callback. Completion
// leaves readiness to separately authenticated engine catch-up evidence.
func (t *productionPlacementTransition) Activate(ctx context.Context, record databaseadmission.Record) error {
	return t.activate(ctx, record, "")
}
func (t *productionPlacementTransition) activate(ctx context.Context, record databaseadmission.Record, operationOverride string) error {
	if t == nil || t.issuer == nil || t.pending == nil || t.check == nil || t.registerUsage == nil {
		return placementtransition.ErrInvalid
	}
	if err := t.check(ctx); err != nil {
		return err
	}
	for _, member := range record.Targets {
		if !member.Installed {
			return placementtransition.ErrInvalid
		}
	}
	r, err := transitionRequest(record)
	if err != nil {
		return err
	}
	if operationOverride != "" {
		r.OperationID = operationOverride
	}
	revisions := map[string]uint64{}
	for _, target := range record.PlacementTargets {
		stored, err := t.pending.Load(ctx, target.ServerIdentity)
		if err != nil {
			return err
		}
		receipt := new(pb.PlacementProposalResponse)
		stage := new(pb.PlacementStageRequest)
		if stored.OperationID != r.OperationID || !bytes.Equal(stored.Request, target.Proposal) || len(stored.Receipt) == 0 || proto.Unmarshal(stored.Request, stage) != nil || proto.Unmarshal(stored.Receipt, receipt) != nil || tbep.ValidatePlacementReceipt(receipt, stage.Proposal) != nil || stage.ExpectedRevision == ^uint64(0) || receipt.Revision != stage.ExpectedRevision+1 {
			return errors.New("runtime transition: pending Stage receipt unresolved")
		}
		revisions[target.ServerIdentity] = receipt.Revision
	}
	signed, err := t.issuer.Load(ctx, r.OperationID)
	if errors.Is(err, placementtransition.ErrMissing) {
		var prior placementtransition.Proof
		head, headErr := t.issuer.Head(ctx, r.ScopeID)
		if headErr == nil {
			if json.Unmarshal(head.Payload, &prior, json.RejectUnknownMembers(true)) != nil {
				return placementtransition.ErrInvalid
			}
			if prior.Request.OperationID == r.OperationID {
				r.PriorEpoch = prior.Request.PriorEpoch
				d, digestErr := placementtransition.RequestDigest(r)
				if digestErr != nil || d != prior.RequestDigest {
					return placementtransition.ErrConflict
				}
				signed = head
				err = nil
				goto deliver
			}
			r.PriorEpoch = prior.Request.Epoch
		} else if !errors.Is(headErr, placementtransition.ErrMissing) {
			return headErr
		}
		var genesis *placementtransition.Signed
		var receipts []placementtransition.Signed
		if r.PriorEpoch == 0 {
			grant, ok := t.config.GenesisGrants[r.OperationID]
			if !ok {
				return errors.New("runtime transition: explicit request-bound genesis grant required")
			}
			genesis = &grant
		} else {
			receipts, err = t.config.Drain(ctx, r, prior)
			if err != nil {
				return err
			}
		}
		signed, err = t.issuer.Issue(ctx, r, genesis, receipts)
	}
	if err != nil {
		return err
	}
deliver:
	var proof placementtransition.Proof
	if json.Unmarshal(signed.Payload, &proof, json.RejectUnknownMembers(true)) != nil {
		return placementtransition.ErrInvalid
	}
	r.PriorEpoch = proof.Request.PriorEpoch
	d, err := placementtransition.RequestDigest(r)
	if err != nil || d != proof.RequestDigest {
		return placementtransition.ErrConflict
	}
	for _, target := range record.PlacementTargets {
		if err := t.check(ctx); err != nil {
			return err
		}
		if err := t.config.Deliver(ctx, target.ServerIdentity, r.OperationID, revisions[target.ServerIdentity], signed); err != nil {
			return err
		}
	}
	sum := sha256.Sum256(signed.Payload)
	digest := hex.EncodeToString(sum[:])
	if err := t.registerUsage(ctx, record, digest); err != nil {
		return err
	}
	if t.completion != nil {
		if err := t.check(ctx); err != nil {
			return err
		}
		if err := t.completion(ctx, r.OperationID, digest, true); err != nil {
			return err
		}
	}
	return nil
}
