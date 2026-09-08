package placementtransition

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"slices"
	"time"
)

// JoinRecipient is produced only by the live enrollment and exact provider
// identity resolver. It is not decoded from a client or member message.
type JoinRecipient struct {
	Identity   string
	Region     string
	Generation uint64
	ResourceID string
	PublicKey  ed25519.PublicKey
}

type JoinChallenge struct {
	SchemaVersion       int    `json:"schema_version"`
	Kind                string `json:"kind"`
	ScopeID             string `json:"scope_id"`
	MemberIdentity      string `json:"member_identity"`
	MemberRegion        string `json:"member_region"`
	BootstrapNonce      string `json:"bootstrap_nonce"`
	ProposalRevision    uint64 `json:"proposal_revision"`
	StageProposalDigest string `json:"stage_proposal_digest"`
}

type JoinCheckpoint struct {
	SchemaVersion          int    `json:"schema_version"`
	Kind                   string `json:"kind"`
	ScopeID                string `json:"scope_id"`
	MemberIdentity         string `json:"member_identity"`
	MemberRegion           string `json:"member_region"`
	MemberGeneration       uint64 `json:"member_generation"`
	ProviderResourceID     string `json:"provider_resource_id"`
	BootstrapNonce         string `json:"bootstrap_nonce"`
	PriorProof             Signed `json:"prior_proof"`
	PriorProofDigest       string `json:"prior_proof_digest"`
	AcceptedProofDigest    string `json:"accepted_proof_digest"`
	SuccessorRequestDigest string `json:"successor_request_digest"`
	StageProposalDigest    string `json:"stage_proposal_digest"`
	ProposalRevision       uint64 `json:"proposal_revision"`
	AuthorityEpoch         uint64 `json:"authority_epoch"`
	LeaseID                string `json:"lease_id"`
	CandidateID            string `json:"candidate_id"`
	IssuedAtUnixMillis     int64  `json:"issued_at_unix_millis"`
	ExpiresAtUnixMillis    int64  `json:"expires_at_unix_millis"`
}

// AcceptanceProof retains the signed epoch envelope for normal members. Only
// an empty recipient may use the separately signed, nonce-bound checkpoint.
// The checkpoint never changes the epoch proof payload or its receipt digest.
type AcceptanceProof struct {
	KeyID          string  `json:"key_id"`
	Payload        []byte  `json:"payload"`
	Signature      []byte  `json:"signature"`
	JoinCheckpoint *Signed `json:"join_checkpoint,omitempty"`
}

func AcceptedEnvelope(proof Signed, checkpoint *Signed) AcceptanceProof {
	return AcceptanceProof{KeyID: proof.KeyID, Payload: proof.Payload, Signature: proof.Signature, JoinCheckpoint: checkpoint}
}
func (p AcceptanceProof) Signed() Signed {
	return Signed{KeyID: p.KeyID, Payload: p.Payload, Signature: p.Signature}
}

type JoinRequest struct {
	OperationID    string
	MemberIdentity string
	Successor      Signed
	Prior          Signed
	Challenge      Signed
}

// IssueJoinCheckpoint performs a CAS on the exact current scope head before a
// signature may escape. A newer head, lease loss, unavailable enrollment, or
// changed provider incarnation leaves the join unresolved. The bounded grant
// authorizes only this empty recipient's authenticated local bootstrap nonce.
func (i *Issuer) IssueJoinCheckpoint(ctx context.Context, request JoinRequest) (Signed, error) {
	if i == nil || i.journal == nil || i.joinMember == nil || !token(i.candidateID) || ctx == nil || !token(request.OperationID) || !token(request.MemberIdentity) {
		return Signed{}, ErrInvalid
	}
	var successor, prior Proof
	if verify(request.Successor, i.key.Public().(ed25519.PublicKey), &successor) != nil || verify(request.Prior, i.key.Public().(ed25519.PublicKey), &prior) != nil {
		return Signed{}, ErrInvalid
	}
	if !validMemberReceiptInventory(successor) || !validMemberReceiptInventory(prior) {
		return Signed{}, ErrInvalid
	}
	memberIndex := slices.IndexFunc(successor.Request.Members, func(member Member) bool { return member.Identity == request.MemberIdentity })
	if memberIndex < 0 || successor.Kind != "accepted_epoch" || prior.Kind != "accepted_epoch" || successor.Request.OperationID != request.OperationID || successor.Request.ScopeID != prior.Request.ScopeID || successor.Request.PriorEpoch != prior.Request.Epoch || successor.PriorGeneration != prior.Request.Generation || successor.PreviousProofDigest != hash(request.Prior.Payload) || successor.AuthorityEpoch > i.epoch {
		return Signed{}, ErrConflict
	}
	if slices.ContainsFunc(prior.Request.Members, func(member Member) bool { return member.Identity == request.MemberIdentity }) {
		return Signed{}, ErrConflict
	}
	member := successor.Request.Members[memberIndex]
	var result Signed
	var admitted JoinRecipient
	// A read-only snapshot would let a competing successor win after Head was
	// read but before the signature escaped. The no-op state CAS closes that gap.
	err := i.journal.TransactRevision(scopeContext(ctx, successor.Request.ScopeID), true, func(s *state, _ uint64) error {
		head, found := s.Heads[successor.Request.ScopeID]
		retained, retainedFound := s.Operations[head]
		if !found || !retainedFound || head != request.OperationID || retained.Proof.KeyID != request.Successor.KeyID || !bytes.Equal(retained.Proof.Payload, request.Successor.Payload) || !bytes.Equal(retained.Proof.Signature, request.Successor.Signature) {
			return ErrConflict
		}
		var err error
		admitted, err = i.joinMember(ctx, member)
		if err != nil {
			return err
		}
		if admitted.Identity != member.Identity || admitted.Region != member.Region || admitted.Generation == 0 || !token(admitted.ResourceID) || len(admitted.PublicKey) != ed25519.PublicKeySize || !bytes.Equal(successor.MemberReceiptKeys[member.Identity], admitted.PublicKey) {
			return ErrConflict
		}
		var challenge JoinChallenge
		if request.Challenge.KeyID != member.Identity || verify(request.Challenge, admitted.PublicKey, &challenge) != nil || challenge.SchemaVersion != 1 || challenge.Kind != "placement_join_challenge" || challenge.ScopeID != successor.Request.ScopeID || challenge.MemberIdentity != member.Identity || challenge.MemberRegion != member.Region || !digest(challenge.BootstrapNonce) || challenge.ProposalRevision != 1 || challenge.StageProposalDigest != member.PlacementDigest {
			return ErrInvalid
		}
		now := time.Now().UTC()
		checkpoint := JoinCheckpoint{SchemaVersion: 1, Kind: "placement_join", ScopeID: successor.Request.ScopeID, MemberIdentity: member.Identity, MemberRegion: member.Region, MemberGeneration: admitted.Generation, ProviderResourceID: admitted.ResourceID, BootstrapNonce: challenge.BootstrapNonce, PriorProof: request.Prior, PriorProofDigest: hash(request.Prior.Payload), AcceptedProofDigest: hash(request.Successor.Payload), SuccessorRequestDigest: successor.RequestDigest, StageProposalDigest: member.PlacementDigest, ProposalRevision: challenge.ProposalRevision, AuthorityEpoch: i.epoch, LeaseID: i.leaseID, CandidateID: i.candidateID, IssuedAtUnixMillis: now.UnixMilli(), ExpiresAtUnixMillis: now.Add(5 * time.Minute).UnixMilli()}
		// One bounded prior proof expands by base64 inside the checkpoint.
		// Keep ordinary evidence at 64 KiB and the complete acceptance below 256 KiB.
		result, err = signBoundedEvidence(i.keyID, i.key, checkpoint, 96<<10)
		return err
	})
	if err != nil {
		return Signed{}, err
	}
	// Resolve performs the session effect fence as well as the exact provider
	// read. Never return a checkpoint after a takeover or incarnation change.
	current, err := i.joinMember(ctx, member)
	if err != nil {
		return Signed{}, err
	}
	if current.Identity != admitted.Identity || current.Region != admitted.Region || current.Generation != admitted.Generation || current.ResourceID != admitted.ResourceID || !bytes.Equal(current.PublicKey, admitted.PublicKey) {
		return Signed{}, ErrConflict
	}
	return result, nil
}

// ValidateAcceptanceEnvelope checks only bounded wire shape. Recipient pins,
// live issuer authority and signed proof validation remain their real owners.
func ValidateAcceptanceEnvelope(encoded []byte) (AcceptanceProof, error) {
	var envelope AcceptanceProof
	if len(encoded) == 0 || len(encoded) > 256<<10 || json.Unmarshal(encoded, &envelope, json.RejectUnknownMembers(true)) != nil || !token(envelope.KeyID) || len(envelope.Payload) == 0 || len(envelope.Signature) != ed25519.SignatureSize {
		return AcceptanceProof{}, ErrInvalid
	}
	if envelope.JoinCheckpoint != nil && (!token(envelope.JoinCheckpoint.KeyID) || len(envelope.JoinCheckpoint.Payload) == 0 || len(envelope.JoinCheckpoint.Signature) != ed25519.SignatureSize) {
		return AcceptanceProof{}, ErrInvalid
	}
	return envelope, nil
}
