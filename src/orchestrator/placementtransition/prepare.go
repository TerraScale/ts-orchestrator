package placementtransition

import (
	"context"
	"encoding/json/v2"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
)

// Prepared authorizes a member to fence this exact transition. It is never an
// accepted membership or serving grant.
type Prepared struct {
	SchemaVersion       int     `json:"schema_version"`
	Kind                string  `json:"kind"`
	Request             Request `json:"request"`
	RequestDigest       string  `json:"request_digest"`
	PriorGeneration     uint64  `json:"prior_generation"`
	PreviousProofDigest string  `json:"previous_proof_digest"`
	AuthorityEpoch      uint64  `json:"authority_epoch"`
	LeaseID             string  `json:"lease_id"`
	JournalRevision     uint64  `json:"journal_revision"`
}

func (i *Issuer) Prepare(ctx context.Context, r Request) (Signed, error) {
	if ctx == nil || i == nil {
		return Signed{}, ErrInvalid
	}
	d, err := RequestDigest(r)
	if err != nil || r.PriorEpoch == 0 {
		return Signed{}, ErrInvalid
	}
	shard, ok := i.journal.(*shardedJournal)
	if !ok {
		return Signed{}, ErrInvalid
	}
	if err := shard.reserve(ctx, "operation", r.OperationID, d); err != nil {
		return Signed{}, err
	}
	head, err := i.Head(ctx, r.ScopeID)
	if err != nil {
		return Signed{}, err
	}
	var prior Proof
	if json.Unmarshal(head.Payload, &prior) != nil || prior.Request.Epoch != r.PriorEpoch || prior.Request.Generation >= r.Generation {
		return Signed{}, ErrConflict
	}
	config := shard.config
	config.StateKey = "placement.prepared." + hash([]byte(r.OperationID))
	journal, err := authorityjournal.New(config, func() Signed { return Signed{} }, func(s Signed) error {
		if len(s.Payload) == 0 && s.KeyID == "" && len(s.Signature) == 0 {
			return nil
		}
		var p Prepared
		if json.Unmarshal(s.Payload, &p, json.RejectUnknownMembers(true)) != nil || p.Kind != "prepared_epoch" || p.SchemaVersion != 1 || p.JournalRevision == 0 || p.RequestDigest != d {
			return ErrInvalid
		}
		return nil
	})
	if err != nil {
		return Signed{}, err
	}
	var out Signed
	err = journal.TransactRevision(ctx, true, func(s *Signed, revision uint64) error {
		if len(s.Payload) > 0 {
			var p Prepared
			if json.Unmarshal(s.Payload, &p) != nil || p.RequestDigest != d || p.PreviousProofDigest != hash(head.Payload) {
				return ErrConflict
			}
			out = cloneSigned(*s)
			return nil
		}
		p := Prepared{1, "prepared_epoch", r, d, prior.Request.Generation, hash(head.Payload), i.epoch, i.leaseID, revision}
		signed, err := SignEvidence(i.keyID, i.key, p)
		if err != nil {
			return err
		}
		*s = signed
		out = cloneSigned(signed)
		return nil
	})
	if err != nil {
		return Signed{}, err
	}
	return out, nil
}
