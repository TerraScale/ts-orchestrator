package placementtransition

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"google.golang.org/protobuf/proto"
	"os"
	"strings"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"testing"
)

func TestIssueJoinCheckpointBindsLiveRecipientAndCurrentHead(t *testing.T) {
	for _, scenario := range []string{"valid", "forged challenge", "foreign Region", "unavailable identity", "post-CAS incarnation change", "stale head", "wrong prior"} {
		t.Run(scenario, func(t *testing.T) {
			issuer, _, keys := setup(t)
			first := request()
			genesis := grant(t, first, keys["genesis"])
			prior, err := issuer.Issue(t.Context(), first, &genesis, nil)
			if err != nil {
				t.Fatal(err)
			}
			next := Request{OperationID: "op2", ScopeID: first.ScopeID, PriorEpoch: 1, Epoch: 2, Generation: 2, Members: []Member{{"b", "GRU", hash([]byte("b2"))}, {"c", "GRU", hash([]byte("c2"))}}}
			successor, err := issuer.Issue(t.Context(), next, nil, []Signed{drain(t, next, "a", keys["a"])})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			recipient := JoinRecipient{Identity: "c", Region: "GRU", Generation: 7, ResourceID: "ocid1.instance.original", PublicKey: keys["c"].Public().(ed25519.PublicKey)}
			issuer.joinMember = func(_ context.Context, member Member) (JoinRecipient, error) {
				calls++
				if member.Identity != "c" || member.Region != "GRU" {
					t.Fatalf("wrong admitted identity requested: %+v", member)
				}
				if scenario == "unavailable identity" {
					return JoinRecipient{}, errors.New("provider unavailable")
				}
				out := recipient
				if scenario == "foreign Region" {
					out.Region = "FRA"
				}
				if scenario == "post-CAS incarnation change" && calls > 1 {
					out.Generation++
				}
				return out, nil
			}
			challengeBody := JoinChallenge{SchemaVersion: 1, Kind: "placement_join_challenge", ScopeID: next.ScopeID, MemberIdentity: "c", MemberRegion: "GRU", BootstrapNonce: hash([]byte("durable-member-local-nonce")), ProposalRevision: 1, StageProposalDigest: next.Members[1].PlacementDigest}
			challengeKey := keys["c"]
			if scenario == "forged challenge" {
				challengeKey = keys["a"]
			}
			challenge, err := SignEvidence("c", challengeKey, challengeBody)
			if err != nil {
				t.Fatal(err)
			}
			join := JoinRequest{OperationID: next.OperationID, MemberIdentity: "c", Successor: successor, Prior: prior, Challenge: challenge}
			if scenario == "wrong prior" {
				join.Prior = successor
			}
			if scenario == "stale head" {
				later := next
				later.OperationID, later.PriorEpoch, later.Epoch, later.Generation = "op3", 2, 3, 3
				digest, _ := RequestDigest(later)
				fence, _ := SignEvidence("b", keys["b"], DrainReceipt{Kind: "old_epoch_drained_fenced", MemberIdentity: "b", ScopeID: later.ScopeID, PriorEpoch: 2, PriorGeneration: 2, RequestDigest: digest, FrontierDigest: hash([]byte("new-frontier"))})
				if _, err := issuer.Issue(t.Context(), later, nil, []Signed{fence}); err != nil {
					t.Fatal(err)
				}
			}
			checkpoint, err := issuer.IssueJoinCheckpoint(t.Context(), join)
			if scenario != "valid" {
				if err == nil || len(checkpoint.Payload) != 0 {
					t.Fatalf("unsafe join signed: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var bound JoinCheckpoint
			if err := verify(checkpoint, keys["gru"].Public().(ed25519.PublicKey), &bound); err != nil {
				t.Fatal(err)
			}
			if bound.MemberIdentity != "c" || bound.MemberGeneration != 7 || bound.ProviderResourceID != recipient.ResourceID || bound.BootstrapNonce != challengeBody.BootstrapNonce || bound.ProposalRevision != 1 || bound.AcceptedProofDigest != hash(successor.Payload) || bound.PriorProofDigest != hash(prior.Payload) || bound.StageProposalDigest != next.Members[1].PlacementDigest || bound.AuthorityEpoch != issuer.epoch || bound.CandidateID != issuer.candidateID || bound.ExpiresAtUnixMillis-bound.IssuedAtUnixMillis != 300000 || calls != 2 {
				t.Fatalf("join binding lost authoritative facts: %+v", bound)
			}
			if path := os.Getenv("TS_EXPORT_PLACEMENT_JOIN_VECTOR"); path != "" {
				vector := struct {
					SchemaVersion    int               `json:"schema_version"`
					AuthorityKeys    map[string][]byte `json:"authority_keys"`
					GenesisKeys      map[string][]byte `json:"genesis_keys"`
					StaticMemberKeys map[string][]byte `json:"static_member_keys"`
					Challenge        Signed            `json:"challenge"`
					Accepted         AcceptanceProof   `json:"accepted"`
				}{1, map[string][]byte{"gru": keys["gru"].Public().(ed25519.PublicKey)}, map[string][]byte{"genesis": keys["genesis"].Public().(ed25519.PublicKey)}, map[string][]byte{"a": keys["a"].Public().(ed25519.PublicKey), "b": keys["b"].Public().(ed25519.PublicKey)}, challenge, AcceptedEnvelope(successor, &checkpoint)}
				encoded, err := json.Marshal(vector)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, encoded, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// This fixture exercises real protobuf proposal digests and canonical SPIFFE
// identities independently in the Rust durable PlacementJournal consumer.
func TestCanonicalJoinCheckpointVector(t *testing.T) {
	issuer, _, keys := setup(t)
	cluster := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	ids := []string{"01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAX", "01ARZ3NDEKTSV4RRFFQ69G5FAY"}
	prefix := "spiffe://terrascale.tech/production/terrabase-member/" + cluster + "/"
	issuer.memberKeys = map[string]ed25519.PublicKey{}
	for index, alias := range []string{"a", "b", "c"} {
		issuer.memberKeys[prefix+ids[index]] = keys[alias].Public().(ed25519.PublicKey)
	}
	proposal := &pb.PlacementProposal{Environment: "production", Cluster: cluster, Generation: 1, Epoch: 1, Regions: []*pb.PlacementRegionSeats{{Region: "GRU", Members: ids[:2]}}}
	priorBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	first := Request{OperationID: "op1", ScopeID: "production/" + cluster, Epoch: 1, Generation: 1, Members: []Member{{prefix + ids[0], "GRU", hash(priorBytes)}, {prefix + ids[1], "GRU", hash(priorBytes)}}}
	genesis := grant(t, first, keys["genesis"])
	prior, err := issuer.Issue(t.Context(), first, &genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	proposal.Generation, proposal.Epoch = 2, 2
	proposal.Regions[0].Members = ids[1:]
	stageBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	next := Request{OperationID: "op2", ScopeID: first.ScopeID, PriorEpoch: 1, Epoch: 2, Generation: 2, Members: []Member{{prefix + ids[1], "GRU", hash(stageBytes)}, {prefix + ids[2], "GRU", hash(stageBytes)}}}
	successor, err := issuer.Issue(t.Context(), next, nil, []Signed{drain(t, next, prefix+ids[0], keys["a"])})
	if err != nil {
		t.Fatal(err)
	}
	issuer.joinMember = func(context.Context, Member) (JoinRecipient, error) {
		return JoinRecipient{Identity: prefix + ids[2], Region: "GRU", Generation: 7, ResourceID: "ocid1.instance.original", PublicKey: keys["c"].Public().(ed25519.PublicKey)}, nil
	}
	challenge, err := SignEvidence(prefix+ids[2], keys["c"], JoinChallenge{SchemaVersion: 1, Kind: "placement_join_challenge", ScopeID: first.ScopeID, MemberIdentity: prefix + ids[2], MemberRegion: "GRU", BootstrapNonce: strings.Repeat("a", 64), ProposalRevision: 1, StageProposalDigest: hash(stageBytes)})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := issuer.IssueJoinCheckpoint(t.Context(), JoinRequest{OperationID: "op2", MemberIdentity: prefix + ids[2], Successor: successor, Prior: prior, Challenge: challenge})
	if err != nil {
		t.Fatal(err)
	}
	proposal.Generation, proposal.Epoch = 3, 3
	laterBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	later := Request{OperationID: "op3", ScopeID: first.ScopeID, PriorEpoch: 2, Epoch: 3, Generation: 3, Members: []Member{{prefix + ids[1], "GRU", hash(laterBytes)}, {prefix + ids[2], "GRU", hash(laterBytes)}}}
	laterDigest, err := RequestDigest(later)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := SignEvidence(prefix+ids[2], keys["c"], DrainReceipt{Kind: "old_epoch_drained_fenced", MemberIdentity: prefix + ids[2], ScopeID: first.ScopeID, PriorEpoch: 2, PriorGeneration: 2, RequestDigest: laterDigest, FrontierDigest: hash([]byte("later-frontier"))})
	if err != nil {
		t.Fatal(err)
	}
	laterAccepted, err := issuer.Issue(t.Context(), later, nil, []Signed{fence})
	if err != nil {
		t.Fatal(err)
	}
	vector := map[string]any{"schema_version": 1, "authority_keys": map[string][]byte{"gru": keys["gru"].Public().(ed25519.PublicKey)}, "genesis_keys": map[string][]byte{"genesis": keys["genesis"].Public().(ed25519.PublicKey)}, "static_member_keys": map[string][]byte{prefix + ids[0]: keys["a"].Public().(ed25519.PublicKey), prefix + ids[1]: keys["b"].Public().(ed25519.PublicKey)}, "challenge": challenge, "accepted": AcceptedEnvelope(successor, &checkpoint), "stage_proposal": stageBytes, "prior_stage_proposal": priorBytes, "member_id": ids[2], "later_stage_proposal": laterBytes, "later_accepted": laterAccepted}
	encoded, err := json.Marshal(vector)
	if err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("TS_EXPORT_CANONICAL_JOIN_VECTOR"); path != "" {
		if err := os.WriteFile(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestJoinCheckpointCapacityIncludesMaximumPriorProof(t *testing.T) {
	issuer, _, keys := setup(t)
	first := request()
	genesis := grant(t, first, keys["genesis"])
	prior, err := issuer.Issue(t.Context(), first, &genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Signed JSON may contain trailing whitespace and still be a valid prior.
	prior.Payload = append(prior.Payload, []byte(strings.Repeat(" ", (64<<10)-len(prior.Payload)))...)
	prior.Signature = ed25519.Sign(issuer.key, signatureInput(prior.Payload))
	var verified Proof
	if err := verify(prior, issuer.key.Public().(ed25519.PublicKey), &verified); err != nil {
		t.Fatal("maximum prior is not valid", err)
	}
	checkpoint := JoinCheckpoint{SchemaVersion: 1, Kind: "placement_join", ScopeID: strings.Repeat("s", 256), MemberIdentity: strings.Repeat("m", 256), MemberRegion: "GRU", MemberGeneration: ^uint64(0), ProviderResourceID: strings.Repeat("r", 256), BootstrapNonce: strings.Repeat("a", 64), PriorProof: prior, PriorProofDigest: strings.Repeat("a", 64), AcceptedProofDigest: strings.Repeat("a", 64), SuccessorRequestDigest: strings.Repeat("a", 64), StageProposalDigest: strings.Repeat("a", 64), ProposalRevision: 1, AuthorityEpoch: ^uint64(0), LeaseID: strings.Repeat("l", 256), CandidateID: strings.Repeat("c", 256), IssuedAtUnixMillis: 1 << 62, ExpiresAtUnixMillis: 1<<62 + 300000}
	signed, err := signBoundedEvidence(issuer.keyID, issuer.key, checkpoint, 96<<10)
	if err != nil {
		t.Fatal("maximum prior cannot be checkpointed", err)
	}
	if len(signed.Payload) <= 64<<10 || !ed25519.Verify(issuer.key.Public().(ed25519.PublicKey), signatureInput(signed.Payload), signed.Signature) {
		t.Fatal("extended checkpoint signature invalid")
	}
	encoded, err := json.Marshal(AcceptedEnvelope(prior, &signed))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAcceptanceEnvelope(encoded); err != nil {
		t.Fatal("maximum joined envelope exceeds consumer bound", len(encoded), err)
	}
	if _, err := SignEvidence(issuer.keyID, issuer.key, checkpoint); err == nil {
		t.Fatal("ordinary evidence bound was relaxed")
	}
	if _, err := signBoundedEvidence(issuer.keyID, issuer.key, strings.Repeat("x", 96<<10), 96<<10); err == nil {
		t.Fatal("checkpoint bound missing")
	}
}
