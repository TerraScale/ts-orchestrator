package placementtransition

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"os"
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
			if bound.MemberIdentity != "c" || bound.MemberGeneration != 7 || bound.ProviderResourceID != recipient.ResourceID || bound.BootstrapNonce != challengeBody.BootstrapNonce || bound.ProposalRevision != 1 || bound.AcceptedProofDigest != hash(successor.Payload) || bound.PriorProofDigest != hash(prior.Payload) || bound.StageProposalDigest != next.Members[1].PlacementDigest || bound.AuthorityEpoch != issuer.epoch || bound.CandidateID != issuer.candidateID || bound.ExpiresAtUnixMillis-bound.IssuedAtUnixMillis != 600000 || calls != 2 {
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
