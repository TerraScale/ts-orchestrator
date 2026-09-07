package enrollment

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
)

type reincarnationTransaction struct {
	state     State
	loseReply bool
}

func (s *reincarnationTransaction) Read(context.Context) (State, error) { return s.state, nil }
func (s *reincarnationTransaction) Transact(_ context.Context, write bool, change func(*State) error) error {
	raw, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	var next State
	if err := json.Unmarshal(raw, &next); err != nil {
		return err
	}
	if err := change(&next); err != nil {
		return err
	}
	if err := validate(next); err != nil {
		return err
	}
	if write {
		s.state = next
	}
	if s.loseReply {
		s.loseReply = false
		return errors.New("reply lost after commit")
	}
	return nil
}

func TestSlotReincarnationRequiresCompleteExactRetirementAndReplaysUnknownCommit(t *testing.T) {
	now := time.Now().UTC()
	input := Record{Environment: "production", Cluster: "cluster", Region: "gru", Slot: 3, Generation: 7, TemplateDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	tx := &reincarnationTransaction{state: State{Records: map[string]Record{}}}
	journal := &Journal{journal: tx}
	first, err := journal.Reserve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	input.Generation++
	retry, err := journal.Reserve(t.Context(), input)
	if err != nil || retry.MemberID != first.MemberID || retry.Generation != first.Generation {
		t.Fatalf("ordinary retry rotated: %+v %v", retry, err)
	}
	removal := hostremoval.Operation{OperationID: "remove-first", ResourceID: "ocid1.instance.first", MemberIdentity: Identity(first, "member"), Generation: first.Generation, Stage: hostremoval.StageComplete}
	for _, mismatch := range []string{"pending", "identity", "generation"} {
		bad := removal
		switch mismatch {
		case "pending":
			bad.Stage = hostremoval.StageFenced
		case "identity":
			bad.MemberIdentity += "foreign"
		case "generation":
			bad.Generation++
		}
		if err := journal.Retire(t.Context(), "gru", 3, bad); err == nil {
			t.Fatalf("accepted %s retirement", mismatch)
		}
	}
	if err := journal.Retire(t.Context(), "gru", 3, removal); err != nil {
		t.Fatal(err)
	}
	tx.loseReply = true
	if _, err := journal.Reserve(t.Context(), input); err == nil {
		t.Fatal("missing lost reply")
	}
	reserved := tx.state.Records["gru:3"]
	second, err := journal.Reserve(t.Context(), input)
	if err != nil || second.MemberID != reserved.MemberID || second.OperationID != reserved.OperationID || second.Generation != first.Generation+1 || second.MemberID == first.MemberID || second.OperationID == first.OperationID || second.Public != nil || second.Retirement != nil {
		t.Fatalf("invalid successor replay: %+v %v", second, err)
	}
	if err := journal.Retire(t.Context(), "gru", 3, removal); err != nil {
		t.Fatalf("repeated old completion: %v", err)
	}
	if got := tx.state.Records["gru:3"]; got.MemberID != second.MemberID || got.Retirement != nil {
		t.Fatal("old completion retired successor")
	}
	archived := tx.state.Retired[removal.OperationID]
	if archived.MemberID != first.MemberID || archived.OperationID != first.OperationID || archived.Retirement.ResourceID != removal.ResourceID {
		t.Fatalf("lost history: %+v", archived)
	}
}
