package hostremoval

import (
	"context"
	"errors"
	"testing"
)

// A durable write can commit even when its acknowledgement is lost. A new
// owner must discover that committed stage before replaying external effects.
type interruptedRemovalJournal struct {
	*Journal
	interrupt Stage
	failure   error
}

func (j *interruptedRemovalJournal) after(op Operation, err error) (Operation, error) {
	if err == nil && op.Stage == j.interrupt {
		j.interrupt = ""
		return Operation{}, j.failure
	}
	return op, err
}

func (j *interruptedRemovalJournal) Reserve(ctx context.Context, id string, member MemberObservation, generation uint64, survivors []MemberObservation) (Operation, error) {
	return j.after(j.Journal.Reserve(ctx, id, member, generation, survivors))
}

func (j *interruptedRemovalJournal) Begin(ctx context.Context, id string, member MemberObservation, generation, revision uint64, replacements []Replacement, survivors []MemberObservation) (Operation, error) {
	return j.after(j.Journal.Begin(ctx, id, member, generation, revision, replacements, survivors))
}

func (j *interruptedRemovalJournal) Advance(ctx context.Context, id string, stage Stage) (Operation, error) {
	return j.after(j.Journal.Advance(ctx, id, stage))
}

func TestRemovalRestartAfterEveryCommittedStageAcknowledgementIsLost(t *testing.T) {
	for _, stage := range []Stage{StageInventoryPending, StageInventoryCaptured, StageReplacing, StageFenced, StageComplete} {
		t.Run(string(stage), func(t *testing.T) {
			failure := errors.New("journal acknowledgement lost")
			journal := &interruptedRemovalJournal{Journal: &Journal{journal: &removalMemory{state: state{Operations: map[string]Operation{}}}}, interrupt: stage, failure: failure}
			member := MemberObservation{ProviderETag: "original-etag", ResourceID: "original-resource", Identity: "original-member", Generation: 7}
			present := true
			inventory, replacements, fences, deletes, reconciliations := 0, 0, 0, 0, 0
			construct := func() *Owner {
				return &Owner{Journal: journal,
					Inventory: func(_ context.Context, request RemovalRequest, _ []Replacement) (uint64, []Replacement, error) {
						inventory++
						if request.Member.ProviderETag != member.ProviderETag || request.Member.ResourceID != member.ResourceID || request.Generation != member.Generation {
							t.Fatal("restart changed reserved provider request")
						}
						return 1, []Replacement{{DatabaseID: "db", IssuerOperationID: "replacement", ProposalDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}, nil
					},
					Replace:              func(context.Context, Replacement) error { replacements++; return nil },
					Revalidate:           func(context.Context, string, string, uint64) error { return nil },
					Fence:                func(context.Context, string, string, []Replacement) error { fences++; return nil },
					Observe:              func(context.Context, string) (bool, error) { return present, nil },
					Terminate:            func(context.Context, string) error { deletes++; present = false; return nil },
					ReconcileTermination: func(context.Context, string) error { reconciliations++; return nil },
				}
			}
			if err := construct().RemoveMember(t.Context(), "remove", member, member.Generation); !errors.Is(err, failure) {
				t.Fatalf("interruption: %v", err)
			}
			if err := construct().RemoveMember(t.Context(), "remove", member, member.Generation); err != nil {
				t.Fatalf("restart: %v", err)
			}
			op, err := journal.Load(t.Context(), "remove")
			if err != nil || op.Stage != StageComplete || inventory != 1 || replacements != 1 || fences != 1 || deletes != 1 || reconciliations != 1 {
				t.Fatalf("stage=%s inventory=%d replacements=%d fences=%d deletes=%d reconciliations=%d error=%v", op.Stage, inventory, replacements, fences, deletes, reconciliations, err)
			}
		})
	}
}
