package authority

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestVerifyLeaseHolderFencesEveryOtherTermWithoutTakingAuthority(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	leader, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "leader", LeaseDuration: 5 * time.Second,
		RenewInterval: time.Second, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := Start(ctx, js, Config{Scope: "gru", CandidateID: "seed", LeaseDuration: 5 * time.Second,
		RenewInterval: time.Second, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = seed.Close() })
	term := leader.Current()
	if !term.CanMutate() || seed.Current().Leader {
		t.Fatalf("leader=%+v seed=%+v, want the first runtime to lead", term, seed.Current())
	}
	if err := seed.VerifyLeaseHolder(ctx, term.Epoch, term.CandidateID, term.OwnerID); err != nil {
		t.Fatalf("current holder rejected: %v", err)
	}
	for name, check := range map[string]func() error{
		"stale epoch": func() error { return seed.VerifyLeaseHolder(ctx, term.Epoch+1, term.CandidateID, term.OwnerID) },
		"other candidate": func() error {
			return seed.VerifyLeaseHolder(ctx, term.Epoch, "seed", term.OwnerID)
		},
		"other owner process": func() error {
			return seed.VerifyLeaseHolder(ctx, term.Epoch, term.CandidateID, "restarted")
		},
		"empty identity": func() error { return seed.VerifyLeaseHolder(ctx, term.Epoch, "", "") },
	} {
		if err := check(); !errors.Is(err, ErrFenced) {
			t.Errorf("%s: err = %v, want ErrFenced", name, err)
		}
	}
	if seed.Current().Leader {
		t.Fatal("verifying a foreign lease made the verifier a leader")
	}
	if err := leader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := seed.VerifyLeaseHolder(ctx, term.Epoch, term.CandidateID, term.OwnerID); !errors.Is(err, ErrFenced) {
		t.Fatalf("released lease still verifies: %v", err)
	}
}
