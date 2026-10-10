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
	leader, err := Start(ctx, js, Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "0000000000FHEQV98X4ASD7RXW", LeaseDuration: 5 * time.Second,
		RenewInterval: time.Second, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := Start(ctx, js, Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "0000000000SF1REEJJX6TC691V", LeaseDuration: 5 * time.Second,
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
			return seed.VerifyLeaseHolder(ctx, term.Epoch, "0000000000SF1REEJJX6TC691V", term.OwnerID)
		},
		"other owner process": func() error {
			return seed.VerifyLeaseHolder(ctx, term.Epoch, term.CandidateID, "0000000000DKT0SAM6NFTCGPGT")
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
