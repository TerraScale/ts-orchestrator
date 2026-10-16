package authority

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestOutOfWindowResetNeedsFreshRootAuthorizationForItsExactHold(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	issued := time.Now().Add(-2 * time.Hour)
	expired, err := SignIdentityReset(f.reset, issued, issued.Add(time.Hour), f.key)
	if err != nil {
		t.Fatal(err)
	}
	f.envelope = expired
	if _, err := ResetIdentityLease(t.Context(), f.js, expired, f.roots, f.target, expired.IssuedAt.Add(time.Minute)); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("late broker commitment was reported successful: %v", err)
	}
	if _, err := VerifyCommittedIdentityReset(t.Context(), f.js, expired, f.roots, f.target); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("late hold admitted without root: %v", err)
	}
	if _, err := ReplaceIdentityRecords(t.Context(), f.js, expired, f.roots, f.target, f.values, time.Now()); err == nil {
		t.Fatal("late hold allowed replacement")
	}
	recovery, err := SignIdentityResetRecovery(t.Context(), f.js, expired, f.roots, f.target, f.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"signature", "scope", "hold", "expired authorization"} {
		t.Run(fault, func(t *testing.T) {
			candidate, target, now := recovery, f.target, time.Now()
			switch fault {
			case "signature":
				candidate.Signature = "invalid"
			case "scope":
				target.DeploymentID = "00000000000000000000000000"
			case "hold":
				issued := time.Now().Add(-3 * time.Hour)
				envelope, err := SignIdentityReset(f.reset, issued, issued.Add(time.Hour), f.key)
				if err != nil {
					t.Fatal(err)
				}
				candidate, err = SignIdentityResetRecovery(t.Context(), f.js, envelope, f.roots, target, f.key, time.Now())
				if err != nil {
					t.Fatal(err)
				}
			case "expired authorization":
				now = candidate.ExpiresAt.Add(time.Second)
			}
			if err := CommitIdentityResetRecovery(t.Context(), f.js, expired, candidate, f.roots, target, now); err == nil {
				t.Fatal("foreign or expired authorization committed")
			}
		})
	}
	if err := CommitIdentityResetRecovery(t.Context(), f.js, expired, recovery, f.roots, f.target, time.Now()); err != nil {
		t.Fatal(err)
	}
	revisions, err := ReplaceIdentityRecords(t.Context(), f.js, expired, f.roots, f.target, f.values, recovery.ExpiresAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.assertReplaced(t, revisions)
	if _, err := CompleteIdentityReset(t.Context(), f.js, expired, f.roots, f.target, recovery.ExpiresAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestResetRecoveryCannotAuthorizeAnUncommittedProposalOrForeignSigner(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	if _, err := SignIdentityResetRecovery(t.Context(), f.js, f.envelope, f.roots, f.target, f.key, time.Now()); err == nil {
		t.Fatal("uncommitted proposal renewed")
	}
	f.barrier(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignIdentityResetRecovery(t.Context(), f.js, f.envelope, f.roots, f.target, key, time.Now()); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("foreign root: %v", err)
	}
}

func TestAtomicOutOfWindowHoldRecoversBothScopesWithFreshRootAuthorization(t *testing.T) {
	f := newIdentityRecordsFixture(t, 8)
	f.reset.GlobalLease = &IdentityResetGlobalLease{Epoch: 13}
	issued := time.Now().Add(-2 * time.Hour)
	envelope, err := SignIdentityReset(f.reset, issued, issued.Add(time.Hour), f.key)
	if err != nil {
		t.Fatal(err)
	}
	f.envelope = envelope
	if _, err := ResetIdentityLease(t.Context(), f.js, envelope, f.roots, f.target, issued.Add(time.Minute)); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("late atomic hold: %v", err)
	}
	recovery, err := SignIdentityResetRecovery(t.Context(), f.js, envelope, f.roots, f.target, f.key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := CommitIdentityResetRecovery(t.Context(), f.js, envelope, recovery, f.roots, f.target, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.replace(t, f.js, t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteIdentityReset(t.Context(), f.js, envelope, f.roots, f.target, time.Now()); err != nil {
		t.Fatal(err)
	}
}
