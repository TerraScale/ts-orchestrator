package journal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
)

func newTestAccountJwtSigner(t *testing.T) *NatsAccountJwtSigner {
	t.Helper()
	pair, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := pair.Seed()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := pair.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return &NatsAccountJwtSigner{
		mu:               make(chan struct{}, 1),
		seed:             append([]byte(nil), seed...),
		issuerPublicKey:  publicKey,
		accountPublicKey: publicKey,
	}
}

func TestNatsAccountJwtSignerRejectsNilAndCanceledContexts(t *testing.T) {
	signer := newTestAccountJwtSigner(t)
	if _, err := signer.SignAsync(nil, []byte("material")); err == nil {
		t.Fatal("expected nil context to be rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signer.SignAsync(ctx, []byte("material")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if _, err := (*NatsAccountJwtSigner)(nil).SignAsync(context.Background(), nil); err == nil {
		t.Fatal("expected nil signer to be rejected")
	}
}

func TestNatsAccountJwtSignerDisposeSerializesWithSigning(t *testing.T) {
	signer := newTestAccountJwtSigner(t)
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = signer.SignAsync(context.Background(), []byte("material"))
		}()
	}
	signer.Dispose()
	wait.Wait()
	if signer.seed != nil {
		t.Fatal("expected disposal to clear the signing seed")
	}
	if _, err := signer.SignAsync(context.Background(), []byte("material")); err == nil {
		t.Fatal("expected signing after disposal to fail")
	}
}

func TestOpenedAccountSignerIssuesVerifiableRunnerJwt(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	accountPair, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := accountPair.Seed()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := accountPair.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(directory, "account.seed")
	if err := os.WriteFile(seedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(seed)
	accountPair.Wipe()

	signer, err := NatsAccountJwtSignerOpen(seedPath, nil)
	if err != nil {
		t.Fatalf("open account signer: %v", err)
	}
	t.Cleanup(signer.Dispose)
	if signer.IssuerPublicKey() != publicKey || signer.AccountPublicKey() != publicKey {
		t.Fatalf("signer identity = %q/%q, want %q", signer.IssuerPublicKey(), signer.AccountPublicKey(), publicKey)
	}
	userPair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userPublic, err := userPair.PublicKey()
	userPair.Wipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NatsAccountJwtSignerOpen(seedPath, &userPublic); err == nil {
		t.Fatal("user account override was accepted")
	}

	topology, err := messaging.NewGlobalNatsTopology(3)
	if err != nil {
		t.Fatal(err)
	}
	runner := "runner-a"
	expected, err := topology.CiJobConsumer("trusted-build", runner)
	if err != nil {
		t.Fatal(err)
	}
	registration := NewCiRunnerConsumerRegistration("trusted-build", expected.Name, expected.FilterSubject)
	issuer, err := NewCiRunnerNatsCredentialIssuer(topology, signer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_750_000_000, 0).UTC()
	lease, err := issuer.IssueAsync(context.Background(), registration, runner, now, time.Minute)
	if err != nil {
		t.Fatalf("issue runner credential: %v", err)
	}
	t.Cleanup(lease.Dispose)
	claims, err := jwt.DecodeUserClaims(lease.Jwt)
	if err != nil {
		t.Fatalf("decode issued JWT: %v", err)
	}
	if claims.Subject != lease.PublicKey || claims.Issuer != publicKey || claims.Name != expected.Name ||
		claims.IssuedAt != now.Unix() || claims.Expires != now.Unix()+int64(time.Minute/time.Second) {
		t.Fatalf("issued claims = subject=%q issuer=%q name=%q iat=%d exp=%d", claims.Subject, claims.Issuer, claims.Name, claims.IssuedAt, claims.Expires)
	}
}

func TestOpenedAccountSignerRejectsUserAndOperatorKeys(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		create func() (nkeys.KeyPair, error)
	}{
		{"user-seed", nkeys.CreateUser},
		{"operator-seed", nkeys.CreateOperator},
	} {
		t.Run(test.name, func(t *testing.T) {
			pair, err := test.create()
			if err != nil {
				t.Fatal(err)
			}
			public, err := pair.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			if shared.NatsRequireAccountPublicKey(public, "cross-type") == nil {
				t.Fatal("cross-type public key was accepted")
			}
			seed, err := pair.Seed()
			seed = append([]byte(nil), seed...)
			pair.Wipe()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(seed)
			path := filepath.Join(t.TempDir(), "identity.seed")
			if err := os.WriteFile(path, seed, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NatsAccountJwtSignerOpen(path, nil); err == nil {
				t.Fatal("cross-type signing seed was accepted")
			}
		})
	}
}
