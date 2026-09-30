package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestOperatorMetadataRecovery(t *testing.T) {
	temporary := &jetstream.APIError{Code: 503, ErrorCode: 10008, Description: "JetStream cluster temporarily unavailable"}
	permanent := &jetstream.APIError{Code: 403, ErrorCode: 10008, Description: "permission denied"}
	t.Run("artifact push bind recovers from typed 503", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		want := new(delivery.Service)
		var calls int
		service, runtime, err := bindArtifactPushClientWith(ctx, Config{}, nil, func(context.Context, Config, *natscell.Runtime, bool) (*delivery.Service, error) {
			calls++
			if calls == 1 {
				return nil, fmt.Errorf("bind artifact store: %w", temporary)
			}
			return want, nil
		})
		if err != nil || service != want || runtime != nil || calls != 2 {
			t.Fatalf("typed 503 bind recovery: service=%p runtime=%p calls=%d err=%v", service, runtime, calls, err)
		}
	})
	t.Run("artifact push bind rejects permanent error", func(t *testing.T) {
		var calls int
		_, _, err := bindArtifactPushClientWith(t.Context(), Config{}, nil, func(context.Context, Config, *natscell.Runtime, bool) (*delivery.Service, error) {
			calls++
			return nil, permanent
		})
		if !errors.Is(err, permanent) || calls != 1 {
			t.Fatalf("permanent artifact bind retried: calls=%d err=%v", calls, err)
		}
	})
	t.Run("artifact push bind stops at shorter caller deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 350*time.Millisecond)
		defer cancel()
		var calls int
		_, _, err := bindArtifactPushClientWith(ctx, Config{}, nil, func(context.Context, Config, *natscell.Runtime, bool) (*delivery.Service, error) {
			calls++
			return nil, temporary
		})
		if !errors.Is(err, context.DeadlineExceeded) || calls < 2 {
			t.Fatalf("artifact bind escaped caller deadline: calls=%d err=%v", calls, err)
		}
	})
	t.Run("deploy bind recovers from typed 503", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		var calls int
		value, err := retryOperatorMetadata(ctx, func(context.Context) (string, error) {
			calls++
			if calls == 1 {
				return "", fmt.Errorf("bind delivery operations: %w", temporary)
			}
			return "bound", nil
		})
		if err != nil || value != "bound" || calls != 2 {
			t.Fatalf("deploy bind recovery: value=%q calls=%d err=%v", value, calls, err)
		}
	})
	t.Run("authority observation recovers before choosing epoch", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		var calls int
		epoch, err := observeOperatorAuthority(ctx, func(context.Context) (authority.Snapshot, error) {
			calls++
			if calls == 1 {
				return authority.Snapshot{}, fmt.Errorf("read authority lease: %w", temporary)
			}
			return authority.Snapshot{Ready: true, Reason: "observed", Epoch: 7, ExpiresAt: time.Now().Add(time.Minute)}, nil
		})
		if err != nil || epoch != 7 || calls != 2 {
			t.Fatalf("authority recovery: epoch=%d calls=%d err=%v", epoch, calls, err)
		}
	})
	t.Run("permanent errors and expired lease fail fast", func(t *testing.T) {
		if !retryableOperatorBackendError(temporary, false) || retryableOperatorBackendError(permanent, false) || retryableOperatorBackendError(context.Canceled, false) {
			t.Fatal("operator backend classifier retried a permanent error or rejected a typed transient error")
		}
		var bindCalls int
		_, err := retryOperatorMetadata(t.Context(), func(context.Context) (string, error) {
			bindCalls++
			return "", permanent
		})
		if !errors.Is(err, permanent) || bindCalls != 1 {
			t.Fatalf("permanent bind retried: calls=%d err=%v", bindCalls, err)
		}
		var observeCalls int
		_, err = observeOperatorAuthority(t.Context(), func(context.Context) (authority.Snapshot, error) {
			observeCalls++
			return authority.Snapshot{}, permanent
		})
		if !errors.Is(err, permanent) || observeCalls != 1 {
			t.Fatalf("permanent authority error retried: calls=%d err=%v", observeCalls, err)
		}
		observeCalls = 0
		_, err = observeOperatorAuthority(t.Context(), func(context.Context) (authority.Snapshot, error) {
			observeCalls++
			return authority.Snapshot{Ready: true, Reason: "observed", Epoch: 7, ExpiresAt: time.Now().Add(-time.Second)}, nil
		})
		if err == nil || observeCalls != 1 {
			t.Fatalf("expired authority lease retried: calls=%d err=%v", observeCalls, err)
		}
	})
	t.Run("shorter caller deadline bounds transient retries", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 350*time.Millisecond)
		defer cancel()
		var calls int
		_, err := retryOperatorMetadata(ctx, func(context.Context) (string, error) {
			calls++
			return "", temporary
		})
		if !errors.Is(err, context.DeadlineExceeded) || calls < 2 {
			t.Fatalf("transient retries escaped caller deadline: calls=%d err=%v", calls, err)
		}
	})
}

func TestArtifactAdmissionExactEnvelopeIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	runtime, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: "one", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "js")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	codec := delivery.Ed25519Codec{Cell: "lab", Actor: "operator", PrivateKey: private,
		Trusted:  map[string]delivery.TrustedSigner{keyID: {Actor: "operator", PublicKey: public}},
		Lifetime: time.Minute, MaxLifetime: time.Minute}
	service, err := delivery.Open(ctx, delivery.Config{Conn: runtime.Conn(), JS: runtime.JetStream(), Cell: "lab", Replicas: 1,
		ArtifactSigner: codec, ArtifactVerifier: codec, AuthorizeArtifact: func(context.Context, string, delivery.ArtifactRecord) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	record, claim, err := service.PrepareArtifact(ctx, bytes.NewReader([]byte("artifact bytes")), delivery.ArtifactClaimRequest{
		Source: delivery.ArtifactSource{Repository: "https://example.com/terrascale/terrabase", Commit: strings.Repeat("a", 40), TreeDigest: strings.Repeat("b", 64)},
		Cell:   "lab", Role: "terrabase", Environment: "production",
	})
	if err != nil {
		t.Fatal(err)
	}
	if admitted, err := service.AcceptArtifactClaim(ctx, claim); err != nil || admitted != record {
		t.Fatalf("first admission: record=%+v err=%v", admitted, err)
	}
	admissions, err := runtime.JetStream().KeyValue(ctx, delivery.AdmissionBucket)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := admissions.Keys(ctx)
	if err != nil || len(keys) != 1 {
		t.Fatalf("admission keys=%v err=%v", keys, err)
	}
	first, err := admissions.Get(ctx, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if admitted, err := service.AcceptArtifactClaim(ctx, claim); err != nil || admitted != record {
		t.Fatalf("exact claim replay: record=%+v err=%v", admitted, err)
	}
	second, err := admissions.Get(ctx, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if second.Revision() != first.Revision() {
		t.Fatalf("exact claim replay wrote another admission: revision=%d -> %d", first.Revision(), second.Revision())
	}
}

func TestArtifactAdmissionReplaysExactClaimWithinRecoveryWindow(t *testing.T) {
	conn := testOperatorAdmissionConnection(t)
	record := delivery.ArtifactRecord{Digest: "test-digest"}
	claim := []byte("exact signed claim bytes")
	transient, err := json.Marshal(artifactAdmissionResponse{Error: "temporary admission metadata failure", Retryable: true})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := json.Marshal(artifactAdmissionResponse{Record: record})
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan []byte, 2)
	var replies atomic.Int32
	var admissions atomic.Int32
	sub, err := conn.Subscribe(delivery.ArtifactClaimSubject("lab"), func(message *nats.Msg) {
		seen <- bytes.Clone(message.Data)
		if replies.Add(1) == 1 {
			admissions.Add(1)
			_ = message.Respond(transient)
			return
		}
		_ = message.Respond(accepted)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := conn.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := requestArtifactAdmission(ctx, conn, "lab", record, claim); err != nil {
		t.Fatal(err)
	}
	if first, second := <-seen, <-seen; !bytes.Equal(first, claim) || !bytes.Equal(second, claim) || !bytes.Equal(first, second) || replies.Load() != 2 || admissions.Load() != 1 {
		t.Fatalf("claim replay changed bytes or repeated admission: first=%q second=%q replies=%d admissions=%d", first, second, replies.Load(), admissions.Load())
	}
}

func TestArtifactAdmissionPermanentReplyAndCallerBound(t *testing.T) {
	for _, test := range []struct {
		name      string
		retryable bool
		wantCalls int32
	}{
		{name: "unauthorized fails without replay", wantCalls: 1},
		{name: "transient replies stop at caller deadline", retryable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := testOperatorAdmissionConnection(t)
			message := "admission denied"
			if test.retryable {
				message = "temporary admission metadata failure"
			}
			wire, err := json.Marshal(artifactAdmissionResponse{Error: message, Retryable: test.retryable})
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			sub, err := conn.Subscribe(delivery.ArtifactClaimSubject("lab"), func(message *nats.Msg) {
				calls.Add(1)
				_ = message.Respond(wire)
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sub.Unsubscribe() })
			if err := conn.FlushTimeout(time.Second); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 350*time.Millisecond)
			defer cancel()
			err = requestArtifactAdmission(ctx, conn, "lab", delivery.ArtifactRecord{}, []byte("signed claim"))
			if test.retryable {
				if !errors.Is(err, context.DeadlineExceeded) || calls.Load() < 2 {
					t.Fatalf("retryable response exhausted too early: calls=%d err=%v", calls.Load(), err)
				}
			} else if err == nil || calls.Load() != test.wantCalls {
				t.Fatalf("permanent response retried: calls=%d err=%v", calls.Load(), err)
			}
		})
	}
}

func testOperatorAdmissionConnection(t *testing.T) *nats.Conn {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	return conn
}
