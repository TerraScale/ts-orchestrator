package rolloutexec

import (
	"context"
	"errors"

	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func testProof(unit, digest string, at time.Time) HealthProof {
	return HealthProof{Schema: HealthSchema, Cell: "gru", Unit: unit, BinarySHA256: digest, ProcessID: 42,
		StartNonce: "0123456789abcdef0123456789abcdef", ObservedAt: at}
}

func TestPublisherProofsReachTheCollector(t *testing.T) {
	conn, _ := testNATS(t)
	key, keys := testKey(t)
	executable := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(executable, []byte("running release"), 0o755); err != nil {
		t.Fatal(err)
	}
	collector := NewCollector("gru", func(string) (trust.Keyring, error) { return keys, nil }, nil)
	sub, err := collector.Subscribe(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Publisher{Conn: conn, Cell: "gru", Unit: "ctl-a", Key: key, Healthy: func() bool { return true },
			Interval: 20 * time.Millisecond, Executable: executable}.Run(ctx)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if proof, ok := collector.Latest("ctl-a"); ok {
			if proof.BinarySHA256 != digestOf("running release") || proof.ProcessID != int64(os.Getpid()) {
				t.Fatalf("proof = %+v", proof)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no proof arrived")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("publisher stopped with %v", err)
	}

	t.Run("superseded-incarnation", func(t *testing.T) {
		key, keys := testKey(t)
		start := time.Now().UTC().Truncate(time.Second)
		now := start
		collector := NewCollector("gru", func(string) (trust.Keyring, error) { return keys, nil },
			func() time.Time { return now })
		subject := protocol.RolloutProofSubject("gru", "h1")
		received, err := conn.SubscribeSync(subject)
		if err != nil {
			t.Fatal(err)
		}
		defer received.Unsubscribe()
		if err := conn.Flush(); err != nil {
			t.Fatal(err)
		}
		sign := func(proof HealthProof) []byte {
			t.Helper()
			wire, err := SignHealthProof(proof, key, proof.ObservedAt)
			if err != nil {
				t.Fatal(err)
			}
			return wire
		}
		observe := func(wire []byte) error {
			t.Helper()
			if err := conn.Publish(subject, wire); err != nil {
				return err
			}
			message, err := received.NextMsg(5 * time.Second)
			if err != nil {
				return err
			}
			return collector.Observe(message.Subject, message.Data)
		}
		a := sign(testProof("h1", fromDigest, start))
		if err := observe(a); err != nil {
			t.Fatal(err)
		}
		b := testProof("h1", fromDigest, start.Add(10*time.Second))
		b.ProcessID, b.StartNonce = 43, "fedcba9876543210fedcba9876543210"
		now = start.Add(10 * time.Second)
		if err := observe(sign(b)); err != nil {
			t.Fatal(err)
		}
		now = start.Add(80 * time.Second)
		if err := observe(a); err != nil {
			t.Fatal(err)
		}
		if proof, _ := collector.Latest("h1"); proof.ProcessID != 43 {
			t.Fatalf("a superseded incarnation became current again: %+v", proof)
		}
	})
}
