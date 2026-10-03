package rolloutexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func testProof(unit, digest string, at time.Time) HealthProof {
	return HealthProof{Schema: HealthSchema, Cell: "gru", Unit: unit, BinarySHA256: digest, ProcessID: 42,
		StartNonce: "0123456789abcdef0123456789abcdef", ObservedAt: at}
}

func TestCollectorKeepsOnlyVerifiedNewestProofsOnTheirOwnSubject(t *testing.T) {
	key, keys := testKey(t)
	other, _ := testKey(t)
	now := time.Now().UTC().Truncate(time.Second)
	collector := NewCollector("gru", func(unit string) (trust.Keyring, error) {
		if unit != "ctl-a" {
			return nil, errors.New("unknown unit")
		}
		return keys, nil
	}, func() time.Time { return now })
	sign := func(proof HealthProof, signer []byte) []byte {
		t.Helper()
		wire, err := SignHealthProof(proof, signer, proof.ObservedAt)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	subject := protocol.RolloutProofSubject("gru", "ctl-a")
	if err := collector.Observe(subject, sign(testProof("ctl-a", toDigest, now), key)); err != nil {
		t.Fatal(err)
	}
	if proof, ok := collector.Latest("ctl-a"); !ok || proof.BinarySHA256 != toDigest || !proof.ReceivedAt.Equal(now) {
		t.Fatalf("latest = %+v %v", proof, ok)
	}
	for name, attempt := range map[string]func() error{
		"another unit's subject": func() error {
			return collector.Observe(protocol.RolloutProofSubject("gru", "ctl-b"), sign(testProof("ctl-a", fromDigest, now), key))
		},
		"unknown key": func() error {
			return collector.Observe(subject, sign(testProof("ctl-a", fromDigest, now), other))
		},
		"unknown unit": func() error {
			return collector.Observe(protocol.RolloutProofSubject("gru", "ctl-z"), sign(testProof("ctl-z", fromDigest, now), key))
		},
		"expired": func() error {
			return collector.Observe(subject, sign(testProof("ctl-a", fromDigest, now.Add(-HealthLifetime-time.Second)), key))
		},
		"other cell": func() error {
			proof := testProof("ctl-a", fromDigest, now)
			proof.Cell = "sfo"
			return collector.Observe(subject, sign(proof, key))
		},
	} {
		if err := attempt(); err == nil {
			t.Errorf("%s: proof accepted", name)
		}
	}
	// An older proof never replaces a newer one.
	if err := collector.Observe(subject, sign(testProof("ctl-a", fromDigest, now.Add(-time.Second)), key)); err != nil {
		t.Fatal(err)
	}
	if proof, _ := collector.Latest("ctl-a"); proof.BinarySHA256 != toDigest {
		t.Fatal("an older proof replaced the newest one")
	}
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
}

// A full collector reclaims units whose proofs expired, so a replacement
// unit is admitted once the removed ones stopped proving.
func TestCollectorReclaimsExpiredUnitsWhenFull(t *testing.T) {
	key, keys := testKey(t)
	now := time.Now().UTC().Truncate(time.Second)
	collector := NewCollector("gru", func(string) (trust.Keyring, error) { return keys, nil },
		func() time.Time { return now })
	observe := func(unit string) error {
		t.Helper()
		wire, err := SignHealthProof(testProof(unit, toDigest, now), key, now)
		if err != nil {
			t.Fatal(err)
		}
		return collector.Observe(protocol.RolloutProofSubject("gru", unit), wire)
	}
	for i := range maxProofUnits {
		if err := observe(fmt.Sprintf("old-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := observe("new-0"); err == nil {
		t.Fatal("a full collector of live units admitted another unit")
	}
	now = now.Add(HealthLifetime + time.Second)
	if err := observe("new-0"); err != nil {
		t.Fatalf("replacement unit after expiry = %v", err)
	}
	if _, ok := collector.Latest("new-0"); !ok {
		t.Fatal("replacement unit has no proof")
	}
	if _, ok := collector.Latest("old-0"); ok {
		t.Fatal("an expired unit was kept")
	}
}
