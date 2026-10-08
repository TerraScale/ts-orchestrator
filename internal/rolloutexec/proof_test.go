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
		StartNonce: "014D2PF2DBSQQG28T5CY4TQKFF", ObservedAt: at}
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
	now = now.Add(retiredFor + time.Second)
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

// A restarted unit whose clock stepped back is accepted once its previous
// incarnation went quiet; until then, and always within one incarnation,
// an earlier-reading proof never replaces the newest one.
func TestCollectorAcceptsANewIncarnationWhoseClockSteppedBack(t *testing.T) {
	key, keys := testKey(t)
	start := time.Now().UTC().Truncate(time.Second)
	now := start
	collector := NewCollector("gru", func(string) (trust.Keyring, error) { return keys, nil },
		func() time.Time { return now })
	subject := protocol.RolloutProofSubject("gru", "ctl-a")
	observe := func(proof HealthProof) error {
		t.Helper()
		wire, err := SignHealthProof(proof, key, proof.ObservedAt)
		if err != nil {
			t.Fatal(err)
		}
		return collector.Observe(subject, wire)
	}
	if err := observe(testProof("ctl-a", fromDigest, start)); err != nil {
		t.Fatal(err)
	}
	restarted := func(at time.Time) HealthProof {
		proof := testProof("ctl-a", toDigest, at)
		proof.ProcessID, proof.StartNonce = 43, "7YVJX9GXJM688FXQ5TK1V58CGG"
		return proof
	}
	// The old incarnation proved 5 s ago: an earlier-reading proof of
	// another incarnation is not trusted to replace it yet.
	now = start.Add(5 * time.Second)
	if err := observe(restarted(start.Add(-40 * time.Second))); err != nil {
		t.Fatal(err)
	}
	if proof, _ := collector.Latest("ctl-a"); proof.ProcessID != 42 {
		t.Fatal("an earlier-reading proof replaced a live incarnation")
	}
	now = start.Add(incarnationQuiet + 5*time.Second)
	if err := observe(restarted(start.Add(-10 * time.Second))); err != nil {
		t.Fatal(err)
	}
	if proof, _ := collector.Latest("ctl-a"); proof.ProcessID != 43 || proof.BinarySHA256 != toDigest {
		t.Fatalf("the restarted incarnation was not accepted: %+v", proof)
	}
	// Within the new incarnation, proofs still only move forward.
	if err := observe(restarted(start.Add(-20 * time.Second))); err != nil {
		t.Fatal(err)
	}
	if proof, _ := collector.Latest("ctl-a"); !proof.ObservedAt.Equal(start.Add(-10 * time.Second)) {
		t.Fatalf("an older proof of the same incarnation replaced the newest: %s", proof.ObservedAt)
	}
}

// A process a newer incarnation superseded never becomes current again,
// even after the newer one went quiet: A, then B, then a delayed copy of
// A's still-valid proof is refused.
func TestCollectorRefusesASupersededIncarnation(t *testing.T) {
	key, keys := testKey(t)
	start := time.Now().UTC().Truncate(time.Second)
	now := start
	collector := NewCollector("gru", func(string) (trust.Keyring, error) { return keys, nil },
		func() time.Time { return now })
	subject := protocol.RolloutProofSubject("gru", "h1")
	sign := func(proof HealthProof) []byte {
		t.Helper()
		wire, err := SignHealthProof(proof, key, proof.ObservedAt)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	a := sign(testProof("h1", fromDigest, start))
	if err := collector.Observe(subject, a); err != nil {
		t.Fatal(err)
	}
	b := testProof("h1", fromDigest, start.Add(10*time.Second))
	b.ProcessID, b.StartNonce = 43, "7YVJX9GXJM688FXQ5TK1V58CGG"
	now = start.Add(10 * time.Second)
	if err := collector.Observe(subject, sign(b)); err != nil {
		t.Fatal(err)
	}
	now = start.Add(80 * time.Second)
	if err := collector.Observe(subject, a); err != nil {
		t.Fatal(err)
	}
	if proof, _ := collector.Latest("h1"); proof.ProcessID != 43 {
		t.Fatalf("a superseded incarnation became current again: %+v", proof)
	}
}
