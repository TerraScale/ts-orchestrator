package natscell

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBrokerGenesisZeroProofRefuses(t *testing.T) {
	if err := (VerifiedBrokerGenesis{}).Revalidate(t.Context()); err == nil {
		t.Fatal("zero proof accepted")
	}
}

func TestOriginalBrokerReservationIsExclusiveAndNeverReissued(t *testing.T) {
	cfg := installationIdentityFixture(t)
	existingInstallationPins(t, cfg)
	first := &Runtime{}
	t.Cleanup(func() { _ = first.Close() })
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(10*time.Second))
	defer cancel()
	if err := first.lockBrokerStore(ctx, cfg, true); err != nil {
		t.Fatal(err)
	}
	if first.genesis == nil || first.genesis.expires.After(time.Now().Add(10*time.Second)) {
		t.Fatal("original deadline not retained")
	}
	second := &Runtime{}
	if err := second.lockBrokerStore(t.Context(), cfg, false); err == nil {
		t.Fatal("concurrent store owner accepted")
	}
	_ = second.Close()
	_ = first.Close()
	retry := &Runtime{}
	defer retry.Close()
	if err := retry.lockBrokerStore(t.Context(), cfg, true); err == nil {
		t.Fatal("interrupted original start reissued")
	}
}

func TestOriginalBrokerRefusesUnknownOrRetainedStorage(t *testing.T) {
	for _, name := range []string{"jetstream", "unknown", brokerGenesisMarker} {
		t.Run(name, func(t *testing.T) {
			cfg := installationIdentityFixture(t)
			existingInstallationPins(t, cfg)
			if err := os.WriteFile(filepath.Join(cfg.Embedded.StoreDir, name), []byte("prior"), 0o600); err != nil {
				t.Fatal(err)
			}
			r := &Runtime{}
			defer r.Close()
			if err := r.lockBrokerStore(t.Context(), cfg, true); err == nil {
				t.Fatal("prior storage accepted as original")
			}
		})
	}
}

func TestOrdinaryBrokerCannotProduceGenesis(t *testing.T) {
	cfg := installationIdentityFixture(t)
	existingInstallationPins(t, cfg)
	r := &Runtime{}
	defer r.Close()
	if err := r.lockBrokerStore(t.Context(), cfg, false); err != nil {
		t.Fatal(err)
	}
	if r.genesis != nil {
		t.Fatal("ordinary reopen minted genesis")
	}
}

func TestOriginalBrokerProofBindsActualServerAndDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("original production broker is root-owned")
	}
	cfg := installationIdentityFixture(t)
	existingInstallationPins(t, cfg)
	cfg.Embedded.Port = freeClientPort(t)
	// This identity fixture has no JetStream API grants; provenance requires
	// only the real embedded broker and its authenticated local connection.
	cfg.ClientRole = "host"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r, proof, err := StartOriginalBroker(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := proof.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := proof.RevalidateRuntime(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if err := proof.RevalidateRuntime(t.Context(), &Runtime{}); err == nil {
		t.Fatal("genesis accepted another runtime")
	}
	info := proof.Info()
	if info.ServerID != r.server.ID() || info.RaftNodeID != r.server.NodeName() || info.Installation.CellAccount != r.CellAccount() {
		t.Fatal("proof does not bind actual broker")
	}
	original := cfg.Embedded.StoreDir
	if err := os.Rename(original, original+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := proof.Revalidate(t.Context()); err == nil {
		t.Fatal("recreated directory retained original proof")
	}
	if err := os.Remove(original); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original+"-retained", original); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := proof.Revalidate(t.Context()); err == nil {
		t.Fatal("canceled creation operation remained valid")
	}
	storage, err := r.ObserveBrokerStorage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.RevalidateRuntime(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if err := storage.RevalidateRuntime(t.Context(), &Runtime{}); err == nil {
		t.Fatal("storage observation accepted another runtime")
	}
	if storage.Info().MarkerSHA256 != proof.Info().MarkerSHA256 || storage.Info().StartedAt != proof.Info().StartedAt {
		t.Fatal("read-only observation changed durable origin")
	}
	_ = r.Close()
	reopened, err := Start(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	retained, err := reopened.ObserveBrokerStorage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if reopened.genesis != nil || retained.Info().MarkerSHA256 != info.MarkerSHA256 || retained.Info().Inode != info.Inode {
		t.Fatal("reopen lost origin or renewed creation authority")
	}
	if err := storage.Revalidate(t.Context()); err == nil {
		t.Fatal("stopped original process retained observation")
	}
	if err := os.Remove(filepath.Join(cfg.Embedded.StoreDir, brokerGenesisMarker)); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.ObserveBrokerStorage(t.Context()); err == nil {
		t.Fatal("missing original marker accepted on actual reopened broker")
	}
}
