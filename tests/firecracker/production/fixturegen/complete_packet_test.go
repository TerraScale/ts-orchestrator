package fixturegen

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

func TestCompletedPacketRequiresSeedAndManagedSlotRoles(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	anchor, roots := verifiedCaptureAnchor(t, now)
	anchored := anchor.Anchor()
	sourceRoot, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	pins, err := CurrentCompletedSourcePins(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	controllers := []Controller{
		{Slot: "controller-a", InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.a", GuestRoot: "controllers/controller-a/guest-root"},
		{Slot: "controller-b", InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.b", GuestRoot: "controllers/controller-b/guest-root"},
		{Slot: "seed-a", InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.seed", GuestRoot: "controllers/seed-a/guest-root"},
	}
	manifest := Manifest{SchemaVersion: ManifestVersion, DeploymentID: anchored.DeploymentID,
		Cell: string(anchored.Cell), Environment: anchored.Environment, FixtureNow: now,
		Controllers: controllers, SourcePins: pins,
	}
	for _, test := range []struct {
		name  string
		seed  string
		peers []string
	}{
		{name: "swapped seed", seed: "controller-a", peers: []string{"controller-b", "seed-a"}},
		{name: "missing managed controller", seed: "seed-a", peers: []string{"controller-a", "another-slot"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			capture, err := NewCapturingObjectStorage(now)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			destination := filepath.Join(t.TempDir(), "packet")
			_, _, err = EmitCompletedRestartPacket(t.Context(), destination, sourceRoot, manifest,
				func(context.Context, CompletedHistories) (map[string][]byte, error) { return nil, nil },
				anchor, capture, func(*bootstrap.Ledger) (SeedHistory, []ManagedHistory, error) {
					called = true
					return SeedHistory{Scope: bootstrap.BootstrapScope{Slot: test.seed}},
						[]ManagedHistory{
							{Scope: bootstrap.BootstrapScope{Slot: test.peers[0]}},
							{Scope: bootstrap.BootstrapScope{Slot: test.peers[1]}},
						}, nil
				}, nil, roots, now.Add(time.Hour))
			if !called || err == nil || !strings.Contains(err.Error(), "seed-a external seed") {
				t.Fatalf("role-mismatched histories: preparer called=%t, error=%v", called, err)
			}
			if capture.PutCount() != 0 {
				t.Fatal("role-mismatched histories wrote captured storage objects")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatalf("role-mismatched histories published packet: %v", err)
			}
		})
	}
}
