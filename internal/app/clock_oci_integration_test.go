package app

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

// Flip the clock after OCI sees a mutable snapshot. The subsequent Guard must
// still stop the durable intent and provider call at the real authority boundary.
type clockFlipFencer struct {
	*authority.Runtime
	healthy *atomic.Bool
}

func (f clockFlipFencer) Current() authority.Snapshot {
	snapshot := f.Runtime.Current()
	f.healthy.Store(false)
	return snapshot
}

type clockFenceJournal struct {
	oci.Journal
	intents atomic.Int32
}

// GetOperation finds no earlier launch: the fleet reads the journal before
// it records an intent, which is not an effect.
func (j *clockFenceJournal) GetOperation(context.Context, oci.OperationScope) (oci.OperationIntent, bool, error) {
	return oci.OperationIntent{}, false, nil
}

func (j *clockFenceJournal) RecordIntent(context.Context, oci.OperationIntent) error {
	j.intents.Add(1)
	return errors.New("clock-fenced OCI mutation reached the journal")
}

type clockFenceProvider struct {
	oci.Provider
	launches atomic.Int32
}

func (p *clockFenceProvider) LaunchInstance(context.Context, oci.LaunchRequest) (oci.CloudInstance, error) {
	p.launches.Add(1)
	return oci.CloudInstance{}, errors.New("clock-fenced OCI mutation reached the provider")
}

func TestUnhealthyAuthorityClockStopsOCILaunchBeforeIntent(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	broker, err := natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: "clock-oci", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	var healthy atomic.Bool
	healthy.Store(true)
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{Scope: "gru", CandidateID: "0000000000999SG7965GCYC9GD", Replicas: 1,
		ClockCheck: func() error {
			if !healthy.Load() {
				return authority.ErrClockUnhealthy
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if !control.Current().CanMutate() {
		t.Fatal("authority did not acquire a mutable lease")
	}
	intent := oci.RegionIntent{SchemaVersion: 1, Generation: 7, BootstrapRegion: oci.RegionGRU,
		Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}}
	region := oci.RegionConfig{Region: oci.RegionGRU, Generation: 7, Endpoint: "https://iaas.sa-saopaulo-1.oraclecloud.com",
		CompartmentID: "ocid1.compartment.oc1..owned", ImageCompartmentID: "ocid1.compartment.oc1..image", AvailabilityDomain: "AD-1",
		FaultDomains: []string{"FAULT-DOMAIN-1"}, SubnetID: "ocid1.subnet.oc1..owned",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1..owned"},
		BootVolumeGB:            50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 50,
		ImageID: "ocid1.image.oc1..owned", Shape: "VM.Standard.A1.Flex", Owner: "regional-owner"}
	journal := new(clockFenceJournal)
	provider := new(clockFenceProvider)
	fleet, err := oci.NewFleetWithImageVerifier(region, intent, provider, journal, clockFlipFencer{Runtime: control, healthy: &healthy}, nil, nil,
		acceptingImageVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fleet.EnsureHost(ctx, oci.EnsureRequest{
		Name: "gru-1-db-1", CreateKey: "0000000000WTMKBKTNXTWEMRYP", PrivateIP: "10.251.0.21", FaultDomain: "FAULT-DOMAIN-1",
		Shape: region.Shape, WholeOCPUs: 1, MemoryInGBs: 6,
		PlacementProfileDigest: strings.Repeat("a", 64), PlacementGeneration: 1,
		BootPins: oci.HostBootPins{
			DatabaseID: "0000000000SPNBE1B5PSS9BMK6", PartitionID: "0000000000R8WYPN3QERZ3PEKH", SeatID: "0000000000M4R4NE7RJXQ9M8NM",
			HostAttempt: 1, IntentPayloadDigest: strings.Repeat("b", 64),
			CanonicalRosterDigest: strings.Repeat("c", 64), RuntimeManifestDigest: strings.Repeat("d", 64),
		},
	})
	if !errors.Is(err, authority.ErrClockUnhealthy) {
		t.Fatalf("OCI launch with clock lost between snapshot and Guard = %v", err)
	}
	if journal.intents.Load() != 0 || provider.launches.Load() != 0 {
		t.Fatalf("clock-fenced OCI launch recorded %d intents and made %d provider calls", journal.intents.Load(), provider.launches.Load())
	}
}
