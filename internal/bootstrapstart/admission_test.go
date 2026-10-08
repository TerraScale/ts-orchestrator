package bootstrapstart

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

type fakeInstanceObserver struct{ observation InstanceObservation }

func (fake fakeInstanceObserver) ObserveInstance(context.Context, string) (InstanceObservation, error) {
	return fake.observation, nil
}

func observationFixture() (bootstrap.SlotState, bootstrap.BootstrapAnchor, InstanceObservation) {
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.example"
	compartmentID := "ocid1.compartment.oc1..example"
	imageID := "ocid1.image.oc1.sa-saopaulo-1.example"
	intentHash := strings.Repeat("a", 64)
	resultHash := strings.Repeat("b", 64)
	state := bootstrap.SlotState{
		Head:         bootstrap.SlotHead{ResultDigest: resultHash},
		IntentRecord: bootstrap.StoredRecord{SHA256: intentHash},
		ResultRecord: &bootstrap.StoredRecord{SHA256: resultHash},
		Intent: bootstrap.Intent{
			DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Environment: "production", Cell: "GRU",
			OCIRegion: "sa-saopaulo-1", Role: "controller", Slot: "controller-a",
			ImageOCID: imageID, CompartmentOCID: compartmentID, CreateKey: "0000000000DQTHYRQR02X2ABFT",
			AvailabilityDomain: "AD-1", FaultDomain: "FAULT-DOMAIN-1", Shape: "VM.Standard.E5.Flex",
			SubnetOCID:              "ocid1.subnet.oc1.sa-saopaulo-1.example",
			NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.one", "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.two"},
		},
		Result: &bootstrap.Result{InstanceOCID: instanceID, ImageOCID: imageID,
			CompartmentOCID: compartmentID, CreateKey: "0000000000DQTHYRQR02X2ABFT", Shape: "VM.Standard.E5.Flex"},
	}
	anchor := bootstrap.BootstrapAnchor{DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Environment: "production",
		ClusterID: "0000000000RMSAJ9B0JFV7ESHN", Cell: oci.Region("GRU"), OCIRegion: "sa-saopaulo-1"}
	observation := InstanceObservation{
		InstanceOCID: instanceID, CompartmentOCID: compartmentID, ImageOCID: imageID,
		AvailabilityDomain: "AD-1", FaultDomain: "FAULT-DOMAIN-1", Shape: "VM.Standard.E5.Flex",
		SubnetOCID:      "ocid1.subnet.oc1.sa-saopaulo-1.example",
		NSGOCIDs:        []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.two", "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.one"},
		PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1.example", PrimaryPrivateIP: "10.0.0.3",
		PrimaryVNIC: true, LifecycleState: "RUNNING",
		Facts: bootstrap.InstanceFacts{CreateKey: "0000000000RPYNQGXVXJSC20CX", IntentSHA256: strings.Repeat("f", 64)},
	}
	return state, anchor, observation
}

func TestObserveAssemblesIntentFactsAfterExactOCIComparison(t *testing.T) {
	state, anchor, observation := observationFixture()
	gate := Gate{Instances: fakeInstanceObserver{observation}}
	got, err := gate.observe(t.Context(), observation.InstanceOCID, state, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if got.Facts.CreateKey != state.Intent.CreateKey || got.Facts.IntentSHA256 != state.IntentRecord.SHA256 ||
		got.Facts.ClusterID != anchor.ClusterID || got.Facts.Profile.SubnetOCID != observation.SubnetOCID {
		t.Fatalf("assembled facts used observer-supplied signed fields: %+v", got.Facts)
	}
}

func TestObserveRejectsMismatchedCloudInstanceAndPrimaryVNIC(t *testing.T) {
	state, anchor, observation := observationFixture()
	for name, mutate := range map[string]func(*InstanceObservation){
		"instance":     func(o *InstanceObservation) { o.InstanceOCID = "ocid1.instance.oc1.sa-saopaulo-1.foreign" },
		"image":        func(o *InstanceObservation) { o.ImageOCID = "ocid1.image.oc1.sa-saopaulo-1.foreign" },
		"subnet":       func(o *InstanceObservation) { o.SubnetOCID = "ocid1.subnet.oc1.sa-saopaulo-1.foreign" },
		"NSG":          func(o *InstanceObservation) { o.NSGOCIDs = nil },
		"primary VNIC": func(o *InstanceObservation) { o.PrimaryVNIC = false },
		"private IP":   func(o *InstanceObservation) { o.PrimaryPrivateIP = "127.0.0.1" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := observation
			mutate(&changed)
			gate := Gate{Instances: fakeInstanceObserver{changed}}
			if _, err := gate.observe(t.Context(), observation.InstanceOCID, state, anchor); !errors.Is(err, ErrAdmission) {
				t.Fatalf("mismatched %s accepted: %v", name, err)
			}
		})
	}
}

func TestExpectedMaterialsIncludesRegionalHostIssuerForSeedAndPeer(t *testing.T) {
	manifest := bootstrap.Manifest{SeedSlot: "controller-a", Secrets: []bootstrap.SecretReference{
		{Purpose: bootstrap.SecretRegionalShared, TargetFile: "ca.pem", SHA256: "regional"},
		{Purpose: bootstrap.SecretHostIssuer, TargetFile: "host-nats-issuer.seed", SHA256: "issuer"},
		{Purpose: bootstrap.SecretController, Slot: "controller-a", TargetFile: "controller-a.creds", SHA256: "0000000000SF1REEJJX6TC691V"},
		{Purpose: bootstrap.SecretController, Slot: "controller-b", TargetFile: "controller-b.creds", SHA256: "peer"},
		{Purpose: bootstrap.SecretSeedFounder, Slot: "controller-a", TargetFile: "founder.key", SHA256: "founder"},
	}}
	seed := map[string]string{"ca.pem": "regional", "host-nats-issuer.seed": "issuer",
		"controller-a.creds": "0000000000SF1REEJJX6TC691V", "founder.key": "founder"}
	peer := map[string]string{"ca.pem": "regional", "host-nats-issuer.seed": "issuer",
		"controller-b.creds": "peer"}
	if got := expectedMaterials(manifest, "controller-a"); !maps.Equal(got, seed) {
		t.Fatalf("seed expected material = %v", got)
	}
	if got := expectedMaterials(manifest, "controller-b"); !maps.Equal(got, peer) {
		t.Fatalf("peer expected material = %v", got)
	}
}
