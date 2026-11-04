package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type seedCLIFixture struct {
	seedInputs
	rootPrivate     ed25519.PrivateKey
	ledgerPrivate   ed25519.PrivateKey
	identityPath    string
	anchorPath      string
	planPath        string
	rootPath        string
	rootPrivatePath string
	manifestPaths   []string
	directory       string
	now             time.Time
}

func newSeedCLIFixture(t *testing.T) seedCLIFixture {
	return newSeedCLIFixtureWithLedgerKey(t, nil)
}

func newSeedCLIFixtureWithLedgerKey(t *testing.T, supplied ed25519.PrivateKey) seedCLIFixture {
	t.Helper()
	base := newInitialFounderCLIFixture(t)
	now := base.now
	slots := []string{"controller-a", "controller-b", "controller-c"}
	rename := map[string]string{"seed-a": "controller-a", "controller-a": "controller-b", "controller-b": "controller-c"}
	var ledgerPublic ed25519.PublicKey
	var ledgerPrivate ed25519.PrivateKey
	var err error
	if supplied == nil {
		ledgerPublic, ledgerPrivate, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		ledgerPrivate = slices.Clone(supplied)
		ledgerPublic = ledgerPrivate.Public().(ed25519.PublicKey)
	}
	ledgerPublicWire, err := trust.EncodeDelegatedPublicKey(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerID, err := trust.KeyID(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := make([]trust.Capability, 0, len(bootstrap.BootstrapLedgerCapabilityDomains()))
	for _, domain := range bootstrap.BootstrapLedgerCapabilityDomains() {
		capabilities = append(capabilities, trust.Capability{Domain: domain,
			DeploymentID: base.anchor.DeploymentID, Cell: string(base.anchor.Cell),
			Environment: base.anchor.Environment, Role: "controller", Slots: slots, Actions: []string{"sign"}})
	}
	ledgerGrant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: ledgerID, SubjectPublicKey: ledgerPublicWire, Capabilities: capabilities},
		now.Add(-time.Hour), now.Add(25*time.Hour), base.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	anchor := base.anchor
	anchor.ControllerSlots = slots
	anchor.LedgerDelegationWire = encodeEnvelope(t, ledgerGrant)
	base.writeAnchorFor(t, anchor, 24*time.Hour)
	anchorWire, err := os.ReadFile(base.anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerPublicWire, err := trust.EncodeDelegatedPublicKey(peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := trust.KeyID(peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	peerGrant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: peerID, SubjectPublicKey: peerPublicWire,
		Capabilities: []trust.Capability{{Domain: peerReceiptDomain,
			DeploymentID: anchor.DeploymentID, Cell: string(anchor.Cell), Environment: anchor.Environment,
			Role: "controller", Slots: slots[1:], Actions: []string{"sign"}}}},
		now.Add(-time.Minute), now.Add(23*time.Hour), base.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	manifestWires := make(map[string][]byte, 3)
	manifestPaths := make([]string, 0, 3)
	for _, previous := range []string{"seed-a", "controller-a", "controller-b"} {
		envelope, err := trust.DecodeEnvelope(base.manifestWires[previous])
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := bootstrap.ManifestPayload(envelope.Payload)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Slot, manifest.SeedSlot = rename[previous], seedSlot
		manifest.ControllerSlots = slices.Clone(slots)
		manifest.PeerReceiptDelegation = &peerGrant
		for index := range manifest.Profiles {
			manifest.Profiles[index].Slot = rename[manifest.Profiles[index].Slot]
		}
		slices.SortFunc(manifest.Profiles, func(a, b bootstrap.LaunchProfile) int {
			return strings.Compare(a.Slot, b.Slot)
		})
		for index := range manifest.Secrets {
			if manifest.Secrets[index].Slot != "" {
				manifest.Secrets[index].Slot = rename[manifest.Secrets[index].Slot]
			}
		}
		if manifest.Slot == seedSlot {
			manifest.Secrets = append(manifest.Secrets,
				bootstrap.SecretReference{Purpose: bootstrap.SecretSeedFounder, Slot: seedSlot,
					SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.founder", VersionNumber: 1,
					SHA256: digest([]byte("founder")), MaxBytes: 128, TargetFile: "founder.key"},
				bootstrap.SecretReference{Purpose: bootstrap.SecretSeedLedgerSigner, Slot: seedSlot,
					SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.ledger", VersionNumber: 1,
					SHA256: digest([]byte("ledger")), MaxBytes: 128, TargetFile: "ledger.key"})
		}
		signed, err := bootstrap.SignManifest(manifest, now, now.Add(22*time.Hour), base.rootPrivate)
		if err != nil {
			t.Fatal(err)
		}
		wire := encodeEnvelope(t, signed)
		manifestWires[manifest.Slot] = wire
		path := filepath.Join(base.directory, manifest.Slot+".seed-manifest.json")
		writeFixture(t, path, wire, 0o600)
		manifestPaths = append(manifestPaths, path)
	}
	plan := base.plan
	plan.SeedSlot = seedSlot
	plan.ControllerSlots = slices.Clone(slots)
	plan.AnchorSHA256 = digest(anchorWire)
	plan.SeedManifestSHA256 = digest(manifestWires[seedSlot])
	for index := range plan.Peers {
		peer := &plan.Peers[index]
		peer.Slot = rename[peer.Slot]
		peer.ManifestSHA256 = digest(manifestWires[peer.Slot])
		for endpoint := range peer.RouteEndpoints {
			peer.RouteEndpoints[endpoint].Slot = rename[peer.RouteEndpoints[endpoint].Slot]
		}
		slices.SortFunc(peer.RouteEndpoints, func(a, b bootstrap.FounderEndpoint) int {
			return strings.Compare(a.Slot, b.Slot)
		})
		for endpoint := range peer.ClientEndpoints {
			peer.ClientEndpoints[endpoint].Slot = rename[peer.ClientEndpoints[endpoint].Slot]
		}
	}
	plan.SeedPrivateIP = "10.44.0.10"
	plan.LaunchDeadline = now.Add(20 * time.Hour)
	planCandidate, err := protocol.EncodeJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	candidatePath := filepath.Join(base.directory, "seed-plan-candidate.json")
	writeFixture(t, candidatePath, planCandidate, 0o600)
	planPath := filepath.Join(base.directory, "seed-plan.signed.json")
	args := []string{"sign-founder-plan", "--candidate", candidatePath,
		"--identity", base.identityPath, "--anchor", base.anchorPath,
		"--root-key", base.rootPath, "--signing-key", base.privatePath,
		"--out", planPath, "--valid-for", "21h"}
	for _, path := range manifestPaths {
		args = append(args, "--manifest", path)
	}
	if err := runAt(args, now); err != nil {
		t.Fatalf("sign controller-a/b/c plan: %v", err)
	}
	inputs, err := loadSeedInputs(base.identityPath, base.anchorPath, planPath, base.rootPath,
		manifestPaths, now)
	if err != nil {
		t.Fatalf("load complete first-seed authority: %v", err)
	}
	return seedCLIFixture{seedInputs: inputs, rootPrivate: base.rootPrivate,
		ledgerPrivate: ledgerPrivate, identityPath: base.identityPath, anchorPath: base.anchorPath,
		planPath: planPath, rootPath: base.rootPath, rootPrivatePath: base.privatePath,
		manifestPaths: manifestPaths,
		directory:     base.directory, now: now}
}

func (fixture seedCLIFixture) inputArgs() []string {
	args := []string{"--identity", fixture.identityPath, "--anchor", fixture.anchorPath,
		"--founder-plan", fixture.planPath, "--root-key", fixture.rootPath}
	for _, path := range fixture.manifestPaths {
		args = append(args, "--manifest", path)
	}
	return args
}

func (fixture seedCLIFixture) reviewedSeedPlan(createIdentity string) reviewedSeedPlan {
	profile, _ := fixture.manifest.Profile(seedSlot)
	manifest := fixture.manifest.Manifest()
	return reviewedSeedPlan{SchemaVersion: 2, Slot: seedSlot, Shape: profile.Shape,
		OCPUs: 1, MemoryGB: 6, BootGB: 50, BootVPUsPerGB: 10,
		CompartmentID: profile.CompartmentOCID, AvailabilityDomain: profile.AvailabilityDomain,
		FaultDomain: profile.FaultDomain, SubnetID: profile.SubnetOCID,
		NetworkSecurityGroupIDs: slices.Clone(profile.NetworkSecurityGroupOCIDs), ImageID: manifest.ImageOCID,
		AnchorSHA256: fixture.anchor.Digest(), ManifestSHA256: fixture.manifest.Digest(),
		ImageReceiptSHA256: manifest.ReleaseReceiptSHA256,
		AdmissionSHA256:    digest([]byte("cost admission")), InventorySHA256: digest([]byte("live inventory")),
		AdmissionAdmittedAt: fixture.now.Add(-time.Minute),
		AdmissionExpiresAt:  fixture.now.Add(14 * time.Minute), MonthlyEstimateUSD: "89.55",
		CreateIdentity: createIdentity}
}

func writeReviewedSeedPlan(t *testing.T, plan reviewedSeedPlan) (string, string) {
	t.Helper()
	wire, err := protocol.EncodeJSON(plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manual-seed-plan.json")
	writeFixture(t, path, wire, 0o600)
	return path, digest(wire)
}

func TestReviewedManualSeedPlanBindsSignedLaunchAndCreateIdentity(t *testing.T) {
	fixture := newSeedCLIFixture(t)
	plan := fixture.reviewedSeedPlan("seed-create-1")
	check := func(plan reviewedSeedPlan, create string) error {
		t.Helper()
		path, sha := writeReviewedSeedPlan(t, plan)
		_, err := readReviewedSeedPlan(path, sha, create, fixture.seedInputs, fixture.now, true)
		return err
	}
	if err := check(plan, "seed-create-1"); err != nil {
		t.Fatalf("reviewed manual launch rejected: %v", err)
	}
	if err := check(plan, "other-create"); err == nil {
		t.Fatal("different OCI create identity accepted")
	}
	plan.AnchorSHA256 = digest([]byte("other anchor"))
	if err := check(plan, "seed-create-1"); err == nil {
		t.Fatal("different signed anchor accepted")
	}
	plan = fixture.reviewedSeedPlan("seed-create-1")
	plan.SubnetID = "ocid1.subnet.oc1.sa-saopaulo-1.other"
	if err := check(plan, "seed-create-1"); err == nil {
		t.Fatal("different signed seed subnet accepted")
	}
	plan = fixture.reviewedSeedPlan("seed-create-1")
	plan.AdmissionExpiresAt = fixture.now.Add(-time.Second)
	if err := check(plan, "seed-create-1"); err == nil {
		t.Fatal("expired cost admission accepted")
	}
	path, sha := writeReviewedSeedPlan(t, plan)
	if _, err := readReviewedSeedPlan(path, sha, "seed-create-1", fixture.seedInputs,
		fixture.now, false); err != nil {
		t.Fatalf("exact seed identity could not be retried after admission expiry: %v", err)
	}
	plan = fixture.reviewedSeedPlan("seed-create-1")
	plan.MonthlyEstimateUSD = "200"
	if err := check(plan, "seed-create-1"); err != nil {
		t.Fatalf("exact monthly cost ceiling rejected: %v", err)
	}
	plan.MonthlyEstimateUSD = "200.01"
	if err := check(plan, "seed-create-1"); err == nil {
		t.Fatal("over-budget launch accepted")
	}
	plan = fixture.reviewedSeedPlan("seed-create-1")
	plan.OCPUs = 2
	if err := check(plan, "seed-create-1"); err == nil {
		t.Fatal("oversized seed shape configuration accepted")
	}
	// 1 OCPU nodes run 4 GB (sjc-1, gru-1 since TS-627) to 6 GB.
	for memory, ok := range map[int]bool{
		4: true,
	} {
		plan = fixture.reviewedSeedPlan("seed-create-1")
		plan.MemoryGB = memory
		if err := check(plan, "seed-create-1"); (err == nil) != ok {
			t.Errorf("seed with %d GB: %v", memory, err)
		}
	}
}
