package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
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
	for memory, ok := range map[int]bool{3: false, 4: true, 6: true, 7: false} {
		plan = fixture.reviewedSeedPlan("seed-create-1")
		plan.MemoryGB = memory
		if err := check(plan, "seed-create-1"); (err == nil) != ok {
			t.Errorf("seed with %d GB: %v", memory, err)
		}
	}
}

func TestExternalSeedSigningBindsReviewedCreateAndExactOCIInstance(t *testing.T) {
	fixture := newSeedCLIFixture(t)
	reviewed := digest([]byte("reviewed protected OpenTofu plan"))
	reservation, err := makeSeedReservation(fixture.seedInputs, reviewed, "seed-create-1",
		fixture.ledgerPrivate, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	state, err := verifySeedReservation(fixture.seedInputs, reservation, fixture.now, false)
	if err != nil || state.Intent.Mode != bootstrap.IntentModeExternalSeed ||
		state.Intent.ReviewedPlanDigest != reviewed || state.Intent.CreateKey != "seed-create-1" {
		t.Fatalf("signed reservation did not bind reviewed create: state=%+v err=%v", state, err)
	}
	if _, err := makeSeedReservation(fixture.seedInputs, reviewed, "seed-create-2",
		fixture.rootPrivate, fixture.now); err == nil {
		t.Fatal("root key unexpectedly signed delegated ledger reservation")
	}
	reservationWire, err := protocol.EncodeJSON(reservation)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := fixture.manifest.Profile(seedSlot)
	if !ok {
		t.Fatal("seed profile absent")
	}
	observation := seedObservation{SchemaVersion: 1, ReservationSHA256: digest(reservationWire),
		InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.seed-one", BootstrapCreateKey: "seed-create-1",
		CompartmentOCID: profile.CompartmentOCID, ImageOCID: fixture.manifest.Manifest().ImageOCID,
		ETag: "seed-etag-1", AvailabilityDomain: profile.AvailabilityDomain,
		FaultDomain: profile.FaultDomain, Shape: profile.Shape, SubnetOCID: profile.SubnetOCID,
		NetworkSecurityGroupOCIDs: slices.Clone(profile.NetworkSecurityGroupOCIDs),
		PrimaryVNICOCID:           "ocid1.vnic.oc1.sa-saopaulo-1.seed-one", PrimaryPrivateIP: fixture.plan.Plan().SeedPrivateIP,
		LifecycleState: "RUNNING", ObservedAt: fixture.now}
	completion, err := makeSeedCompletion(fixture.seedInputs, reservation, reservationWire,
		observation, fixture.rootPrivate, fixture.ledgerPrivate, fixture.now.Add(time.Minute))
	if err != nil {
		t.Fatalf("sign exact seed completion: %v", err)
	}
	if _, _, _, err := verifySeedCompletion(fixture.seedInputs, reservation, reservationWire,
		completion, fixture.now.Add(time.Minute), false); err != nil {
		t.Fatalf("verify signed completion: %v", err)
	}
	if _, _, _, err := verifySeedCompletion(fixture.seedInputs, reservation, reservationWire,
		completion, fixture.now.Add(16*time.Minute), false); err == nil {
		t.Fatal("stale observation authorized a new result write")
	}
	if _, _, _, err := verifySeedCompletion(fixture.seedInputs, reservation, reservationWire,
		completion, fixture.now.Add(16*time.Minute), true); err != nil {
		t.Fatalf("exact already-stored result could not be reconciled: %v", err)
	}
	refreshed := observation
	refreshed.ObservedAt = fixture.now.Add(16 * time.Minute)
	refreshedCompletion, err := makeSeedCompletionUsingReceipt(fixture.seedInputs, reservation,
		reservationWire, refreshed, fixture.rootPrivate, fixture.ledgerPrivate,
		completion.ReceiptWire, fixture.now.Add(17*time.Minute))
	if err != nil || !slices.Equal(refreshedCompletion.ReceiptWire, completion.ReceiptWire) ||
		slices.Equal(refreshedCompletion.ResultWire, completion.ResultWire) {
		t.Fatalf("fresh result did not reuse exact root receipt: err=%v", err)
	}
	for _, mutate := range []func(*seedObservation){
		func(value *seedObservation) { value.BootstrapCreateKey = "another-create" },
		func(value *seedObservation) { value.PrimaryPrivateIP = "10.44.0.99" },
		func(value *seedObservation) { value.Shape = "VM.Standard.E4.Flex" },
		func(value *seedObservation) { value.ETag = "" },
	} {
		changed := observation
		mutate(&changed)
		if _, _, err := verifySeedObservation(fixture.seedInputs, reservation, reservationWire,
			changed, fixture.now.Add(time.Minute), false); err == nil {
			t.Fatalf("changed OCI observation accepted: %+v", changed)
		}
	}
	for _, mutate := range []func(*seedObservation){
		func(value *seedObservation) { value.InstanceOCID = "ocid1.instance.oc1.sa-saopaulo-1.other" },
		func(value *seedObservation) { value.PrimaryVNICOCID = "ocid1.vnic.oc1.sa-saopaulo-1.other" },
		func(value *seedObservation) { value.PrimaryPrivateIP = "10.44.0.99" },
		func(value *seedObservation) { value.ETag = "changed-etag" },
	} {
		changed := observation
		mutate(&changed)
		if sameSeedOCIObservation(changed, observation.instanceObservation(), true) {
			t.Fatalf("changed OCI readback matched signed observation: %+v", changed)
		}
	}
	changed := completion
	changed.ResultWire = reservation.IntentWire
	if _, _, _, err := verifySeedCompletion(fixture.seedInputs, reservation, reservationWire,
		changed, fixture.now.Add(time.Minute), false); err == nil {
		t.Fatal("mismatched signed result accepted")
	}
	committed := state
	committed.Head.ResultDigest = digest(completion.ResultWire)
	committed.HeadRecord = bootstrap.StoredRecord{Bytes: completion.CompletedHeadWire,
		SHA256: digest(completion.CompletedHeadWire)}
	committed.ResultRecord = &bootstrap.StoredRecord{Bytes: completion.ResultWire, SHA256: committed.Head.ResultDigest}
	committed.SeedReceiptRecord = &bootstrap.StoredRecord{Bytes: completion.ReceiptWire,
		SHA256: digest(completion.ReceiptWire)}
	committed.ManifestRecord = &bootstrap.StoredRecord{Bytes: fixture.manifestWire,
		SHA256: digest(fixture.manifestWire)}
	resultScope := trust.Scope{Domain: seedResultDomain, DeploymentID: fixture.identity.DeploymentID,
		Cell: string(fixture.identity.Cell), Environment: fixture.identity.Environment,
		Role: "controller", Slot: seedSlot}
	grant, err := fixture.anchor.LedgerDelegation()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSeedSignedRecord[bootstrap.Result](completion.ResultWire, resultScope,
		grant, fixture.now.Add(time.Minute), false)
	if err != nil {
		t.Fatal(err)
	}
	committed.Result = &decoded
	if !seedCompletionMatchesCommitted(committed, reservation, reservationWire,
		completion, fixture.manifestWire) {
		t.Fatal("exact persisted completion was not replayable")
	}
	changed = completion
	changed.Observation.ETag = "other-etag"
	if seedCompletionMatchesCommitted(committed, reservation, reservationWire,
		changed, fixture.manifestWire) {
		t.Fatal("changed signed observation replayed as exact completion")
	}
	headPayload, err := trust.EncodePayload(committed.Head)
	if err != nil {
		t.Fatal(err)
	}
	headScope := resultScope
	headScope.Domain = seedHeadDomain
	resignedHead, err := trust.Sign(headPayload, headScope, fixture.now.Add(time.Second),
		fixture.now.Add(time.Hour), fixture.ledgerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	changed = completion
	changed.CompletedHeadWire, err = trust.EncodeEnvelope(resignedHead)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := verifySeedCompletion(fixture.seedInputs, reservation, reservationWire,
		changed, fixture.now.Add(time.Minute), false); err != nil {
		t.Fatalf("valid re-signed HEAD was rejected before exact replay check: %v", err)
	}
	if seedCompletionMatchesCommitted(committed, reservation, reservationWire,
		changed, fixture.manifestWire) {
		t.Fatal("different signed HEAD bytes replayed as exact completion")
	}
	afterDeadline := fixture.now.Add(20*time.Hour + time.Minute)
	if _, err := loadSeedInputs(fixture.identityPath, fixture.anchorPath, fixture.planPath,
		fixture.rootPath, fixture.manifestPaths, afterDeadline); !errors.Is(err, bootstrap.ErrFounderPlanExpired) {
		t.Fatalf("expired founder launch authority was still current: %v", err)
	}
	readOnlyInputs, completedPlan, err := loadCompletedSeedInputs(fixture.identityPath,
		fixture.anchorPath, fixture.planPath, fixture.rootPath, fixture.manifestPaths, afterDeadline)
	if err != nil {
		t.Fatalf("load current read-only founder continuation: %v", err)
	}
	committed.IntentRecord.LastModified = fixture.now.Add(time.Minute)
	committed.ResultRecord.LastModified = fixture.now.Add(2 * time.Minute)
	committed.HeadRecord.LastModified = fixture.now.Add(3 * time.Minute)
	if err := verifyCompletedSeedReplay(readOnlyInputs, completedPlan, committed,
		reservation, reservationWire, completion, afterDeadline); err != nil {
		t.Fatalf("pre-deadline completed seed could not be reconciled read-only: %v", err)
	}
	if err := verifyCompletedSeedReplay(readOnlyInputs, completedPlan, committed,
		reservation, reservationWire, changed, afterDeadline); err == nil {
		t.Fatal("different completed HEAD bytes passed post-deadline replay")
	}
	lateHead := committed
	lateHead.HeadRecord.LastModified = fixture.now.Add(20 * time.Hour)
	if err := verifyCompletedSeedReplay(readOnlyInputs, completedPlan, lateHead,
		reservation, reservationWire, completion, afterDeadline); err == nil {
		t.Fatal("HEAD stored at the founder deadline passed read-only reconciliation")
	}
	unfinished := committed
	unfinished.Head.ResultDigest = ""
	if err := verifyCompletedSeedReplay(readOnlyInputs, completedPlan, unfinished,
		reservation, reservationWire, completion, afterDeadline); err == nil {
		t.Fatal("unfinished seed passed post-deadline reconciliation")
	}
}

func TestExternalSeedCLIDoesNotOpenOCIWithoutValidSignedInputs(t *testing.T) {
	fixture := newSeedCLIFixture(t)
	keyPath := filepath.Join(fixture.directory, "founder-ledger.key")
	writeFixture(t, keyPath, fixture.ledgerPrivate, 0o600)
	reservationPath := filepath.Join(fixture.directory, "reservation.json")
	reviewedPlanPath, reviewedPlanSHA := writeReviewedSeedPlan(t, fixture.reviewedSeedPlan("seed-create-1"))
	args := append([]string{"sign-external-seed-reservation"}, fixture.inputArgs()...)
	args = append(args, "--reviewed-plan", reviewedPlanPath, "--reviewed-plan-sha256", reviewedPlanSHA,
		"--create-identity", "seed-create-1", "--ledger-signing-key", keyPath, "--out", reservationPath)
	if err := runAt(args, fixture.now); err != nil {
		t.Fatalf("sign reservation CLI: %v", err)
	}
	reservation, _, err := readSeedBundle[seedReservation](reservationPath)
	if err != nil || reservation.CreateIdentity != "seed-create-1" {
		t.Fatalf("read signed reservation: reservation=%+v err=%v", reservation, err)
	}
	bad := append([]string{"publish-external-seed-reservation"}, fixture.inputArgs()...)
	bad = append(bad, "--reservation", reservationPath, "--oci-config", "absent-config")
	if err := runAt(bad, fixture.now.Add(21*time.Hour)); err == nil {
		t.Fatal("expired founder plan reached OCI publisher")
	}
	if _, err := os.Stat(filepath.Join(fixture.directory, "not-created")); err == nil {
		t.Fatal("invalid publication created output")
	}
}

func TestExternalSeedSignerConsumesGeneratedLedgerKey(t *testing.T) {
	materialDirectory := filepath.Join(t.TempDir(), "controller-material")
	config := bootstrapmaterial.Config{Environment: "production", Region: "sa-saopaulo-1",
		Cell: "gru", DeploymentID: "0000000000XXVM2FA4QBBHZBKD", ClusterID: "00000000000C2KQX35BT9P1FFG",
		SubnetCIDR: "10.251.0.0/24", ValidityHours: 48,
		Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.10"},
			{Name: "controller-b", PrivateIP: "10.251.0.11"},
			{Name: "controller-c", PrivateIP: "10.251.0.12"}}}
	now := time.Now().UTC().Truncate(time.Second)
	record, err := bootstrapmaterial.Generate(materialDirectory, config, now)
	if err != nil {
		t.Fatalf("generate real controller material: %v", err)
	}
	if _, err := bootstrapmaterial.Load(materialDirectory); err != nil {
		t.Fatalf("load generated controller material: %v", err)
	}
	ledgerPath := filepath.Join(materialDirectory, "founder-ledger.key")
	generatedKey, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSeedCLIFixtureWithLedgerKey(t, generatedKey)
	clear(generatedKey)
	grant, err := fixture.anchor.LedgerDelegation()
	if err != nil {
		t.Fatal(err)
	}
	public := fixture.ledgerPrivate.Public().(ed25519.PublicKey)
	keyID, err := trust.KeyID(public)
	if err != nil || base64.StdEncoding.EncodeToString(public) != record.Public.LedgerSignerPublicKey ||
		keyID != grant.SubjectKeyID() {
		t.Fatalf("generated signer did not bind the anchor delegation: %v", err)
	}
	if _, err := readRootPrivateKey(ledgerPath); err == nil {
		t.Fatal("raw delegated ledger key was accepted as a root PEM key")
	}
	reservationPath := filepath.Join(fixture.directory, "generated-key-reservation.json")
	reviewedPlanPath, reviewedPlanSHA := writeReviewedSeedPlan(t, fixture.reviewedSeedPlan("seed-create-generated"))
	args := append([]string{"sign-external-seed-reservation"}, fixture.inputArgs()...)
	args = append(args, "--reviewed-plan", reviewedPlanPath, "--reviewed-plan-sha256", reviewedPlanSHA,
		"--create-identity", "seed-create-generated", "--ledger-signing-key", ledgerPath,
		"--out", reservationPath)
	if err := runAt(args, fixture.now); err != nil {
		t.Fatalf("sign reservation with generated raw ledger key: %v", err)
	}
	reservation, reservationWire, err := readSeedBundle[seedReservation](reservationPath)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := fixture.manifest.Profile(seedSlot)
	if !ok {
		t.Fatal("seed launch profile absent")
	}
	observation := seedObservation{SchemaVersion: 1, ReservationSHA256: digest(reservationWire),
		InstanceOCID:       "ocid1.instance.oc1.sa-saopaulo-1.generated-seed",
		BootstrapCreateKey: reservation.CreateIdentity,
		CompartmentOCID:    profile.CompartmentOCID, ImageOCID: fixture.manifest.Manifest().ImageOCID,
		ETag: "generated-seed-etag", AvailabilityDomain: profile.AvailabilityDomain,
		FaultDomain: profile.FaultDomain, Shape: profile.Shape, SubnetOCID: profile.SubnetOCID,
		NetworkSecurityGroupOCIDs: slices.Clone(profile.NetworkSecurityGroupOCIDs),
		PrimaryVNICOCID:           "ocid1.vnic.oc1.sa-saopaulo-1.generated-seed",
		PrimaryPrivateIP:          fixture.plan.Plan().SeedPrivateIP, LifecycleState: "RUNNING",
		ObservedAt: fixture.now}
	observationPath := filepath.Join(fixture.directory, "generated-key-observation.json")
	if err := writeSeedBundle(observationPath, observation); err != nil {
		t.Fatal(err)
	}
	completionPath := filepath.Join(fixture.directory, "generated-key-completion.json")
	completionArgs := append([]string{"sign-external-seed-completion"}, fixture.inputArgs()...)
	completionArgs = append(completionArgs, "--reservation", reservationPath,
		"--observation", observationPath, "--signing-key", fixture.rootPrivatePath,
		"--ledger-signing-key", ledgerPath, "--out", completionPath)
	if err := runAt(completionArgs, fixture.now.Add(time.Minute)); err != nil {
		t.Fatalf("sign completion with generated raw ledger key: %v", err)
	}
	completion, _, err := readSeedBundle[seedCompletion](completionPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := verifySeedCompletion(fixture.seedInputs, reservation, reservationWire,
		completion, fixture.now.Add(time.Minute), false); err != nil {
		t.Fatalf("generated ledger key produced invalid completion: %v", err)
	}
	wrongSigner := filepath.Join(materialDirectory, "founder-peer.key")
	if _, err := readSeedLedgerSigner(wrongSigner, fixture.anchor); err == nil {
		t.Fatal("generated peer signer was accepted for ledger delegation")
	}
	linkedPath := filepath.Join(fixture.directory, "linked-ledger.key")
	if err := os.Symlink(ledgerPath, linkedPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readSeedLedgerSigner(linkedPath, fixture.anchor); err == nil {
		t.Fatal("symlink was accepted as delegated ledger key")
	}
	if err := os.Chmod(ledgerPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSeedLedgerSigner(ledgerPath, fixture.anchor); err == nil {
		t.Fatal("world-readable delegated ledger key was accepted")
	}
	if err := os.Chmod(ledgerPath, 0o600); err != nil {
		t.Fatal(err)
	}
	corruptPath := filepath.Join(fixture.directory, "corrupt-ledger.key")
	corrupt := slices.Clone(fixture.ledgerPrivate)
	corrupt[len(corrupt)-1] ^= 1
	writeFixture(t, corruptPath, corrupt, 0o600)
	clear(corrupt)
	if _, err := readSeedLedgerSigner(corruptPath, fixture.anchor); err == nil {
		t.Fatal("noncanonical delegated ledger key was accepted")
	}
}

func TestPeerReceiptDelegationSignsOnlyPlannedPeers(t *testing.T) {
	fixture := newSeedCLIFixture(t)
	peerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	peerPath := filepath.Join(fixture.directory, "peer-public.pem")
	writeFixture(t, peerPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
	outputPath := filepath.Join(fixture.directory, "peer-delegation.json")
	args := []string{"sign-peer-receipt-delegation", "--identity", fixture.identityPath,
		"--anchor", fixture.anchorPath, "--root-key", fixture.rootPath,
		"--signing-key", fixture.rootPrivatePath, "--peer-public-key", peerPath,
		"--out", outputPath, "--valid-for", "1h"}
	if err := runAt(args, fixture.now); err != nil {
		t.Fatalf("sign exact peer delegation: %v", err)
	}
	wire, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := trust.VerifyDelegationCurrent(envelope, fixture.roots, fixture.now,
		bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	capabilities := grant.Capabilities()
	if len(capabilities) != 1 || capabilities[0].Domain != peerReceiptDomain ||
		!slices.Equal(capabilities[0].Slots, []string{"controller-b", "controller-c"}) ||
		!slices.Equal(capabilities[0].Actions, []string{"sign"}) {
		t.Fatalf("peer signer received unexpected authority: %+v", capabilities)
	}
	rootAsPeer := slices.Clone(args)
	rootAsPeer[10] = fixture.rootPath
	rootAsPeer[12] = filepath.Join(fixture.directory, "root-as-peer-delegation.json")
	if err := runAt(rootAsPeer, fixture.now); err == nil {
		t.Fatal("root key was accepted as delegated peer signer")
	}
}
