package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	staged "git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go"
)

const (
	deployTestCell       = "gru"
	deployTestRepository = "https://git.terrascale.tech/TerraScale/TerraBase"
	deployTestOwner      = "ts-preview-gru-test"
)

// deployTestCellServices is the controller half of one regional cell with
// every managed TerraBase service the live controller wires, backed by an
// in-memory OCI region and object store.
type deployTestCellServices struct {
	control       *authority.Runtime
	broker        *natscell.Runtime
	provider      *deployTestProvider
	store         placement.Store
	hosts         *host.Controller
	placement     *placement.Controller
	materials     host.ManagedMaterialProvider
	runtimeTarget managedRuntimeTargetVerifier
	operatorFile  string
	root          string
	responseKey   ed25519.PublicKey
	controllerKey ed25519.PrivateKey
	holds         *placementHoldLog
	policy        signerPolicy
	status        *nats.Subscription
}

func TestTerraBaseDeployDrivesManagedPlacementToDesiredState(t *testing.T) {
	cell := startDeployTestCell(t, true, true)
	ctx := t.Context()
	plan, state := writeDeployTestPlan(t, cell.root, 9465)
	output := runDeployTestOperator(t, ctx, cell, "terrabase-deploy", "--plan", plan, "--state", state)
	steps := deployTestSteps(t, output)
	if !slices.Equal(steps, []string{"identity:generated", "artifact:admitted", "spec:signed", "material:prepared",
		"customer:opened", "placement:admitted", "deploy:applied"}) {
		t.Fatalf("first deployment steps = %v", steps)
	}
	var credentials managedmaterial.CustomerMaterial
	var client terrabaseClientProfile
	var intent placement.Intent
	var reply materialPrepareReply
	readDeployTestState(t, state, deployCredentialsFile, &credentials)
	readDeployTestState(t, state, deployClientFile, &client)
	readDeployTestState(t, state, deployIntentFile, &intent)
	readDeployTestState(t, state, deployMaterialFile, &reply)
	if !strings.HasPrefix(credentials.Token, "tbk1.") || !strings.Contains(credentials.HTTPSCAPEM, "CERTIFICATE") ||
		client.Version != terrabaseClientProfileVersion || len(client.Members) != 2 ||
		client.Members[0].URL != "https://10.251.0.21:9465" ||
		client.Collections[0].SchemaDigest != "0d645cd6d847a903aaf2b34a6fa3b9ca3047c9b0a283218a4fa29cd0b6085090" ||
		!slices.Equal(client.Collections[0].UTF8Fields, []string{"title"}) {
		t.Fatalf("customer outputs are incomplete: client=%+v", client)
	}
	if info, err := os.Stat(filepath.Join(state, deployCredentialsFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("customer credentials are not owner-only: %v", err)
	}
	entry, err := cell.control.ReadPlacementIntent(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil || entry.Sequence == 0 {
		t.Fatalf("placement was not admitted to R3: %v", err)
	}

	// A rerun resumes: identities, spec, material and customer files are
	// reused, and the idempotent artifact and placement admissions repeat.
	steps = deployTestSteps(t, runDeployTestOperator(t, ctx, cell, "terrabase-deploy", "--plan", plan, "--state", state))
	if !slices.Equal(steps, []string{"identity:reused", "artifact:admitted", "spec:reused", "material:reused",
		"customer:reused", "placement:admitted", "deploy:applied"}) {
		t.Fatalf("resumed deployment steps = %v", steps)
	}
	changed, _ := writeDeployTestPlan(t, t.TempDir(), 9466)
	if _, err := runDeployTestOperatorErr(ctx, cell, "terrabase-deploy", "--plan", changed, "--state", state); err == nil ||
		!strings.Contains(err.Error(), "plan changed") {
		t.Fatalf("a changed plan reused retained identities: %v", err)
	}

	cell.tickUntil(t, func(members map[string]placement.MemberState) bool {
		return len(members) == 2 && members["000000000082AXF7GZQT1D126Y"].Stage == placement.StageAwaitingHost &&
			members["0000000000XG8SBD7XGE97V28G"].Stage == placement.StageAwaitingHost
	})
	if len(cell.provider.launches) != 2 {
		t.Fatalf("launches = %d, want one host per member", len(cell.provider.launches))
	}
	for index, launch := range cell.provider.launches {
		wantIP, wantDomain := []string{"10.251.0.21", "10.251.0.22"}[index], []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"}[index]
		if launch.PrivateIP != wantIP || launch.FaultDomain != wantDomain || launch.Shape != "VM.Standard.A1.Flex" ||
			launch.WholeOCPUs != 1 || launch.MemoryInGBs != 6 || launch.ImageID != cell.provider.config.ImageID {
			t.Fatalf("launch %d = %+v", index, launch)
		}
	}
	report := deployTestStatus(t, ctx, cell, state)
	if report.Serving || len(report.Members) != 2 || report.Members[0].Stage != string(placement.StageAwaitingHost) ||
		report.Members[0].InstanceID == "" || report.Members[0].Host != nil {
		t.Fatalf("status before enrollment = %+v", report)
	}

	agents := cell.enrollMembers(t, intent)
	defer agents()
	cell.tickUntil(t, func(members map[string]placement.MemberState) bool {
		return members["000000000082AXF7GZQT1D126Y"].Stage == placement.StageAwaitingHealthy &&
			members["0000000000XG8SBD7XGE97V28G"].Stage == placement.StageAwaitingHealthy
	})
	desired, err := cell.hosts.ListDesired(ctx, "terrabase")
	if err != nil || len(desired) != 2 {
		t.Fatalf("desired targets = %+v, %v", desired, err)
	}
	statuses, err := cell.hosts.ListHosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range desired {
		launch := target.ManagedMember
		if target.Digest != intent.RuntimeManifests[0].ArtifactDigest || launch == nil || launch.Runtime == nil ||
			launch.ProcessMemoryBytes != 4<<30 || launch.CgroupMemoryMaxBytes != 4<<30 ||
			launch.Runtime.DevicePath != "/dev/oracleoci/oraclevdb" || launch.Runtime.FileSystemType != "ext4" ||
			!strings.HasPrefix(launch.Runtime.MountPath, "/srv/ts-managed/") {
			t.Fatalf("desired launch pins = %+v", launch)
		}
		index := slices.IndexFunc(statuses, func(status host.HostStatus) bool { return status.Registration.Node == target.Node })
		if index < 0 {
			t.Fatalf("no registration for desired node %s", target.Node)
		}
		if err := verifyCurrentVolumeInitSeat(ctx, cell.store, target, statuses[index].Registration,
			cell.runtimeTarget); err != nil {
			t.Fatalf("volume initialization would reject the launched seat %s: %v", target.Node, err)
		}
		files, err := cell.materials(ctx, target, statuses[index].Registration)
		if err != nil {
			t.Fatalf("controller would not deliver material for %s: %v", target.Node, err)
		}
		for name, pin := range map[string]string{
			"authority.tbca": launch.Authority.CertificateSHA256, "server.crt": launch.Runtime.ServerCertificateSHA256,
			"server.key": launch.Runtime.ServerPrivateKeySHA256, "client-ca.pem": launch.Runtime.ClientCARootsSHA256,
			"server-ca.pem":                launch.Runtime.ReplicationServerCASHA256,
			"client-managed-manifest.json": launch.Runtime.ClientManagedMaterialManifestSHA256,
			"signed-v2-s3-config.json":     launch.Runtime.LiveS3ConfigSHA256,
		} {
			sum := sha256.Sum256(files[name])
			if hex.EncodeToString(sum[:]) != pin {
				t.Fatalf("delivered %s differs from its signed desired pin", name)
			}
		}
	}
	report = deployTestStatus(t, ctx, cell, state)
	for _, member := range report.Members {
		if member.Stage != string(placement.StageAwaitingHealthy) || member.VolumeID == "" ||
			member.AttachmentDevice != "/dev/oracleoci/oraclevdb" || member.Host == nil || !member.Host.SessionCurrent ||
			member.DesiredGeneration != 1 || member.ArtifactDigest != intent.RuntimeManifests[0].ArtifactDigest {
			t.Fatalf("status after desired = %+v", member)
		}
	}
	if report.Serving || !slices.ContainsFunc(report.Holds, func(hold placementHoldRecord) bool {
		return strings.Contains(hold.Reason, "independent TerraBase serving proof")
	}) {
		t.Fatalf("status does not explain the serving hold: %+v", report.Holds)
	}
}

// The live R5 image reports neither consistent volume naming nor PV
// in-transit encryption. Placement must hold before attaching and say why.
func TestTerraBaseDeployHoldsVolumeAttachOnUnqualifiedImageLaunchOptions(t *testing.T) {
	cell := startDeployTestCell(t, false, false)
	ctx := t.Context()
	plan, state := writeDeployTestPlan(t, cell.root, 9465)
	runDeployTestOperator(t, ctx, cell, "terrabase-deploy", "--plan", plan, "--state", state)
	var intent placement.Intent
	readDeployTestState(t, state, deployIntentFile, &intent)
	cell.tickUntil(t, func(members map[string]placement.MemberState) bool {
		return len(members) == 2 && members["0000000000XG8SBD7XGE97V28G"].Stage == placement.StageAwaitingHost
	})
	agents := cell.enrollMembers(t, intent)
	defer agents()
	cell.tickUntil(t, func(members map[string]placement.MemberState) bool {
		return members["000000000082AXF7GZQT1D126Y"].Stage == placement.StagePreparedAttach
	})
	for range 3 {
		if err := cell.placement.Tick(ctx); err != nil {
			cell.holds.record("reconciliation error: " + err.Error())
		}
	}
	if len(cell.provider.attachments) != 0 {
		t.Fatal("placement attached a volume to an instance without consistent volume naming")
	}
	report := deployTestStatus(t, ctx, cell, state)
	if report.Members[0].Stage != string(placement.StagePreparedAttach) || !slices.ContainsFunc(report.Holds,
		func(hold placementHoldRecord) bool { return strings.Contains(hold.Reason, "consistent volume naming") }) {
		t.Fatalf("status does not report the image launch-option hold: %+v", report)
	}
}

func startDeployTestCell(t *testing.T, consistentNaming, inTransit bool) *deployTestCellServices {
	t.Helper()
	ctx := t.Context()
	root := t.TempDir()
	broker, err := natscell.Start(ctx, natscell.Config{Cell: deployTestCell, Instance: "deploy-controller", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(root, "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{Scope: deployTestCell, CandidateID: "0000000000D58ZC5VE3YK35W1J", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if !control.Current().CanMutate() {
		t.Fatal("regional authority did not acquire a mutable lease")
	}
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	controllerPublic, controllerPrivate := testEd25519(t, root, "controller.key")
	signerPublic := writeDeployTestRecipientKeys(t, root)
	compatibilityPublic, _ := testEd25519(t, root, "compatibility.key")
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"canary", "production"}, CanRegisterHosts: true,
		CanPlaceTerraBase: true, CanPrepareManagedMaterial: true, CanUpdateTerraBaseRuntime: true,
		Repositories: []string{deployTestRepository}}
	compatibility := TrustedSignerConfig{Actor: "compatibility", PublicKey: base64.StdEncoding.EncodeToString(compatibilityPublic),
		Roles: []string{"terrabase"}, Environments: []string{"canary", "production"}, CanCertifyTerraBaseCompatibility: true}
	cfg := Config{NATS: natscell.Config{Cell: deployTestCell},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant, compatibility}}}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cell := &deployTestCellServices{control: control, broker: broker, root: root, responseKey: controllerPublic,
		operatorFile: testJSONFile(t, root, "operator.json", Config{Version: ConfigVersion,
			NATS:       natscell.Config{Cell: deployTestCell, Instance: "deploy-operator", Replicas: 1, Lab: true, URL: broker.URL()},
			Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant, compatibility}},
			Operator: OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key"),
				ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic)},
		})}
	service, err := delivery.Open(ctx, delivery.Config{Conn: broker.Conn(), JS: broker.JetStream(), Cell: deployTestCell,
		Replicas: 1, Verifier: policy.codec, ArtifactVerifier: policy.codec,
		Authorize: policy.authorizeIntent, AuthorizeArtifact: policy.authorizeArtifact, Fencer: control})
	if err != nil {
		t.Fatal(err)
	}
	subscribe := func(subscription interface{ Unsubscribe() error }, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = subscription.Unsubscribe() })
	}
	subscribe(serveArtifactAdmission(ctx, broker.Conn(), deployTestCell, control, service))
	repository, err := managedmaterial.NewRepository(managedmaterial.RepositoryConfig{Region: oci.RegionGRU, Cell: deployTestCell,
		Namespace: "grxnmoqvrcdv", Bucket: "ts-preview-gru-material", KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.material"},
		new(preparationTestObjects), control)
	if err != nil {
		t.Fatal(err)
	}
	material := managedmaterial.PreparationService{Cell: deployTestCell, Repository: repository, Receipts: control,
		Fencer: control, ControllerKey: controllerPrivate, RecipientSigner: signerPublic,
		AllowedSubnetCIDR: "10.251.0.0/25", NativeValidator: appNativeMaterialValidator{},
		NativeVerifierSHA256: strings.Repeat("a", 64)}
	admission := preparedMaterialAdmission(material)
	subscribe(serveMaterialPreparation(ctx, broker.Conn(), deployTestCell, policy, material))
	subscribe(servePlacementAdmission(ctx, broker.Conn(), deployTestCell, policy, control, admission))
	store, err := placement.NewJetStreamStore(ctx, broker.JetStream(), deployTestCell, 1,
		admittedPlacementReader{cell: deployTestCell, store: control, material: admission})
	if err != nil {
		t.Fatal(err)
	}
	region := oci.RegionConfig{Region: oci.RegionGRU, Generation: 1, Endpoint: "https://iaas.sa-saopaulo-1.oraclecloud.com",
		CompartmentID: "ocid1.compartment.oc1..workload", ImageCompartmentID: "ocid1.compartment.oc1..image",
		AvailabilityDomain: "YDvv:SA-SAOPAULO-1-AD-1", FaultDomains: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		SubnetID: "ocid1.subnet.oc1.sa-saopaulo-1.workload", ImageID: "ocid1.image.oc1.sa-saopaulo-1.r5",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.member"},
		BootVolumeGB:            50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 50,
		Shape: "VM.Standard.A1.Flex", Owner: deployTestOwner}
	journal, err := oci.OpenJournal(ctx, broker.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	cell.provider = newDeployTestProvider(region, consistentNaming, inTransit)
	fleet, err := oci.NewFleetWithImageVerifier(region, oci.RegionIntent{SchemaVersion: 1, Generation: 1,
		BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}},
		cell.provider, journal, control, nil, nil, acceptingImageVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := newManagedRegistrationVerifier(deployTestCell, oci.RegionGRU, region.Owner, region.Generation, control, store, fleet)
	if err != nil {
		t.Fatal(err)
	}
	var controller *placement.Controller
	runtimeTarget := managedRuntimeTargetVerifier(func(ctx context.Context, desired host.Desired, registration host.Registration) (bool, error) {
		return controller.VerifyManagedRuntimeTarget(ctx, desired, registration)
	})
	cell.runtimeTarget = runtimeTarget
	credentials := managedmaterial.CredentialService{Preparation: material, Store: control}
	cell.materials = admittedManagedMaterialProvider(material, control, store, credentials, runtimeTarget)
	cell.hosts, err = host.NewController(ctx, host.ControllerConfig{Cell: deployTestCell, Conn: broker.Conn(),
		JS: broker.JetStream(), Artifacts: service.Artifacts(), StateReplicas: 1, ResponseKey: controllerPrivate,
		HostMutations: control, AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard,
		ManagedRegistrationVerifier: verifier, ManagedMaterialProvider: cell.materials,
		ManagedDesiredVerifier: func(ctx context.Context, desired host.Desired, registration host.Registration,
			current host.Desired, exists bool,
		) error {
			return controller.VerifyManagedDesired(ctx, desired, registration, current, exists)
		}})
	if err != nil {
		t.Fatal(err)
	}
	subscribe(serveHostEnrollment(ctx, broker.Conn(), deployTestCell, policy, control, cell.hosts, nil, nil))
	hostsDone := make(chan error, 1)
	go func() { hostsDone <- cell.hosts.Run(ctx) }()
	select {
	case <-cell.hosts.Ready():
	case err := <-hostsDone:
		t.Fatalf("host controller stopped: %v", err)
	}
	holds := new(placementHoldLog)
	cell.holds = holds
	controller, err = placement.StartController(ctx, placement.Config{Cell: deployTestCell, Region: oci.RegionGRU,
		FaultDomains: region.FaultDomains, ManagedOwner: region.Owner, FleetGeneration: region.Generation, ImageID: region.ImageID,
		Environment: "canary", MemberRole: "terrabase",
		Resources: placement.Resources{CPU: 1, MemoryBytes: 4 << 30, DiskBytes: 50 << 30},
		OnHold:    holds.record, OnError: func(err error) { holds.record("reconciliation error: " + err.Error()) }},
		store, control, fleet, cell.hosts, cell.hosts,
		func(ctx context.Context, digest, role, environment string) (placement.AdmittedArtifact, error) {
			record, err := service.ResolveAdmittedArtifact(ctx, digest, role, environment)
			if err != nil {
				return placement.AdmittedArtifact{}, err
			}
			return placement.AdmittedArtifact{Digest: record.Digest, ManifestDigest: record.ManifestDigest,
				SourceDigest: record.Source.TreeDigest}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	cell.placement, cell.store = controller, store
	cell.policy, cell.controllerKey = policy, controllerPrivate
	cell.status, err = servePlacementStatus(ctx, broker.Conn(), placementStatusSource{cell: deployTestCell, policy: policy,
		control: control, placements: store, hosts: cell.hosts, holds: holds, responseKey: controllerPrivate,
		owner: region.Owner, fleetGeneration: region.Generation})
	subscribe(cell.status, err)
	if err := broker.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	return cell
}

func writeDeployTestRecipientKeys(t *testing.T, root string) ed25519.PublicKey {
	t.Helper()
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]any{"recipient.pem": recipient, "signer.pem": signer, "signer.pub": public} {
		kind, der := "PRIVATE KEY", []byte(nil)
		if name == "signer.pub" {
			kind = "PUBLIC KEY"
			der, err = x509.MarshalPKIXPublicKey(key)
		} else {
			der, err = x509.MarshalPKCS8PrivateKey(key)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return public
}

// writeDeployTestPlan writes a release, its qualification and source digest,
// and a plan matching the live GRU member layout.
func writeDeployTestPlan(t *testing.T, root string, clientPort uint16) (string, string) {
	t.Helper()
	release := writeDeployTestRelease(t, root, "1")
	plan := testJSONFile(t, root, "plan.json", terrabaseDeployPlan{Version: 1,
		PlacementDatabaseID: "0000000000HX30KC7N7WJ1ZFC8", PartitionID: "00000000003ZJEV7X3HYJENEYG", Role: "terrabase", Environment: "canary",
		Release: release,
		HostProfile: placement.ManagedHostProfile{
			Compute:            placement.ComputeTuple{Shape: "VM.Standard.A1.Flex", WholeOCPUs: 1, MemoryInGBs: 6},
			ProcessMemoryBytes: 4 << 30, MemoryHeadroomBytes: 1 << 30, CgroupMemoryMaxBytes: 4 << 30,
			SystemReserveBytes: 1 << 30, AllocatableMemoryBytes: 4 << 30},
		ManagedRuntimeRoot: "/srv/ts-managed",
		Members: [2]terrabaseDeployMember{{PrivateIP: "10.251.0.21", FaultDomain: "FAULT-DOMAIN-1"},
			{PrivateIP: "10.251.0.22", FaultDomain: "FAULT-DOMAIN-2"}},
		ReplicationPort: 9443, ClientPort: clientPort,
		LiveS3: managedmaterial.LiveS3Target{Bucket: "ts-preview-gru-20260926-terrabase-live", Region: "sa-saopaulo-1",
			Endpoint:      "https://grxnmoqvrcdv.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
			Credential:    oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.livesecret", VersionNumber: 2},
			NativeOCIRoot: &managedmaterial.NativeOCIRoot{Namespace: "grxnmoqvrcdv"}},
		Collections: 1,
		Recipient: terrabaseDeployRecipient{SignerKey: filepath.Join(root, "signer.pem"),
			SignerPublicKey: filepath.Join(root, "signer.pub"), RecipientKey: filepath.Join(root, "recipient.pem"),
			GrantValidityHours: 72},
	})
	return plan, filepath.Join(root, "deployment-state")
}

// writeDeployTestRelease writes one retained TerraBase CI release whose
// server bytes and source revision are derived from version.
func writeDeployTestRelease(t *testing.T, root, version string) terrabaseReleaseFiles {
	t.Helper()
	directory := filepath.Join(root, "release-"+version)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := bytes.Repeat([]byte("tb-server-linux-arm64 release "+version+" "), 64)
	binaryPath := filepath.Join(directory, "tb-server-linux-arm64")
	if err := os.WriteFile(binaryPath, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	binarySum := sha256.Sum256(binary)
	commitSum := sha256.Sum256([]byte("commit " + version))
	commit := hex.EncodeToString(commitSum[:20])
	fields := map[string]any{"schema": terrabaseQualificationSchema, "source_revision": commit,
		"artifacts": []map[string]any{{"name": terrabaseServerArtifact, "bytes": len(binary),
			"sha256": hex.EncodeToString(binarySum[:]), "target": terrabaseServerTarget}},
		"verification": map[string]any{"conclusion": "success", "run_id": 11696, "workflow": "fast.yml"}}
	if compatibility := deployTestCompatibility(version); compatibility != nil {
		fields["compatibility"] = compatibility
	}
	qualification, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	qualificationPath := filepath.Join(directory, "qualification.json")
	if err := os.WriteFile(qualificationPath, qualification, 0o644); err != nil {
		t.Fatal(err)
	}
	qualificationSum := sha256.Sum256(qualification)
	sourceSum := sha256.Sum256([]byte("source " + version))
	sourcePath := testJSONFile(t, directory, "source-digest.json", map[string]any{"schema": terrabaseSourceDigestSchema,
		"repository": deployTestRepository, "source_revision": commit, "source_digest_sha256": hex.EncodeToString(sourceSum[:]),
		"qualification_sha256": hex.EncodeToString(qualificationSum[:]), "server_linux_arm64_sha256": hex.EncodeToString(binarySum[:])})
	return terrabaseReleaseFiles{Qualification: qualificationPath, Binary: binaryPath, SourceDigest: sourcePath}
}

// deployTestCompatibility declares every test release mutually compatible
// unless its version names an incompatible persistent format.
func deployTestCompatibility(version string) map[string]any {
	format := 1
	if strings.HasPrefix(version, "format-break") {
		format = 9
	}
	if strings.HasPrefix(version, "no-compat") {
		return nil
	}
	capability := func(version int) map[string]any {
		return map[string]any{"version": version, "accepts": map[string]any{"min": version, "max": version}}
	}
	return map[string]any{"schema": staged.CompatibilitySchema, "persistent_format": capability(format),
		"replication": capability(1), "client_data": capability(1)}
}

func runDeployTestOperatorErr(ctx context.Context, cell *deployTestCellServices, operation string, args ...string) ([]byte, error) {
	var output bytes.Buffer
	err := Run(ctx, append([]string{"operator", operation, "--config", cell.operatorFile}, args...), &output)
	return output.Bytes(), err
}

func runDeployTestOperator(t *testing.T, ctx context.Context, cell *deployTestCellServices, operation string, args ...string) []byte {
	t.Helper()
	output, err := runDeployTestOperatorErr(ctx, cell, operation, args...)
	if err != nil {
		t.Fatalf("operator %s: %v\n%s", operation, err, output)
	}
	return output
}

func deployTestSteps(t *testing.T, output []byte) []string {
	t.Helper()
	var steps []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		var step terrabaseDeployStep
		if err := json.Unmarshal(scanner.Bytes(), &step); err != nil {
			t.Fatalf("deployment output line %q: %v", scanner.Text(), err)
		}
		steps = append(steps, step.Step+":"+step.Status)
	}
	return steps
}

func readDeployTestState(t *testing.T, state, name string, value any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(state, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

func deployTestStatus(t *testing.T, ctx context.Context, cell *deployTestCellServices, state string) placementStatusReport {
	t.Helper()
	output := runDeployTestOperator(t, ctx, cell, "terrabase-status", "--state", state)
	var report placementStatusReport
	if err := json.Unmarshal(bytes.TrimSpace(output), &report); err != nil {
		t.Fatalf("decode status %q: %v", output, err)
	}
	return report
}

// tickUntil drives the placement controller one bounded action at a time and
// reports tick errors through the hold log, as the controller's Run loop does.
func (cell *deployTestCellServices) tickUntil(t *testing.T, done func(map[string]placement.MemberState) bool) {
	t.Helper()
	ctx := t.Context()
	var lastErr error
	for range 64 {
		intents, err := cell.store.ListIntents(ctx)
		if err != nil || len(intents) != 1 {
			t.Fatalf("admitted intents = %d, %v", len(intents), err)
		}
		members, err := cell.store.ListMembers(ctx, intents[0].DatabaseID, intents[0].PartitionID)
		if err != nil {
			t.Fatal(err)
		}
		byID := make(map[string]placement.MemberState, len(members))
		for _, member := range members {
			byID[member.State.MemberID] = member.State
		}
		if done(byID) {
			return
		}
		if err := cell.placement.Tick(ctx); err != nil {
			lastErr = err
			cell.holds.record("reconciliation error: " + err.Error())
		}
	}
	t.Fatalf("placement did not reach the expected stage; last tick error: %v", lastErr)
}

// enrollMembers registers each launched host exactly as managed enrollment
// does and runs its agent until the controller sees a current session.
func (cell *deployTestCellServices) enrollMembers(t *testing.T, intent placement.Intent) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	var done []chan error
	for _, seat := range []string{"000000000082AXF7GZQT1D126Y", "0000000000XG8SBD7XGE97V28G"} {
		member, err := cell.store.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, seat)
		if err != nil {
			t.Fatal(err)
		}
		state := member.State
		hostPublic, hostPrivate := testEd25519(t, cell.root, seat+"-host.key")
		hostNKey, _ := testNKey(t)
		row, roster := state.CanonicalRosterRow, intent.CanonicalRoster
		registration := host.Registration{Cell: deployTestCell, Node: state.HostNode, FailureDomain: row.FailureDomain,
			Environment: "canary", Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(hostPublic),
			NATSUserPublicKey: hostNKey, Generation: 1,
			Capacity: host.Capacity{CPU: 1, MemoryBytes: int64(state.ManagedHostProfile.AllocatableMemoryBytes),
				DiskBytes: 50 << 30},
			SystemReserveBytes: int64(state.ManagedHostProfile.SystemReserveBytes),
			ManagedPlacement: &host.ManagedPlacementBinding{DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
				SeatID: seat, IntentGeneration: intent.Generation, IntentPayloadDigest: state.IntentPayloadDigest,
				CanonicalRosterDigest: state.CanonicalRosterDigest, ManagedHostProfileDigest: state.ManagedHostProfileDigest},
			ManagedMember: &host.ManagedMemberBinding{Scope: host.MemberScope{ClusterID: roster.ClusterID,
				TenantID: roster.TenantID, DatabaseID: roster.DatabaseID, ShardID: roster.ShardID,
				MemberID: row.MemberID, Incarnation: row.Incarnation}, HostAttempt: state.HostAttempt},
			ManagedOCI: &host.ManagedOCIBinding{Region: string(oci.RegionGRU), InstanceID: state.InstanceID,
				Owner: deployTestOwner, FleetGeneration: 1, CreateKey: state.CreateKey}}
		path := testJSONFile(t, cell.root, seat+"-registration.json", registration)
		if _, err := runDeployTestOperatorErr(ctx, cell, "host-register", "--registration", path); err != nil {
			t.Fatalf("register %s: %v", seat, err)
		}
		connection, err := natscell.Start(ctx, natscell.Config{Cell: deployTestCell, Instance: "host-" + strings.ToLower(seat), Replicas: 1,
			Lab: true, URL: cell.broker.URL(), ClientRole: "host"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connection.Close() })
		agent, err := host.NewAgent(host.AgentConfig{Cell: deployTestCell, Node: state.HostNode, Environment: "canary",
			Roles: []string{"terrabase"}, Conn: connection.Conn(), Identity: hostPrivate, NATSUserPublicKey: hostNKey,
			ControllerPublicKey: cell.responseKey, Runner: &inMemoryRunner{},
			InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t), WorkloadIdentity: testHostWorkloadIdentity(),
			PollInterval: 100 * time.Millisecond, ClockCheck: func() error { return nil }})
		if err != nil {
			t.Fatal(err)
		}
		finished := make(chan error, 1)
		done = append(done, finished)
		go func() { finished <- agent.Run(ctx) }()
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		statuses, err := cell.hosts.ListHosts(ctx)
		current := 0
		for _, status := range statuses {
			if status.Verified && status.SessionExpiresAt.After(time.Now().Add(5*time.Second)) {
				current++
			}
		}
		if err == nil && current == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("hosts did not establish current sessions: %+v %v", statuses, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return func() {
		cancel()
		for _, finished := range done {
			<-finished
		}
	}
}

func TestTerraBaseDeployPlanKeepsGRUMembersOnTheirNamedSlots(t *testing.T) {
	root := t.TempDir()
	path, _ := writeDeployTestPlan(t, root, 9465)
	plan, _, err := loadTerraBaseDeployPlan(path, "gru")
	if err != nil {
		t.Fatal(err)
	}
	plan.Members[0], plan.Members[1] = plan.Members[1], plan.Members[0]
	swapped := testJSONFile(t, root, "swapped.json", plan)
	if _, _, err := loadTerraBaseDeployPlan(swapped, "gru"); err == nil || !strings.Contains(err.Error(), "gru-1-db-1") {
		t.Fatalf("member 1 on gru-1-db-2's address was accepted: %v", err)
	}
}
