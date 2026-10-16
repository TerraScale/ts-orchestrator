package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
	"github.com/nats-io/nats.go/jetstream"
)

func TestManagedPlacementEnrollmentThroughSignedOperatorAndCurrentHostSession(t *testing.T) {
	for _, testCase := range []struct {
		cell   string
		region oci.Region
	}{
		{cell: "gru", region: oci.RegionGRU},
		{cell: "sfo", region: oci.RegionSFO},
	} {
		t.Run(testCase.cell, func(t *testing.T) {
			testManagedPlacementEnrollmentThroughSignedOperatorAndCurrentHostSession(t, testCase.cell, testCase.region, nil)
		})
	}
}

func TestManagedPlacementEnrollmentFromRenderedSFOBundle(t *testing.T) {
	bundlePath, bundleSet := os.LookupEnv("TS_TEST_RENDERED_HOST_BUNDLE")
	materialDirectory, materialSet := os.LookupEnv("TS_TEST_RENDERED_HOST_MATERIAL")
	expectedBundleSHA256, hashSet := os.LookupEnv("TS_TEST_RENDERED_HOST_BUNDLE_SHA256")
	if !bundleSet && !materialSet && !hashSet {
		tier.Unavailable(t, "rendered SFO enrollment bundle fixture was not supplied")
	}
	if !bundleSet || !materialSet || !hashSet || bundlePath == "" || materialDirectory == "" || expectedBundleSHA256 == "" {
		t.Fatal("rendered SFO enrollment requires bundle, material directory, and bundle SHA-256 together")
	}
	fixture := loadRenderedSFOEnrollmentFixture(t, bundlePath, materialDirectory, expectedBundleSHA256)
	testManagedPlacementEnrollmentThroughSignedOperatorAndCurrentHostSession(t, "sfo", oci.RegionSFO, fixture)
}

type renderedSFOEnrollmentFixture struct {
	bundle            hostenroll.PublicBundle
	issuer            *hostenroll.Issuer
	serverCertificate tls.Certificate
	responsePublic    ed25519.PublicKey
	responsePrivate   ed25519.PrivateKey
}

func loadRenderedSFOEnrollmentFixture(t *testing.T, bundlePath, materialDirectory, expectedBundleSHA256 string) *renderedSFOEnrollmentFixture {
	t.Helper()
	if !filepath.IsAbs(bundlePath) || filepath.Clean(bundlePath) != bundlePath ||
		!filepath.IsAbs(materialDirectory) || filepath.Clean(materialDirectory) != materialDirectory {
		t.Fatal("rendered SFO bundle and material paths must be clean and absolute")
	}
	if len(expectedBundleSHA256) != sha256.Size*2 {
		t.Fatalf("rendered SFO bundle SHA-256 has invalid length: %d", len(expectedBundleSHA256))
	}
	if _, err := hex.DecodeString(expectedBundleSHA256); err != nil || strings.ToLower(expectedBundleSHA256) != expectedBundleSHA256 {
		t.Fatal("rendered SFO bundle SHA-256 must be lowercase hexadecimal")
	}
	bundleWire, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read exact rendered SFO public bundle bytes: %v", err)
	}
	digest := sha256.Sum256(bundleWire)
	gotBundleSHA256 := hex.EncodeToString(digest[:])
	if gotBundleSHA256 != expectedBundleSHA256 {
		t.Fatalf("rendered SFO public bundle hash mismatch: got %s, want %s", gotBundleSHA256, expectedBundleSHA256)
	}
	bundle, err := hostenroll.ReadPublicBundle(bundlePath)
	if err != nil {
		t.Fatalf("read root-owned rendered SFO public bundle: %v", err)
	}
	canonical, err := protocol.EncodeJSON(bundle)
	if err != nil || !bytes.Equal(bundleWire, canonical) {
		t.Fatalf("rendered SFO public bundle bytes are not the exact parsed image input: %v", err)
	}
	wantControllers := []string{"10.0.0.11:8443", "10.0.0.12:8443", "10.0.0.13:8443"}
	wantNATS := []string{"tls://10.0.0.11:4222", "tls://10.0.0.12:4222", "tls://10.0.0.13:4222"}
	if bundle.SchemaVersion != 1 || bundle.Cell != "sfo" || bundle.Region != "SFO" || bundle.Environment != "production" ||
		!slices.Equal(bundle.ControllerEndpoints, wantControllers) || !slices.Equal(bundle.NATSURLs, wantNATS) ||
		bundle.InstallRoot != "/var/lib/terrascale-orchestrator-host/install" ||
		bundle.StateRoot != "/var/lib/terrascale-orchestrator-host/state" || bundle.ManagedRuntimeRoot != "/srv/ts-managed" ||
		bundle.WorkloadUID != 2000 || bundle.WorkloadGID != 2000 {
		t.Fatalf("rendered SFO public bundle has unexpected image identity or configuration: %+v", bundle)
	}
	caWire, err := os.ReadFile(filepath.Join(materialDirectory, "ca.pem"))
	if err != nil || !bytes.Equal(caWire, []byte(bundle.CAPEM)) {
		t.Fatalf("rendered bundle CA does not match generated private material: %v", err)
	}
	responsePrivate, err := readPrivateKey(filepath.Join(materialDirectory, "controller-a-response.key"))
	if err != nil {
		t.Fatalf("load matching controller response key: %v", err)
	}
	responsePublic, err := bundle.ResponsePublicKey()
	if err != nil || !bytes.Equal(responsePublic, responsePrivate.Public().(ed25519.PublicKey)) {
		clear(responsePrivate)
		t.Fatalf("rendered bundle response key does not match generated material: %v", err)
	}
	issuer, err := hostenroll.LoadIssuer("sfo", bundle.CellAccountNKey,
		filepath.Join(materialDirectory, "host-nats-issuer.seed"),
		filepath.Join(materialDirectory, "host-tls-issuer-key.pem"),
		filepath.Join(materialDirectory, "host-tls-issuer-cert.pem"), caWire)
	if err != nil {
		clear(responsePrivate)
		t.Fatalf("load matching generated SFO host issuer: %v", err)
	}
	t.Cleanup(func() {
		issuer.NATSKey.Wipe()
		clear(responsePrivate)
	})
	cellJWT, err := os.ReadFile(filepath.Join(materialDirectory, "cell.jwt"))
	if err != nil {
		t.Fatalf("generated SFO cell account does not authorize the host issuer: %v", err)
	}
	if err := issuer.ValidateAccountScope(strings.TrimSpace(string(cellJWT))); err != nil {
		t.Fatalf("generated SFO cell account does not authorize the host issuer: %v", err)
	}
	serverCertificate, err := tls.LoadX509KeyPair(
		filepath.Join(materialDirectory, "controller-a-tls-cert.pem"),
		filepath.Join(materialDirectory, "controller-a-tls-key.pem"))
	if err != nil {
		t.Fatalf("load matching generated SFO controller TLS identity: %v", err)
	}
	t.Logf("using rendered SFO enrollment public bundle sha256=%s", gotBundleSHA256)
	return &renderedSFOEnrollmentFixture{bundle: bundle, issuer: issuer, serverCertificate: serverCertificate,
		responsePublic: responsePublic, responsePrivate: responsePrivate}
}

func testManagedPlacementEnrollmentThroughSignedOperatorAndCurrentHostSession(
	t *testing.T, cell string, regionID oci.Region, rendered *renderedSFOEnrollmentFixture,
) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	root := t.TempDir()
	broker, err := natscell.Start(ctx, natscell.Config{
		Cell: cell, Instance: "managed-enrollment", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(root, "nats")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: cell, CandidateID: "0000000000E907NSBAGPHGG5DT", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	if !control.Current().CanMutate() {
		t.Fatal("regional authority did not acquire a mutable lease")
	}
	operatorPublic, _ := testEd25519(t, root, "operator.key")
	var controllerPublic ed25519.PublicKey
	var controllerPrivate ed25519.PrivateKey
	if rendered == nil {
		controllerPublic, controllerPrivate = testEd25519(t, root, "controller.key")
	} else {
		controllerPublic, controllerPrivate = rendered.responsePublic, rendered.responsePrivate
	}
	hostPublic, hostPrivate := testEd25519(t, root, "host.key")
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(operatorPublic),
		Roles: []string{"terrabase"}, Environments: []string{"production"}, CanRegisterHosts: true, CanPlaceTerraBase: true}
	policy, err := buildSignerPolicy(Config{NATS: natscell.Config{Cell: cell}, Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}}})
	if err != nil {
		t.Fatal(err)
	}
	operatorConfig := testJSONFile(t, root, "operator.json", Config{Version: ConfigVersion,
		NATS: natscell.Config{Cell: cell, Instance: "enrollment-operator", Replicas: 1, Lab: true,
			URL: broker.URL()},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(root, "operator.key")},
	})
	placementSubscription, err := servePlacementAdmission(ctx, broker.Conn(), cell, policy, control)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = placementSubscription.Unsubscribe() })
	if err := broker.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	apply := func(name string, intent placement.Intent) placementApplyResponse {
		t.Helper()
		path := testJSONFile(t, root, name, intent)
		var output bytes.Buffer
		if err := Run(ctx, []string{"operator", "placement-apply", "--config", operatorConfig, "--intent", path}, &output); err != nil {
			t.Fatalf("signed placement apply: %v", err)
		}
		var receipt placementApplyResponse
		if err := json.Unmarshal(output.Bytes(), &receipt); err != nil || receipt.Sequence == 0 {
			t.Fatalf("placement receipt: %+v, %v", receipt, err)
		}
		return receipt
	}
	intent := testManagedPlacementIntentForRegions(regionID)
	first := apply("placement-7.json", intent)
	entry, err := control.ReadPlacementIntent(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil || entry.Sequence != first.Sequence || entry.SubjectKey != intent.DatabaseID+"."+intent.PartitionID {
		t.Fatalf("real authority readback: entry=%+v err=%v", entry, err)
	}
	admitted, err := placement.NewAuthorityIntentReader(control, cell, regionID)
	if err != nil {
		t.Fatal(err)
	}
	store, err := placement.NewJetStreamStore(ctx, broker.JetStream(), cell, 1, admitted)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := oci.OpenJournal(ctx, broker.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	ociRegion, err := regionID.OCIRegion()
	if err != nil {
		t.Fatal(err)
	}
	regionMappings := []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}
	if regionID != oci.RegionGRU {
		regionMappings = append(regionMappings, oci.RegionMapping{Cell: regionID, OCIRegion: ociRegion})
	}
	regionIntent := oci.RegionIntent{SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU,
		Regions: regionMappings}
	region := oci.RegionConfig{Region: regionID, Generation: 1,
		Endpoint:           "https://iaas." + ociRegion + ".oraclecloud.com",
		CompartmentID:      "ocid1.compartment.oc1." + ociRegion + ".owned",
		ImageCompartmentID: "ocid1.compartment.oc1." + ociRegion + ".image",
		AvailabilityDomain: "AD-1", FaultDomains: []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"},
		SubnetID:                "ocid1.subnet.oc1." + ociRegion + ".owned",
		ImageID:                 "ocid1.image.oc1." + ociRegion + ".owned",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1." + ociRegion + ".owned"},
		BootVolumeGB:            50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 50,
		Shape: "VM.Standard.E4.Flex", Owner: "regional-owner"}
	provider := &managedEnrollmentProvider{placementSizingProvider: &placementSizingProvider{config: region}}
	fleet, err := oci.NewFleetWithImageVerifier(region, regionIntent, provider, journal, control, nil, nil, acceptingImageVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := newManagedRegistrationVerifier(cell, regionID, region.Owner, region.Generation, control, store, fleet)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := broker.JetStream().CreateObjectStore(ctx, jetstream.ObjectStoreConfig{
		Bucket: "ENROLLMENT_ARTIFACTS", Storage: jetstream.FileStorage, Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	hostController, err := host.NewController(ctx, host.ControllerConfig{
		Cell: cell, Conn: broker.Conn(), JS: broker.JetStream(), Artifacts: artifacts,
		StateReplicas: 1, ResponseKey: controllerPrivate, HostMutations: control,
		AuthorityEpoch: func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard,
		ManagedRegistrationVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	grants, err := hostenroll.OpenGrantStore(ctx, broker.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	managedEnrollment := &managedHostEnrollment{cell: cell, region: regionID,
		owner: region.Owner, generation: region.Generation, environment: "production", diskBytes: 32 << 30,
		fleet: fleet, intents: control, members: store, controller: hostController,
		verifier: verifier, grants: grants, fencer: control}
	hostSubscription, err := serveHostEnrollment(ctx, broker.Conn(), cell, policy, control, hostController, managedEnrollment, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hostSubscription.Unsubscribe() })
	hostRunDone := make(chan error, 1)
	go func() { hostRunDone <- hostController.Run(ctx) }()
	select {
	case <-hostController.Ready():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	controller, err := placement.StartController(ctx, placement.Config{
		Cell: cell, Region: regionID, FaultDomains: region.FaultDomains,
		ManagedOwner: region.Owner, FleetGeneration: region.Generation,
		ImageID:     region.ImageID,
		Environment: "production", MemberRole: "terrabase",
		Resources: placement.Resources{CPU: 1, MemoryBytes: 1 << 30, DiskBytes: 32 << 30},
	}, store, control, fleet, hostController, hostController, testPlacementAdmittedArtifact(intent))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := controller.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	seatID := permanentSeatID(regionID)
	member, err := store.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, seatID)
	if err != nil || member.State.Stage != placement.StageAwaitingHost || member.Revision == 0 || len(provider.launches) != 1 {
		t.Fatalf("durable placement did not launch one OCI host: member=%+v launches=%d err=%v", member, len(provider.launches), err)
	}
	observed, err := fleet.Observe(ctx)
	if err != nil || len(observed) != 1 || observed[0].ID != member.State.InstanceID {
		t.Fatalf("OCI reobservation: instances=%+v err=%v", observed, err)
	}
	bootBinding, found, err := journal.GetBootBinding(ctx, observed[0].ID)
	if err != nil || !found || bootBinding.InstanceID != observed[0].ID ||
		bootBinding.BootVolumeID != provider.bootVolume.ID || bootBinding.Region != regionID ||
		bootBinding.Generation != region.Generation || bootBinding.Owner != region.Owner ||
		bootBinding.CreateKey != observed[0].CreateKey || bootBinding.CompartmentID != region.CompartmentID ||
		bootBinding.ImageID != region.ImageID || bootBinding.SizeGB != int64(region.BootVolumeGB) ||
		bootBinding.VPUsPerGB != int64(region.BootVolumeVPUsPerGB) {
		t.Fatalf("managed launch did not persist exact boot ownership: binding=%+v found=%v err=%v", bootBinding, found, err)
	}
	provider.instance.LifecycleState = "RUNNING"
	descriptorWire := provider.launches[0].BootDescriptor
	descriptor, err := hostboot.Parse([]byte(descriptorWire))
	if err != nil {
		t.Fatal(err)
	}
	if observed[0].Region != regionID || descriptor.Cell != cell || descriptor.Region != string(regionID) ||
		!strings.Contains(observed[0].ID, "."+ociRegion+".") {
		t.Fatalf("launched host has wrong regional identity: instance=%+v descriptor=%+v", observed[0], descriptor)
	}
	var bundle hostenroll.PublicBundle
	var issuer *hostenroll.Issuer
	var serverCertificate tls.Certificate
	if rendered == nil {
		bundle, issuer, serverCertificate = testHostEnrollmentTLSMaterial(t, controllerPublic)
		bundle.Cell = cell
		bundle.Region = string(regionID)
		issuer.Cell = cell
	} else {
		bundle, issuer, serverCertificate = rendered.bundle, rendered.issuer, rendered.serverCertificate
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("%s host enrollment public bundle: %v", cell, err)
	}
	if rendered != nil && bundle.ControllerEndpoints[0] != observed[0].PrivateIP+":8443" {
		t.Fatalf("first same-cell controller endpoint %q does not match launched host private IP %q",
			bundle.ControllerEndpoints[0], observed[0].PrivateIP)
	}
	if regionID == oci.RegionSFO {
		gruDescriptor := descriptor
		gruDescriptor.Cell = "gru"
		gruDescriptor.Region = string(oci.RegionGRU)
		gruWire, err := gruDescriptor.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		postCalls := 0
		mismatchErr := runHostSetupWithMetadata(ctx, bundle, hostenroll.InstanceMetadata{
			InstanceID: observed[0].ID, Descriptor: gruDescriptor, Wire: gruWire,
		}, t.TempDir(), &bytes.Buffer{}, hostSetupRuntime{ownerUID: uint32(os.Geteuid()),
			post: func(context.Context, hostenroll.PublicBundle, []byte) ([]byte, error) {
				postCalls++
				return nil, errors.New("mismatched descriptor reached the enrollment endpoint")
			}})
		if mismatchErr == nil || !strings.Contains(mismatchErr.Error(), "differs from image-pinned regional bundle") || postCalls != 0 {
			t.Fatalf("SFO bundle accepted a GRU descriptor: err=%v post calls=%d", mismatchErr, postCalls)
		}
	}
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	hostNKey, hostSeedPath := testNKey(t)
	enrollmentRequest := hostenroll.Request{SchemaVersion: 1, Operation: "enroll",
		InstanceID: observed[0].ID, Descriptor: descriptorWire,
		IdentityPublicKey: base64.StdEncoding.EncodeToString(hostPublic), NATSUserPublicKey: hostNKey,
		CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		Nonce:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), IssuedAt: time.Now().UTC().Add(-49 * time.Hour)}
	if err := enrollmentRequest.Sign(hostPrivate); err != nil {
		t.Fatal(err)
	}
	requestWire, err := protocol.EncodeJSON(enrollmentRequest)
	if err != nil {
		t.Fatal(err)
	}
	invalidCSRDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{DNSNames: []string{"controller.terrascale.internal"}}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	invalidRequest := enrollmentRequest
	invalidRequest.CSRPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: invalidCSRDER}))
	if err := invalidRequest.Sign(hostPrivate); err != nil {
		t.Fatal(err)
	}
	invalidWire, err := protocol.EncodeJSON(invalidRequest)
	if err != nil {
		t.Fatal(err)
	}
	invalidHTTP := httptest.NewRequest(http.MethodPost, "https://"+observed[0].PrivateIP+":8443/v1/host-enrollment", bytes.NewReader(invalidWire))
	invalidHTTP.RemoteAddr = observed[0].PrivateIP + ":44321"
	invalidReply := httptest.NewRecorder()
	managedEnrollment.ServeHTTP(invalidReply, invalidHTTP)
	if invalidReply.Code != http.StatusBadRequest {
		t.Fatalf("caller-selected CSR scope reached enrollment: status=%d", invalidReply.Code)
	}
	if _, _, err := grants.Read(ctx, observed[0].ID); err == nil {
		t.Fatal("invalid CSR created a durable enrollment grant")
	}
	descriptorDigest, err := descriptor.Digest()
	if err != nil {
		t.Fatal(err)
	}
	claimed, claimRevision, err := grants.Claim(ctx, hostenroll.Grant{SchemaVersion: 1, InstanceID: observed[0].ID,
		CreateKey: descriptor.CreateKey, DescriptorSHA256: descriptorDigest, Request: requestWire})
	if err != nil {
		t.Fatal(err)
	}
	managedEnrollment.issuer = issuer
	managedEnrollment.responseKey = controllerPrivate
	csr, err := hostenroll.ParseCSR(enrollmentRequest.CSRPEM)
	if err != nil {
		t.Fatal(err)
	}
	issuedJWT, issuedChain, issuedExpiry, err := issuer.Issue(enrollmentRequest, csr, descriptor.Node, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	completed := hostenroll.Response{SchemaVersion: 1, Operation: "enroll", InstanceID: enrollmentRequest.InstanceID,
		Node: descriptor.Node, DescriptorSHA256: descriptorDigest,
		RequestSHA256: hostenroll.RequestSHA256(requestWire), Nonce: enrollmentRequest.Nonce,
		RegistrationReceipt: host.Receipt{Generation: 1, Revision: 1},
		NATSUserJWT:         issuedJWT, TLSCertificatePEM: string(issuedChain), ExpiresAt: issuedExpiry}
	if err := completed.Sign(controllerPrivate); err != nil {
		t.Fatal(err)
	}
	completedWire, err := protocol.EncodeJSON(completed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grants.Finish(ctx, claimed, claimRevision, completedWire); err != nil {
		t.Fatal(err)
	}
	replayHTTP := httptest.NewRequest(http.MethodPost, "https://"+observed[0].PrivateIP+":8443/v1/host-enrollment", bytes.NewReader(requestWire))
	replayHTTP.RemoteAddr = observed[0].PrivateIP + ":44321"
	replayReply := httptest.NewRecorder()
	managedEnrollment.ServeHTTP(replayReply, replayHTTP)
	if replayReply.Code != http.StatusOK || !bytes.Equal(replayReply.Body.Bytes(), completedWire) {
		_, heldErr := managedEnrollment.enroll(ctx, control.Current().Epoch, observed[0].PrivateIP,
			requestWire, enrollmentRequest, descriptor)
		t.Fatalf("exact >48h grant replay: status=%d held=%v", replayReply.Code, heldErr)
	}
	priorIP := provider.instance.PrivateIP
	provider.instance.PrivateIP = "10.251.0.99"
	stalePeerHTTP := httptest.NewRequest(http.MethodPost, "https://"+observed[0].PrivateIP+":8443/v1/host-enrollment", bytes.NewReader(requestWire))
	stalePeerHTTP.RemoteAddr = observed[0].PrivateIP + ":44321"
	stalePeerReply := httptest.NewRecorder()
	managedEnrollment.ServeHTTP(stalePeerReply, stalePeerHTTP)
	provider.instance.PrivateIP = priorIP
	if stalePeerReply.Code != http.StatusConflict {
		t.Fatalf("stale OCI peer replay status=%d", stalePeerReply.Code)
	}
	setupRoot := t.TempDir()
	hostSeed, err := os.ReadFile(hostSeedPath)
	if err != nil {
		t.Fatal(err)
	}
	tlsKeyDER, err := x509.MarshalECPrivateKey(csrKey)
	if err != nil {
		t.Fatal(err)
	}
	pending := pendingHostEnrollment{InstanceID: enrollmentRequest.InstanceID,
		IdentityKey:   base64.StdEncoding.EncodeToString(hostPrivate),
		NATSUserSeed:  base64.StdEncoding.EncodeToString(hostSeed),
		TLSPrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: tlsKeyDER})),
		Request:       requestWire}
	pendingWire, err := protocol.EncodeJSON(pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(setupRoot, pendingHostEnrollmentFile), pendingWire, 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.RemoteAddr = observed[0].PrivateIP + ":44321"
		managedEnrollment.ServeHTTP(writer, request)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	networkOutage := false
	dropNextResponse := false
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if networkOutage || address != bundle.ControllerEndpoints[0] {
			return nil, errors.New("unused test controller is unavailable")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	setupRuntime := hostSetupRuntime{ownerUID: uint32(os.Geteuid()),
		post: func(ctx context.Context, pinned hostenroll.PublicBundle, wire []byte) ([]byte, error) {
			if pinned.Cell != cell || pinned.Region != string(regionID) {
				return nil, errors.New("host enrollment used a controller bundle from another cell")
			}
			response, err := postHostEnrollmentWithDial(ctx, pinned, wire, dial)
			if err == nil && dropNextResponse {
				dropNextResponse = false
				return nil, errors.New("test response lost after durable grant commit")
			}
			return response, err
		}}
	setupMetadata := hostenroll.InstanceMetadata{InstanceID: enrollmentRequest.InstanceID,
		Descriptor: descriptor, Wire: []byte(descriptorWire)}
	if err := runHostSetupWithMetadata(ctx, bundle, setupMetadata, setupRoot, &bytes.Buffer{}, setupRuntime); err != nil {
		t.Fatalf("guest TLS exact-response replay and installation: %v", err)
	}
	installedConfig, err := os.ReadFile(filepath.Join(setupRoot, "host.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(installedConfig, []byte(descriptor.Node)) {
		t.Fatal("guest did not install the enrolled host configuration")
	}
	if rendered != nil {
		var installed Config
		if err := json.Unmarshal(installedConfig, &installed); err != nil {
			t.Fatalf("decode installed host configuration from rendered bundle: %v", err)
		}
		if installed.NATS.Cell != "sfo" || installed.NATS.Instance != descriptor.Node ||
			installed.NATS.URL != strings.Join(bundle.NATSURLs, ",") || installed.NATS.Replicas != 3 ||
			installed.Host.Node != descriptor.Node || installed.Host.Environment != "production" ||
			!slices.Equal(installed.Host.Roles, []string{"terrabase"}) ||
			installed.Host.ControllerPublicKey != bundle.ControllerResponsePublicKey ||
			installed.Host.InstallRoot != "/var/lib/terrascale-orchestrator-host/install" ||
			installed.Host.StateRoot != "/var/lib/terrascale-orchestrator-host/state" ||
			installed.Host.ManagedRuntimeRoot != "/srv/ts-managed" || installed.Host.WorkloadUID != 2000 || installed.Host.WorkloadGID != 2000 {
			t.Fatalf("installed host configuration differs from rendered SFO image fields: %+v", installed)
		}
	}
	row := member.State.CanonicalRosterRow
	roster := intent.CanonicalRoster
	registration := host.Registration{
		Cell: cell, Node: member.State.HostNode, FailureDomain: row.FailureDomain,
		Environment: "production", Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(hostPublic), NATSUserPublicKey: hostNKey,
		Generation: 1, Capacity: host.Capacity{CPU: 1, MemoryBytes: int64(member.State.ManagedHostProfile.AllocatableMemoryBytes), DiskBytes: 32 << 30},
		SystemReserveBytes: int64(member.State.ManagedHostProfile.SystemReserveBytes),
		ManagedPlacement: &host.ManagedPlacementBinding{
			DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID, SeatID: row.SeatID,
			IntentGeneration: intent.Generation, IntentPayloadDigest: member.State.IntentPayloadDigest,
			CanonicalRosterDigest: member.State.CanonicalRosterDigest, ManagedHostProfileDigest: member.State.ManagedHostProfileDigest,
		},
		ManagedMember: &host.ManagedMemberBinding{Scope: host.MemberScope{
			ClusterID: roster.ClusterID, TenantID: roster.TenantID, DatabaseID: roster.DatabaseID,
			ShardID: roster.ShardID, MemberID: row.MemberID, Incarnation: row.Incarnation,
		}, HostAttempt: member.State.HostAttempt},
		ManagedOCI: &host.ManagedOCIBinding{Region: string(observed[0].Region), InstanceID: observed[0].ID,
			Owner: observed[0].Owner, FleetGeneration: observed[0].Generation, CreateKey: observed[0].CreateKey},
	}
	register := func(name string, value host.Registration) error {
		t.Helper()
		path := testJSONFile(t, root, name, value)
		return Run(ctx, []string{"operator", "host-register", "--config", operatorConfig, "--registration", path}, &bytes.Buffer{})
	}
	stale := registration
	stalePlacement := *registration.ManagedPlacement
	stalePlacement.IntentPayloadDigest = strings.Repeat("a", 64)
	stale.ManagedPlacement = &stalePlacement
	if err := register("stale-registration.json", stale); err == nil {
		t.Fatal("signed stale placement digest enrolled a host")
	}
	if statuses, err := hostController.ListHosts(ctx); err != nil || len(statuses) != 0 {
		t.Fatalf("rejected registration reached host discovery: statuses=%+v err=%v", statuses, err)
	}
	if err := register("registration.json", registration); err != nil {
		t.Fatalf("signed exact managed host registration: %v", err)
	}
	hostRuntime, err := natscell.Start(ctx, natscell.Config{Cell: cell, Instance: "enrolled-host", Replicas: 1,
		Lab: true, URL: broker.URL(), ClientRole: "host"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hostRuntime.Close() })
	agent, err := host.NewAgent(host.AgentConfig{
		Cell: cell, Node: registration.Node, Environment: "production", Roles: []string{"terrabase"},
		Conn: hostRuntime.Conn(), Identity: hostPrivate, NATSUserPublicKey: hostNKey, ControllerPublicKey: controllerPublic,
		Runner: &inMemoryRunner{}, InstallRoot: testHostInstallRoot(t), StateRoot: testHostStateRoot(t),
		WorkloadIdentity: testHostWorkloadIdentity(),
		PollInterval:     100 * time.Millisecond, ClockCheck: func() error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx) }()
	for {
		statuses, err := hostController.ListHosts(ctx)
		if err == nil && len(statuses) == 1 && statuses[0].Verified && statuses[0].SessionExpiresAt.After(time.Now().Add(5*time.Second)) {
			break
		}
		select {
		case err := <-agentDone:
			t.Fatalf("host agent exited before current session: %v", err)
		case <-ctx.Done():
			t.Fatal("host did not establish current session: ", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err := controller.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	member, err = store.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, row.SeatID)
	if err != nil || member.State.Stage != placement.StagePreparedVolume || member.State.HostGeneration != registration.Generation || provider.volumeCalls != 0 {
		t.Fatalf("current enrolled host did not reach volume preparation: member=%+v volumes=%d err=%v", member, provider.volumeCalls, err)
	}
	if rendered != nil {
		// The rendered fixture uses fresh 48-hour credentials, outside the renewal
		// window. The original GRU/SFO fixtures continue through renewal, replay,
		// outage, OCI-retirement, and revoke coverage below.
		cancel()
		if err := <-hostRunDone; !errors.Is(err, context.Canceled) {
			t.Fatalf("host controller shutdown: %v", err)
		}
		if err := <-agentDone; !errors.Is(err, context.Canceled) {
			t.Fatalf("host agent shutdown: %v", err)
		}
		return
	}
	dropNextResponse = true
	if err := runHostSetupWithMetadata(ctx, bundle, setupMetadata, setupRoot, &bytes.Buffer{}, setupRuntime); err == nil {
		t.Fatal("guest renewal did not observe the simulated lost HTTPS response")
	}
	lostRenewal, err := os.ReadFile(filepath.Join(setupRoot, ".host-enrollment-renewal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if currentConfig, err := os.ReadFile(filepath.Join(setupRoot, "host.json")); err != nil || !bytes.Equal(currentConfig, installedConfig) {
		t.Fatalf("lost response changed installed host credentials: %v", err)
	}
	claimedRenewal, _, err := grants.Read(ctx, observed[0].ID)
	if err != nil || !bytes.Equal(claimedRenewal.RenewalRequest, lostRenewal) || len(claimedRenewal.RenewalResponse) == 0 {
		t.Fatalf("lost response was not committed for exact renewal replay: grant=%+v err=%v", claimedRenewal, err)
	}
	if err := runHostSetupWithMetadata(ctx, bundle, setupMetadata, setupRoot, &bytes.Buffer{}, setupRuntime); err != nil {
		t.Fatalf("guest TLS renewal exact replay: %v", err)
	}
	if _, err := os.Stat(filepath.Join(setupRoot, ".host-enrollment-renewal.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed renewal left a retry request: %v", err)
	}
	installedConfig, err = os.ReadFile(filepath.Join(setupRoot, "host.json"))
	if err != nil {
		t.Fatal(err)
	}
	networkOutage = true
	if err := runHostSetupWithMetadata(ctx, bundle, setupMetadata, setupRoot, &bytes.Buffer{}, setupRuntime); err == nil {
		t.Fatal("guest renewal succeeded during a complete HTTPS outage")
	}
	unclaimedWire, err := os.ReadFile(filepath.Join(setupRoot, ".host-enrollment-renewal.json"))
	if err != nil {
		t.Fatal(err)
	}
	unclaimed, err := parsePersistedHostRequest(unclaimedWire)
	if err != nil {
		t.Fatal(err)
	}
	unclaimed.IssuedAt = time.Now().UTC().Add(-6 * time.Minute)
	if err := unclaimed.Sign(hostPrivate); err != nil {
		t.Fatal(err)
	}
	unclaimedWire, err = protocol.EncodeJSON(unclaimed)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicHostFile(filepath.Join(setupRoot, ".host-enrollment-renewal.json"), unclaimedWire, 0o600); err != nil {
		t.Fatal(err)
	}
	if currentConfig, err := os.ReadFile(filepath.Join(setupRoot, "host.json")); err != nil || !bytes.Equal(currentConfig, installedConfig) {
		t.Fatalf("HTTPS outage changed installed host credentials: %v", err)
	}
	networkOutage = false
	if err := runHostSetupWithMetadata(ctx, bundle, setupMetadata, setupRoot, &bytes.Buffer{}, setupRuntime); err != nil {
		t.Fatalf("guest did not refresh stale unclaimed renewal after HTTPS outage: %v", err)
	}
	refreshedGrant, _, err := grants.Read(ctx, observed[0].ID)
	if err != nil || bytes.Equal(refreshedGrant.RenewalRequest, unclaimedWire) || len(refreshedGrant.RenewalResponse) == 0 {
		t.Fatalf("stale unclaimed request was not durably refreshed: grant=%+v err=%v", refreshedGrant, err)
	}
	retiredInstance := provider.instance
	provider.instance = oci.CloudInstance{}
	currentInstances, err := fleet.Observe(ctx)
	if err != nil || len(currentInstances) != 0 {
		t.Fatalf("retired OCI instance remained in the verified fleet: instances=%+v err=%v", currentInstances, err)
	}
	if err := register("retired-registration.json", registration); err == nil {
		t.Fatal("registration for a retired OCI instance was accepted")
	}
	if err := controller.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := store.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, row.SeatID)
	if err != nil || after.Revision != member.Revision || after.State.Stage != placement.StagePreparedVolume || provider.volumeCalls != 0 {
		t.Fatalf("retired host advanced placement or created a retained volume: before=%+v after=%+v volumes=%d err=%v", member, after, provider.volumeCalls, err)
	}
	provider.instance = retiredInstance
	hostRevokePayload, err := protocol.EncodeJSON(hostEnrollmentRevoke{SchemaVersion: 1, InstanceID: observed[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	hostRevokeNow := time.Now().UTC()
	hostRevokeEnvelope, err := protocol.SignEnvelope(hostRevokePayload, protocol.EnvelopeScope{
		Region: cell, Kind: "host.enrollment.revoke", Actor: "node-a",
		OperationID: hostEnrollmentRevokeOperationID(observed[0].ID), Epoch: control.Current().Epoch,
	}, hostRevokeNow, hostRevokeNow.Add(time.Minute), hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	hostRevokeWire, err := protocol.EncodeJSON(hostRevokeEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	hostRevokeReply, err := broker.Conn().RequestWithContext(ctx, hostRegistrationSubject(cell), hostRevokeWire)
	if err != nil {
		t.Fatal(err)
	}
	var denied hostEnrollmentRevokeReply
	if err := json.Unmarshal(hostRevokeReply.Data, &denied); err != nil || denied.Error == "" {
		t.Fatalf("host-signed revoke was not denied: reply=%+v err=%v", denied, err)
	}
	var revokeOutput bytes.Buffer
	if err := Run(ctx, []string{"operator", "host-enrollment-revoke", "--config", operatorConfig,
		"--instance-id", observed[0].ID + "foreign"}, &revokeOutput); err == nil {
		t.Fatal("operator revoked an instance without an exact durable enrollment grant")
	}
	beforeRevoke, _, err := grants.Read(ctx, observed[0].ID)
	if err != nil || beforeRevoke.Disabled {
		t.Fatalf("wrong-instance revoke changed exact grant: grant=%+v err=%v", beforeRevoke, err)
	}
	foreign := observed[0]
	foreign.ID = "ocid1.instance.oc1..foreign-replacement"
	managedEnrollment.fleet = managedEnrollmentObservedFleet{Fleet: fleet, instances: []oci.Instance{foreign}}
	revokeOutput.Reset()
	if err := Run(ctx, []string{"operator", "host-enrollment-revoke", "--config", operatorConfig,
		"--instance-id", observed[0].ID}, &revokeOutput); err == nil {
		t.Fatal("operator revoked a grant while OCI observed a foreign replacement on its node")
	}
	managedEnrollment.fleet = fleet
	if current, _, err := grants.Read(ctx, observed[0].ID); err != nil || current.Disabled {
		t.Fatalf("foreign OCI observation changed exact grant: grant=%+v err=%v", current, err)
	}
	provider.instance = oci.CloudInstance{}
	revokeOutput.Reset()
	if err := Run(ctx, []string{"operator", "host-enrollment-revoke", "--config", operatorConfig,
		"--instance-id", observed[0].ID}, &revokeOutput); err != nil {
		t.Fatalf("authenticated retired managed host enrollment revoke: %v", err)
	}
	provider.instance = retiredInstance
	var revokeReceipt hostEnrollmentRevokeReceipt
	if err := json.Unmarshal(revokeOutput.Bytes(), &revokeReceipt); err != nil ||
		revokeReceipt.InstanceID != observed[0].ID || !revokeReceipt.Disabled || revokeReceipt.GrantRevision == 0 {
		t.Fatalf("revoke receipt=%+v err=%v", revokeReceipt, err)
	}
	disabledGrant, revision, err := grants.Read(ctx, observed[0].ID)
	if err != nil || !disabledGrant.Disabled || revision != revokeReceipt.GrantRevision {
		t.Fatalf("revoked grant readback=%+v revision=%d err=%v", disabledGrant, revision, err)
	}
	if _, _, err := grants.ClaimRenew(ctx, observed[0].ID, []byte("renew"), time.Now()); err == nil {
		t.Fatal("disabled enrollment grant accepted a renewal")
	}
	beforeDenied, err := os.ReadFile(filepath.Join(setupRoot, "host.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := runHostSetupWithMetadata(ctx, bundle, setupMetadata, setupRoot, &bytes.Buffer{}, setupRuntime); err == nil {
		t.Fatal("revoked enrollment grant let the guest install new credentials")
	}
	if afterDenied, err := os.ReadFile(filepath.Join(setupRoot, "host.json")); err != nil || !bytes.Equal(afterDenied, beforeDenied) {
		t.Fatalf("revoked enrollment changed installed host credentials: %v", err)
	}
	cancel()
	if err := <-hostRunDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("host controller shutdown: %v", err)
	}
	if err := <-agentDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("host agent shutdown: %v", err)
	}
}

type managedEnrollmentProvider struct {
	*placementSizingProvider
	volumeCalls int
}

func (provider *managedEnrollmentProvider) LaunchInstance(ctx context.Context, request oci.LaunchRequest) (oci.CloudInstance, error) {
	instance, err := provider.placementSizingProvider.LaunchInstance(ctx, request)
	if err != nil {
		return oci.CloudInstance{}, err
	}
	ociRegion, err := provider.config.Region.OCIRegion()
	if err != nil {
		return oci.CloudInstance{}, err
	}
	instance.ID = "ocid1.instance.oc1." + ociRegion + ".managed-enrollment-" + strings.ToLower(string(provider.config.Region))
	provider.instance.ID = instance.ID
	if err := provider.bindBootVolume(instance.ID); err != nil {
		return oci.CloudInstance{}, err
	}
	return instance, nil
}

func (provider *managedEnrollmentProvider) CreateVolume(context.Context, oci.VolumeCreateRequest, map[string]string, string) (oci.CloudVolume, error) {
	provider.volumeCalls++
	return oci.CloudVolume{}, errors.New("unexpected retained-volume creation")
}

var _ oci.Provider = (*managedEnrollmentProvider)(nil)

type managedEnrollmentObservedFleet struct {
	oci.Fleet
	instances []oci.Instance
}

func (fleet managedEnrollmentObservedFleet) Observe(context.Context) ([]oci.Instance, error) {
	return fleet.instances, nil
}
