//go:build fixturetest

package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
	"golang.org/x/crypto/ssh"
)

// ExerciseDerivedSeedAdmission runs the actual Gate and fixed-store validators
// against temporary paths, retaining the source's real SDK clients and seal.
// The source fixture binds config marker bytes; the app scenario owns rendering.
func ExerciseDerivedSeedAdmission(t *testing.T, seed bootstrap.DerivedStartupAuthority,
	founder VerifiedSourceFounder, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring, sourceDirectory string,
) {
	installation := exerciseDerivedInstallation(t, seed, founder, anchor, roots, sourceDirectory, founder.imds, founder.observer, nil)
	exerciseDerivedFounderPeers(t, installation, seed, founder, anchor, roots, sourceDirectory)
}

type derivedAdmissionInstallation struct {
	accepted AcceptedInstall
	baked    BakedInputs
	floor    *FounderSelectionFloorStore
	ledger   *bootstrap.Ledger
	reader   *CurrentFounderAuthorityReader
	selected CurrentFounderAuthority
	signers  FounderSignerStore
	launch   LaunchMaterial
}

func exerciseDerivedInstallation(t *testing.T, seed bootstrap.DerivedStartupAuthority,
	founder VerifiedSourceFounder, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring, sourceDirectory string,
	descriptor DescriptorSource, observer InstanceObserver, forwarded *LaunchMaterial,
) derivedAdmissionInstallation {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("derived seed admission requires root for the real service-user install and child")
	}
	const serviceUID, serviceGID = 1000, 1000
	root, err := os.MkdirTemp("/dev/shm", "ts-orch-derived-seed-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	directory := func(name string, uid, gid int, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.Mkdir(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
		return path
	}
	installed := directory("material", serviceUID, serviceGID, 0o700)
	staging := directory("staging", 0, 0, 0o700)
	bakedDirectory := directory("baked", 0, 0, 0o755)
	markers := MarkerStore{directory: directory("markers", 0, 0, 0o755), allowUnsafeAncestors: true}
	floor := &FounderSelectionFloorStore{directory: directory("floor", serviceUID, serviceGID, 0o700), ownerUID: serviceUID, allowUnsafeAncestors: true}
	storeDirectory := directory("nats", serviceUID, serviceGID, 0o700)
	write := func(name string, wire []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(bakedDirectory, name), wire, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	payload := seed.Manifest()
	identity := BakedIdentity{SchemaVersion: 1, DeploymentID: payload.DeploymentID, Environment: payload.Environment, Cell: payload.Cell}
	wire, err := protocol.EncodeJSON(identity)
	if err != nil {
		t.Fatal(err)
	}
	write(identityFilename, wire)
	write(anchorFilename, anchor.Wire())
	rootsDirectory := filepath.Join(bakedDirectory, "trust-roots")
	if err := os.Mkdir(rootsDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	index := 1
	for _, key := range roots {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rootsDirectory, fmt.Sprintf("%03d.pem", index)), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o444); err != nil {
			t.Fatal(err)
		}
		index++
	}
	trustStore := bakedStore{directory: bakedDirectory, chainFile: filepath.Join(root, "root-chain.json"), allowUnsafeAncestors: true}
	baked, err := trustStore.load()
	if err != nil {
		t.Fatal(err)
	}
	var record bootstrapmaterial.Record
	if err := json.Unmarshal(seed.MaterialRecord(), &record); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(sourceDirectory, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	bundle := hostenroll.PublicBundle{SchemaVersion: 1, Cell: strings.ToLower(string(payload.Cell)), Region: string(payload.Cell), Environment: payload.Environment,
		CAPEM: string(ca), ControllerResponsePublicKey: record.Public.ControllerResponsePublicKey, CellAccountNKey: record.Public.CellAccountNKey,
		InstallRoot: hostenroll.ImageInstallRoot, StateRoot: hostenroll.ImageStateRoot, ManagedRuntimeRoot: hostenroll.ImageManagedRuntimeRoot,
		WorkloadUID: hostenroll.ImageWorkloadUID, WorkloadGID: hostenroll.ImageWorkloadGID}
	for _, slot := range record.Config.Slots {
		bundle.ControllerEndpoints = append(bundle.ControllerEndpoints, slot.PrivateIP+":8443")
		bundle.NATSURLs = append(bundle.NATSURLs, "tls://"+slot.PrivateIP+":4222")
	}
	wire, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	write(HostEnrollmentFilename, wire)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	write(OperatorSSHKeyFilename, bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshPublic)))
	write(ManagedHostImageReceiptFilename, payload.ReleaseImageReceiptWire)
	write(ManagedHostImageDelegationFilename, payload.ReleaseDelegationWire)
	if forwarded != nil {
		for index, name := range launchMaterialNames {
			write(name, forwarded.wires()[index])
		}
	}
	launch, err := trustStore.loadLaunchMaterial()
	if err != nil {
		t.Fatal(err)
	}
	path := func(name string) string { return filepath.Join(installed, name) }
	slotIP := ""
	var routes []string
	for _, slot := range record.Config.Slots {
		if slot.Name == payload.Slot {
			slotIP = slot.PrivateIP
		} else {
			routes = append(routes, "nats-route://"+slot.PrivateIP+":6222")
		}
	}
	tlsFiles := natscell.TLSFiles{CAFile: path("ca.pem"), CertFile: path(payload.Slot + "-tls-cert.pem"), KeyFile: path(payload.Slot + "-tls-key.pem")}
	cfg := natscell.Config{Cell: record.Config.Cell, Instance: payload.Slot, Replicas: 3, ClientRole: "controller", CredentialsFile: path(payload.Slot + ".creds"), TLS: tlsFiles,
		Embedded: &natscell.Embedded{Host: slotIP, Port: 4222, RouteHost: slotIP, RoutePort: 6222, Routes: routes, StoreDir: storeDirectory, TLS: tlsFiles, RouteTLS: tlsFiles,
			RouteUser: "ts-route", RoutePasswordFile: path("route-password"), OperatorJWTFile: path("operator.jwt"), SystemJWTFile: path("system.jwt"), CellJWTFile: path("cell.jwt"),
			SystemCredentialsFile: path("system.creds"), TicketPublicKeyFile: path("ticket.pub"), BrokerIDs: payload.ControllerSlots}}
	if linkWire := seed.LinkMaterialRecord(); len(linkWire) > 0 {
		var linkRecord bootstrapmaterial.LinkRecord
		if err := json.Unmarshal(linkWire, &linkRecord); err != nil {
			t.Fatal(err)
		}
		link, err := bootstrapmaterial.RenderLink(linkRecord, payload.Slot, installed)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Embedded.Link = &link
	}
	validateKeys := func() error {
		return validateDerivedSeedControllerKeys(CredentialChildRequest{Config: cfg, ResponseKeyFile: path(payload.Slot + "-response.key"), BrokerTicketKeyFile: path("ticket.key")})
	}
	credentials, err := NewLiveCredentialChecker(cfg, serviceUID, serviceGID, path(payload.Slot+"-response.key"), path("ticket.key"), path("host-nats-issuer.seed"), path("host-tls-issuer-key.pem"), path("host-tls-issuer-cert.pem"), validateKeys)
	if err != nil {
		t.Fatal(err)
	}
	credentials.directory, credentials.allowUnsafeAncestors = installed, true
	credentials.TerraBaseCACertFile, credentials.TerraBaseCAKeyFile = path("terrabase-member-ca.pem"), path("terrabase-member-ca.key")
	credentials.runChild = runDerivedSeedCredentialChild
	factory, ctx, err := founder.GuardedFactory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := seed.OpenLedgerWithClient(ctx, roots, &objects)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := bootstrap.NewInstancePrincipalVault(payload.Cell, factory.Provider())
	if err != nil {
		t.Fatal(err)
	}
	material := MaterialStore{vault: vault, installedDirectory: installed, stagingDirectory: staging, serviceUID: serviceUID, serviceGID: serviceGID, allowUnsafeAncestors: true, chainCopy: filepath.Join(root, "material-generations.json")}
	clockCheck := func() error { _, err := brokerauth.MeasureHealthyClock(brokerauth.KernelClockProbe{}); return err }
	gate := Gate{Roots: roots, AnchorWire: anchor.Wire(), Expected: identity.AnchorExpectation(), LoadedControllerConfigSHA256: payload.ControllerConfigSHA256,
		Descriptor: descriptor, Instances: observer, Ledgers: derivedSeedFixtureLedger{seed: seed, roots: roots, ledger: ledger},
		Material: material, Credentials: credentials, Markers: markers, ClockCheck: clockCheck, trustStore: &trustStore}
	gate.InitialIdentity = func(bootstrap.Manifest) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		observed, err := natscell.PrepareInitialInstallationIdentity(cfg, serviceUID, serviceGID)
		broker, store := derivedSeedInstallationIdentity(observed)
		return broker, store, err
	}
	gate.ObserveIdentity = func(AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		observed, err := natscell.ObserveInstalledIdentity(cfg)
		broker, store := derivedSeedInstallationIdentity(observed)
		return broker, store, err
	}
	gate.InitialFounderFloor = func(ctx context.Context, accepted AcceptedInstall, now time.Time) error {
		reader, err := NewDerivedCurrentFounderAuthorityReader(baked, accepted, seed, floor)
		if err != nil {
			return err
		}
		selected, err := reader.readDerivedCurrent(ctx, now, false)
		if err != nil {
			return err
		}
		return reader.provisionDerivedInitial(ctx, selected, ledger, serviceUID, serviceGID, clockCheck)
	}
	gate.InitialPeerFloor = func(ctx context.Context, accepted AcceptedInstall, state bootstrap.SlotState, now time.Time) error {
		checker, err := NewDerivedFounderPeerContinuation(baked, accepted, seed, serviceUID, serviceGID)
		if err != nil {
			return err
		}
		// Keep the constructor's genuine reader; relocate only its filesystem store.
		checker.floor, checker.reader.floor = floor, floor
		return checker.Initialize(ctx, accepted, state, now)
	}
	gate, err = gate.WithDerivedStartupAuthority(seed)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := gate.AdmitInitial(ctx)
	if err != nil {
		t.Fatalf("real derived seed Gate: %v", err)
	}
	reader, err := NewDerivedCurrentFounderAuthorityReader(baked, accepted, seed, floor)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := reader.ReadCurrent(ctx, time.Now().UTC())
	if err != nil || selected.Derived == nil || floor.Check(selected.SelectionGeneration, selected.SelectionSHA256) != nil {
		t.Fatalf("same durable derived founder floor: %v", err)
	}
	signers := FounderSignerStore{directory: installed, uid: serviceUID, gid: serviceGID, allowUnsafeAncestors: true}
	if payload.Slot == payload.SeedSlot {
		keys, err := signers.LoadContext(ctx, selected, accepted, roots, time.Now().UTC())
		if err != nil {
			t.Fatalf("installed source-bound founder signers: %v", err)
		}
		keys.Close()
	}
	restarted, err := gate.AdmitRestart(ctx)
	if err != nil || restarted.InstanceOCID != accepted.InstanceOCID || restarted.Slot != payload.Slot || restarted.ConfigSHA256["controller.json"] != payload.ControllerConfigSHA256 {
		t.Fatalf("accepted derived seed reboot: %v", err)
	}
	if payload.Slot != payload.SeedSlot {
		identity, err := markers.ReadIdentity()
		if err != nil {
			t.Fatalf("actual derived peer accepted identity: %v", err)
		}
		runtime, err := reader.ReadRuntimeAuthority(ctx, identity, time.Now().UTC())
		expected := RuntimeIdentity{DeploymentID: payload.DeploymentID, ClusterID: payload.ClusterID,
			Environment: payload.Environment, Cell: string(payload.Cell), OCIRegion: payload.OCIRegion,
			Slot: payload.Slot, SeedSlot: payload.SeedSlot, InstanceID: restarted.InstanceOCID,
			PrivateIP: restarted.PrimaryPrivateIP, SeedPrivateIP: selected.Plan.Plan().SeedPrivateIP}
		if err != nil || runtime.Identity() != expected || runtime.Anchor().Digest() != seed.AnchorDigest() || !runtime.ExpiresAt().Equal(selected.SelectionExpiresAt) {
			t.Fatalf("actual derived peer runtime authority: %v", err)
		}
		t.Logf("derived peer %s: public runtime authority retained its exact admitted identity and sealed plan", payload.Slot)
	}
	return derivedAdmissionInstallation{accepted: accepted, baked: baked, floor: floor, ledger: ledger, reader: reader, selected: selected, signers: signers, launch: launch}
}

type derivedSeedFixtureLedger struct {
	seed   bootstrap.DerivedStartupAuthority
	roots  trust.Keyring
	ledger *bootstrap.Ledger
}

func exerciseDerivedFounderPeers(t *testing.T, seedInstall derivedAdmissionInstallation, seed bootstrap.DerivedStartupAuthority,
	founder VerifiedSourceFounder, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring, sourceDirectory string,
) {
	t.Helper()
	factory, ctx, err := founder.GuardedFactory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	protocol := &derivedPeerProtocol{plan: seedInstall.selected.Plan.Plan(), region: seed.Manifest().OCIRegion, instances: map[string]derivedPeerInstance{}, retries: map[string]string{}}
	server := httptest.NewTLSServer(protocol)
	t.Cleanup(server.Close)
	adapter, err := NewFounderOCI(seed.Manifest().Cell, factory.Provider(), seedInstall.launch)
	if err != nil {
		t.Fatal(err)
	}
	compute := adapter.compute.(*core.ComputeClient)
	network := adapter.network.(*core.VirtualNetworkClient)
	volume := adapter.volume.(*core.BlockstorageClient)
	compute.Host, compute.HTTPClient = server.URL, server.Client()
	network.Host, network.HTTPClient = server.URL, server.Client()
	volume.Host, volume.HTTPClient = server.URL, server.Client()
	caller := founderCaller{reader: seedInstall.reader, roots: roots, accepted: seedInstall.accepted, signers: seedInstall.signers, adapter: adapter,
		placement: func(ctx context.Context) (bootstrap.ControllerPlacement, error) {
			observed, err := founder.ObserveCurrent(ctx)
			return bootstrap.ControllerPlacement{AvailabilityDomain: observed.AvailabilityDomain, FaultDomain: observed.FaultDomain}, err
		},
		openLedger: func(ctx context.Context, selected CurrentFounderAuthority, roots trust.Keyring) (*bootstrap.Ledger, error) {
			objects, err := factory.ObjectStorage()
			if err != nil {
				return nil, err
			}
			return selected.Derived.SeedAuthority().OpenLedgerWithClient(ctx, roots, &objects)
		}}
	completed := make(map[string]bootstrap.SlotState, 2)
	for _, row := range seedInstall.selected.Plan.Plan().Peers {
		t.Logf("derived peer %s: actual SDK launch and durable completion", row.Slot)
		if err := caller.runPeer(ctx, row.Slot); err != nil {
			t.Fatalf("actual derived founder peer %s: %v", row.Slot, err)
		}
		state, err := seedInstall.ledger.ReadSlot(ctx, bootstrap.BootstrapScope{DeploymentID: seedInstall.accepted.DeploymentID, Cell: seedInstall.accepted.Cell, Slot: row.Slot})
		if err != nil || state.ResultRecord == nil || state.PeerReceiptRecord == nil || state.CandidateRecord == nil || state.ManifestRecord == nil || state.Result == nil || state.Candidate == nil || state.Head.Attempt != 1 || state.Head.Generation != 1 || state.Head.ResultDigest != state.ResultRecord.SHA256 || state.Head.CandidateDigest != state.CandidateRecord.SHA256 || state.Result.InstanceOCID != state.Candidate.InstanceOCID || state.ManifestRecord.SHA256 != row.ManifestSHA256 {
			t.Fatalf("exact derived peer %s durable completion: %v", row.Slot, err)
		}
		completed[row.Slot] = state
		metadata := derivedPeerMetadata{client: server.Client(), endpoint: server.URL, instanceID: state.Result.InstanceOCID}
		forwarded := metadata.launchMaterial(t)
		if !maps.Equal(forwarded.ControllerMetadata(), seedInstall.launch.ControllerMetadata()) {
			t.Fatal("actual peer launch changed public deployment material")
		}
		authority, ok := seedInstall.selected.Derived.Authority(row.Slot)
		if !ok {
			t.Fatal("selected derived peer authority missing")
		}
		observer, err := NewOCIInstanceObserverWithClients(authority.Manifest().Cell, factory.Provider(), compute, network)
		if err != nil {
			t.Fatal(err)
		}
		peer := exerciseDerivedInstallation(t, authority, founder, anchor, roots, sourceDirectory, metadata, observer, &forwarded)
		if peer.accepted.ResultSHA256 != state.ResultRecord.SHA256 || peer.accepted.ReceiptSHA256 != state.PeerReceiptRecord.SHA256 || peer.accepted.InstanceOCID != state.Result.InstanceOCID || peer.floor.Check(seedInstall.selected.SelectionGeneration, seedInstall.selected.SelectionSHA256) != nil {
			t.Fatal("peer Gate or floor changed the source-signed completed history")
		}
	}
	protocol.mu.Lock()
	launches, attempts, lost := len(protocol.instances), protocol.launchAttempts, protocol.lostResponse
	protocol.mu.Unlock()
	if launches != 2 || attempts != 3 || !lost {
		t.Fatalf("lost-response SDK retry duplicated a peer: instances=%d attempts=%d lost=%v", launches, attempts, lost)
	}
	for _, row := range seedInstall.selected.Plan.Plan().Peers {
		if err := caller.runPeer(ctx, row.Slot); err != nil {
			t.Fatalf("completed derived founder retry %s: %v", row.Slot, err)
		}
		state, err := seedInstall.ledger.ReadSlot(ctx, bootstrap.BootstrapScope{DeploymentID: seedInstall.accepted.DeploymentID, Cell: seedInstall.accepted.Cell, Slot: row.Slot})
		prior := completed[row.Slot]
		if err != nil || state.ResultRecord == nil || state.PeerReceiptRecord == nil || !bytes.Equal(state.HeadRecord.Bytes, prior.HeadRecord.Bytes) || !bytes.Equal(state.ResultRecord.Bytes, prior.ResultRecord.Bytes) || !bytes.Equal(state.PeerReceiptRecord.Bytes, prior.PeerReceiptRecord.Bytes) {
			t.Fatalf("completed derived founder retry changed exact proof history %s: %v", row.Slot, err)
		}
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if protocol.launchAttempts != attempts || len(protocol.instances) != launches {
		t.Fatal("completed founder retry issued another SDK launch")
	}
}

type derivedPeerLaunchDetails struct {
	AvailabilityDomain string            `json:"availabilityDomain"`
	CompartmentID      string            `json:"compartmentId"`
	FaultDomain        string            `json:"faultDomain"`
	Shape              string            `json:"shape"`
	Metadata           map[string]string `json:"metadata"`
	ShapeConfig        struct {
		OCPUs  float32 `json:"ocpus"`
		Memory float32 `json:"memoryInGBs"`
	} `json:"shapeConfig"`
	Source struct {
		ImageID string `json:"imageId"`
		BootGB  int64  `json:"bootVolumeSizeInGBs"`
		VPUs    int64  `json:"bootVolumeVpusPerGB"`
	} `json:"sourceDetails"`
	VNIC struct {
		SubnetID  string   `json:"subnetId"`
		NSGs      []string `json:"nsgIds"`
		PrivateIP string   `json:"privateIp"`
	} `json:"createVnicDetails"`
}

type derivedPeerInstance struct {
	id      string
	wire    []byte
	details derivedPeerLaunchDetails
}

// This protocol simulator stores real signed SDK launch bodies. It exposes no
// ledger writes or verified capabilities; all completion uses production code.
type derivedPeerProtocol struct {
	mu             sync.Mutex
	plan           bootstrap.FounderPlan
	region         string
	instances      map[string]derivedPeerInstance
	retries        map[string]string
	launchAttempts int
	lostResponse   bool
}

func (server *derivedPeerProtocol) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	server.mu.Lock()
	defer server.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if strings.HasPrefix(r.URL.Path, "/metadata/") {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/metadata/"), "/", 2)
		if len(parts) != 2 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		instance, ok := server.instances[parts[0]]
		if !ok || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer Oracle" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if parts[1] == "id" {
			io.WriteString(w, instance.id)
		} else {
			io.WriteString(w, instance.details.Metadata[parts[1]])
		}
		return
	}
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/20160918/instances" {
		wire, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var details derivedPeerLaunchDetails
		if err != nil || json.Unmarshal(wire, &details) != nil || r.Header.Get("opc-retry-token") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		descriptor, err := ParseDescriptor([]byte(details.Metadata["terrascale-bootstrap"]))
		if err != nil || details.Metadata["terrascale-controller-manifest-v1"] != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		server.launchAttempts++
		id := "ocid1.instance.oc1." + server.region + "." + descriptor.Slot
		if retryID, ok := server.retries[r.Header.Get("opc-retry-token")]; ok {
			if retryID != id || !bytes.Equal(server.instances[id].wire, wire) {
				w.WriteHeader(http.StatusConflict)
				return
			}
		} else {
			if _, exists := server.instances[id]; exists {
				w.WriteHeader(http.StatusConflict)
				return
			}
			server.instances[id] = derivedPeerInstance{id: id, wire: wire, details: details}
			server.retries[r.Header.Get("opc-retry-token")] = id
			if !server.lostResponse {
				server.lostResponse = true
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"code":"InternalError","message":"launch committed, response lost"}`)
				return
			}
		}
		json.MarshalWrite(w, server.instance(server.instances[id]))
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/20160918/images/") {
		row := server.plan.Peers[0]
		if strings.TrimPrefix(r.URL.Path, "/20160918/images/") != row.ImageOCID {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.MarshalWrite(w, core.Image{Id: new(row.ImageOCID), CompartmentId: new(row.ImageCompartmentOCID), LifecycleState: core.ImageLifecycleStateAvailable})
		return
	}
	for _, instance := range server.instances {
		details := instance.details
		region := regionalOCID(instance.id, "instance")
		_, suffix, _ := strings.CutLast(instance.id, ".")
		vnicID := "ocid1.vnic.oc1." + region + "." + suffix
		bootID := "ocid1.bootvolume.oc1." + region + "." + suffix
		switch {
		case r.URL.Path == "/20160918/instances/"+instance.id:
			w.Header().Set("etag", digest(instance.wire))
			json.MarshalWrite(w, server.instance(instance))
		case r.URL.Path == "/20160918/vnicAttachments" && r.URL.Query().Get("instanceId") == instance.id:
			json.MarshalWrite(w, []core.VnicAttachment{{InstanceId: new(instance.id), CompartmentId: new(details.CompartmentID), SubnetId: new(details.VNIC.SubnetID), VnicId: new(vnicID), LifecycleState: core.VnicAttachmentLifecycleStateAttached}})
		case r.URL.Path == "/20160918/vnics/"+vnicID:
			json.MarshalWrite(w, core.Vnic{Id: new(vnicID), CompartmentId: new(details.CompartmentID), AvailabilityDomain: new(details.AvailabilityDomain), SubnetId: new(details.VNIC.SubnetID), PrivateIp: new(details.VNIC.PrivateIP), NsgIds: details.VNIC.NSGs, IsPrimary: new(true), LifecycleState: core.VnicLifecycleStateAvailable})
		case r.URL.Path == "/20160918/subnets/"+details.VNIC.SubnetID:
			json.MarshalWrite(w, core.Subnet{Id: new(details.VNIC.SubnetID), CompartmentId: new(details.CompartmentID), VcnId: new("ocid1.vcn.oc1." + region + ".peers"), LifecycleState: core.SubnetLifecycleStateAvailable})
		case r.URL.Path == "/20160918/bootVolumeAttachments" && r.URL.Query().Get("instanceId") == instance.id:
			json.MarshalWrite(w, []core.BootVolumeAttachment{{InstanceId: new(instance.id), CompartmentId: new(details.CompartmentID), AvailabilityDomain: new(details.AvailabilityDomain), BootVolumeId: new(bootID), LifecycleState: core.BootVolumeAttachmentLifecycleStateAttached}})
		case r.URL.Path == "/20160918/bootVolumes/"+bootID:
			json.MarshalWrite(w, core.BootVolume{Id: new(bootID), CompartmentId: new(details.CompartmentID), AvailabilityDomain: new(details.AvailabilityDomain), ImageId: new(details.Source.ImageID), SizeInGBs: new(details.Source.BootGB), VpusPerGB: new(details.Source.VPUs), LifecycleState: core.BootVolumeLifecycleStateAvailable})
		default:
			continue
		}
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (server *derivedPeerProtocol) instance(instance derivedPeerInstance) core.Instance {
	details := instance.details
	return core.Instance{Id: new(instance.id), CompartmentId: new(details.CompartmentID), ImageId: new(details.Source.ImageID), AvailabilityDomain: new(details.AvailabilityDomain), FaultDomain: new(details.FaultDomain), Shape: new(details.Shape), ShapeConfig: &core.InstanceShapeConfig{Ocpus: new(details.ShapeConfig.OCPUs), MemoryInGBs: new(details.ShapeConfig.Memory)}, Metadata: maps.Clone(details.Metadata), LifecycleState: core.InstanceLifecycleStateRunning}
}

type derivedPeerMetadata struct {
	client     *http.Client
	endpoint   string
	instanceID string
}

func (metadata derivedPeerMetadata) fetch(ctx context.Context, name string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadata.endpoint+"/metadata/"+metadata.instanceID+"/"+name, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer Oracle")
	response, err := metadata.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrInvalidDescriptor
	}
	return io.ReadAll(io.LimitReader(response.Body, trust.MaxEnvelopeBytes))
}

func (metadata derivedPeerMetadata) FetchDescriptor(ctx context.Context) (Descriptor, error) {
	wire, err := metadata.fetch(ctx, "terrascale-bootstrap")
	if err != nil {
		return Descriptor{}, err
	}
	return ParseDescriptor(wire)
}

func (metadata derivedPeerMetadata) FetchInstanceID(ctx context.Context) (string, error) {
	wire, err := metadata.fetch(ctx, "id")
	if err != nil || !instanceIDRE.Match(wire) {
		return "", ErrInvalidDescriptor
	}
	return string(wire), nil
}

func (metadata derivedPeerMetadata) launchMaterial(t *testing.T) LaunchMaterial {
	t.Helper()
	var material LaunchMaterial
	for name := range material.ControllerMetadata() {
		wire, err := metadata.fetch(t.Context(), name)
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case IdentityMetadataKey:
			material.Identity = wire
		case AnchorMetadataKey:
			material.Anchor = wire
		case OperatorSSHKeyMetadataKey:
			material.OperatorSSHKey = wire
		case ManagedHostImageReceiptMetadataKey:
			material.ManagedHostImageReceipt = wire
		case ManagedHostImageDelegationMetadataKey:
			material.ManagedHostImageDelegation = wire
		default:
			material.HostEnrollment = wire
		}
	}
	return material
}

func (opener derivedSeedFixtureLedger) OpenCurrentLedger(ctx context.Context, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring) (AdmissionLedger, error) {
	if anchor.Digest() != opener.seed.AnchorDigest() || opener.seed.VerifyCurrent(ctx, time.Now().UTC()) != nil || !maps.EqualFunc(roots, opener.roots, func(a, b ed25519.PublicKey) bool { return bytes.Equal(a, b) }) {
		return nil, ErrAdmission
	}
	return admissionLedger{ledger: opener.ledger}, nil
}

func derivedSeedInstallationIdentity(observed natscell.InstallationIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity) {
	return identityrekey.BrokerIdentity{Operator: observed.Operator, SystemAccount: observed.SystemAccount, CellAccount: observed.CellAccount, HostSigner: observed.HostSigner, RoleSigner: observed.RoleSigner, AccountSigner: observed.AccountSigner, InterRegionAccount: observed.InterRegionAccount},
		identityrekey.StoreIdentity{Directory: observed.Directory, ServerName: observed.ServerName, RaftNodeID: observed.RaftNodeID, ServerNameSHA256: observed.ServerNameSHA256, NodeIdentitySHA256: observed.NodeIdentitySHA256}
}

func runDerivedSeedCredentialChild(ctx context.Context, wire []byte, uid, gid uint32) error {
	command := exec.CommandContext(ctx, "/proc/self/exe", "derived-seed-credential-child")
	command.Stdin = bytes.NewReader(wire)
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("real service-user credential child: %w: %s", err, output)
	}
	return nil
}

// ValidateDerivedSeedCredentialChild is called only by the fixture's service-UID
// reexec test; the production parser checks identity, groups and NATS credentials.
func ValidateDerivedSeedCredentialChild(input io.Reader) error {
	return RunCredentialValidationChild(input, validateDerivedSeedControllerKeys)
}

func validateDerivedSeedControllerKeys(request CredentialChildRequest) error {
	read := func(path string) (ed25519.PrivateKey, error) {
		wire, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		defer clear(wire)
		key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(wire)))
		if err != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) {
			clear(key)
			return nil, ErrLiveCredentials
		}
		return ed25519.PrivateKey(key), nil
	}
	response, err := read(request.ResponseKeyFile)
	if err != nil {
		return err
	}
	defer clear(response)
	ticket, err := read(request.BrokerTicketKeyFile)
	if err != nil {
		return err
	}
	defer clear(ticket)
	wire, err := os.ReadFile(request.Config.Embedded.TicketPublicKeyFile)
	if err != nil {
		return err
	}
	public, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(wire)))
	if err != nil || !bytes.Equal(public, ticket.Public().(ed25519.PublicKey)) {
		return ErrLiveCredentials
	}
	return nil
}
