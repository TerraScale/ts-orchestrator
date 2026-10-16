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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	"golang.org/x/crypto/ssh"
)

// ExerciseDerivedSeedAdmission runs the actual Gate and fixed-store validators
// against temporary paths, retaining the source's real SDK clients and seal.
// The source fixture binds config marker bytes; the app scenario owns rendering.
func ExerciseDerivedSeedAdmission(t *testing.T, seed bootstrap.DerivedStartupAuthority,
	founder VerifiedSourceFounder, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring, sourceDirectory string,
) {
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
		if err := os.WriteFile(filepath.Join(bakedDirectory, name), wire, 0o644); err != nil {
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
		if err := os.WriteFile(filepath.Join(rootsDirectory, fmt.Sprintf("%03d.pem", index)), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
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
		if cfg.Cell == natscell.LinkHome {
			cfg.Embedded.CellJWTFile = path("link-cell.jwt")
		}
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
		Descriptor: founder.imds, Instances: founder.observer, Ledgers: derivedSeedFixtureLedger{seed: seed, roots: roots, ledger: ledger},
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
	keys, err := signers.LoadContext(ctx, selected, accepted, roots, time.Now().UTC())
	if err != nil {
		t.Fatalf("installed source-bound founder signers: %v", err)
	}
	keys.Close()
	restarted, err := gate.AdmitRestart(ctx)
	if err != nil || restarted.ManifestSHA256 != seed.Digest() || restarted.InstanceOCID != accepted.InstanceOCID {
		t.Fatalf("accepted derived seed reboot: %v", err)
	}
}

type derivedSeedFixtureLedger struct {
	seed   bootstrap.DerivedStartupAuthority
	roots  trust.Keyring
	ledger *bootstrap.Ledger
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
	command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestDerivedSeedCredentialChild$")
	command.Stdin = bytes.NewReader(wire)
	command.Env = []string{"PATH=/usr/bin:/bin", "TS_ORCH_FIXTURE_CREDENTIAL_CHILD=1"}
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
