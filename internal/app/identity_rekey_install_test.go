package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

func identityRekeyConfigFixture(t *testing.T) (bootstrapstart.AcceptedIdentity, map[string][]byte, Config) {
	t.Helper()
	public := func(operator bool) string {
		t.Helper()
		var pair nkeys.KeyPair
		var err error
		if operator {
			pair, err = nkeys.CreateOperator()
		} else {
			pair, err = nkeys.CreateAccount()
		}
		if err != nil {
			t.Fatal(err)
		}
		defer pair.Wipe()
		key, err := pair.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	encode := func(value any) []byte {
		t.Helper()
		wire, err := protocol.EncodeJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	accepted := bootstrapstart.AcceptedIdentity{SchemaVersion: 1, Origin: identityrekey.AcceptanceOriginRekey, OperationID: entityid.Derive("installer-operation"),
		DeploymentID: entityid.Derive("installer-deployment"), ClusterID: entityid.Derive("installer-cluster"),
		Cell: "GRU", Environment: "canary", Slot: "controller-a", SeedSlot: "controller-a",
		ControllerSlots: []string{"controller-a", "controller-b", "controller-c"},
		InstanceOCID:    "ocid1.instance.oc1.sa-saopaulo-1.existing", ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.existing",
		PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1.existing", PrimaryPrivateIP: "10.251.0.11",
		Binary: identityrekey.BinaryPin{SHA256: strings.Repeat("a", 64), Size: 4096, Architecture: "amd64"},
		Broker: identityrekey.BrokerIdentity{Operator: public(true), SystemAccount: public(false), CellAccount: public(false),
			HostSigner: public(false), RoleSigner: public(false)},
		Store: identityrekey.StoreIdentity{Directory: "/var/lib/terrascale-orchestrator-controller/nats", ServerName: "gru-1-ctl-1", RaftNodeID: "Q4vu3bZy",
			ServerNameSHA256: strings.Repeat("b", 64), NodeIdentitySHA256: strings.Repeat("c", 64)}, AcceptedAt: time.Now().UTC().Truncate(time.Second)}
	accepted.ControllerBindings = []bootstrapstart.ControllerBinding{{Slot: accepted.Slot, InstanceOCID: accepted.InstanceOCID,
		ImageOCID: accepted.ImageOCID, PrimaryVNICOCID: accepted.PrimaryVNICOCID, PrimaryPrivateIP: accepted.PrimaryPrivateIP,
		Binary: accepted.Binary, Store: accepted.Store}}
	for _, name := range []string{"operator.jwt", "system.jwt", "cell.jwt", "system.creds", "ca.pem", "route-password", "ticket.pub", "ticket.key",
		"host-nats-issuer.seed", "host-tls-issuer-cert.pem", "host-tls-issuer-key.pem", "controller-a.creds", "controller-a-tls-cert.pem", "controller-a-tls-key.pem", "controller-a-response.key"} {
		purpose, slot := bootstrap.SecretRegionalShared, ""
		if strings.HasPrefix(name, "host-") {
			purpose = bootstrap.SecretHostIssuer
		} else if strings.HasPrefix(name, accepted.Slot) {
			purpose, slot = bootstrap.SecretController, accepted.Slot
		}
		accepted.MaterialReferences = append(accepted.MaterialReferences, bootstrap.SecretReference{Purpose: purpose, Slot: slot, TargetFile: name,
			SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.pinned", VersionNumber: 1, SHA256: controllerSHA256([]byte(name)), MaxBytes: 64 << 10})
	}
	path := func(name string) string { return filepath.Join(bootstrapstart.MaterialDirectory, name) }
	tls := natscell.TLSFiles{CAFile: path("ca.pem"), CertFile: path("controller-a-tls-cert.pem"), KeyFile: path("controller-a-tls-key.pem")}
	publicSigner, _ := testEd25519(t, t.TempDir(), "operator.key")
	config := Config{Version: ConfigVersion, NATS: natscell.Config{Cell: "gru", Instance: accepted.Slot, Replicas: 3, ClientRole: "controller",
		URL: "tls://10.251.0.11:4222", CredentialsFile: path("controller-a.creds"), TLS: tls,
		Embedded: &natscell.Embedded{Host: "10.251.0.11", Port: 4222, RouteHost: "10.251.0.11", RoutePort: 6222,
			Routes: []string{"nats-route://10.251.0.12:6222", "nats-route://10.251.0.13:6222"}, BrokerIDs: accepted.ControllerSlots,
			StoreDir: accepted.Store.Directory, StoreMaxBytes: 4 << 30, TLS: tls, RouteTLS: tls, RouteUser: "ts-route",
			RoutePasswordFile: path("route-password"), OperatorJWTFile: path("operator.jwt"), SystemJWTFile: path("system.jwt"), CellJWTFile: path("cell.jwt"),
			SystemCredentialsFile: path("system.creds"), TicketPublicKeyFile: path("ticket.pub")}},
		Controller: ControllerConfig{CandidateID: entityid.Derive("controller", accepted.DeploymentID, accepted.Cell, accepted.Slot),
			ResponseKeyFile: path("controller-a-response.key"), BrokerTicketKeyFile: path("ticket.key"), HostNATSIssuerSeedFile: path("host-nats-issuer.seed"),
			HostTLSIssuerKeyFile: path("host-tls-issuer-key.pem"), HostTLSIssuerCertFile: path("host-tls-issuer-cert.pem"), HostEnrollmentListenAddress: "10.251.0.11:8443",
			OciRegionIntentFile: controllerSidecarPath("oci-region-intent.json"), OciRegionConfig: controllerSidecarPath("oci-region.json"), PlacementConfig: controllerSidecarPath("placement.json"),
			TrustedSigners: []TrustedSignerConfig{{Actor: "operator", PublicKey: base64.StdEncoding.EncodeToString(publicSigner), Roles: []string{"terrabase"}, Environments: []string{"canary"}}}}}
	intent := oci.RegionIntent{SchemaVersion: 1, Generation: 7, BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}}
	region := oci.RegionConfig{Region: oci.RegionGRU, Generation: 7, Endpoint: "https://iaas.sa-saopaulo-1.oraclecloud.com", CompartmentID: "ocid1.compartment.oc1..owned",
		ImageCompartmentID: "ocid1.compartment.oc1..image", AvailabilityDomain: "AD-1", FaultDomains: []string{"FAULT-DOMAIN-1"}, SubnetID: "ocid1.subnet.oc1..owned",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1..owned"},
		BootVolumeGB:            50, BootVolumeVPUsPerGB: 10, DataVolumeVPUsPerGB: 10, MaxDataVolumeGB: 50, ImageID: accepted.ImageOCID, Shape: "VM.Standard.Future.Flex", Owner: "regional-owner"}
	files := map[string][]byte{"controller.json": encode(config), "oci-region-intent.json": encode(intent), "oci-region.json": encode(region),
		"placement.json": encode(managedPlacementSettings{Environment: accepted.Environment, MemberRole: "terrabase"})}
	accepted.ConfigSHA256 = map[string]string{}
	for name, wire := range files {
		accepted.ConfigSHA256[name] = controllerSHA256(wire)
	}
	accepted.LaunchMaterialSHA256 = map[string]string{}
	for _, name := range identityRekeyLaunchFiles {
		files[name] = []byte(name)
		accepted.LaunchMaterialSHA256[name] = controllerSHA256(files[name])
	}
	if err := accepted.Validate(); err != nil {
		t.Fatal(err)
	}
	return accepted, files, config
}

func TestIdentityRekeyGlobalScopeMustMatchTopologyHome(t *testing.T) {
	_, _, cfg := identityRekeyConfigFixture(t)
	reset := authority.IdentityReset{}
	if err := verifyIdentityRekeyGlobalScope(cfg, reset); err == nil {
		t.Fatal("standalone home omitted its global root transition")
	}
	reset.GlobalLease = &authority.IdentityResetGlobalLease{Epoch: 1}
	if err := verifyIdentityRekeyGlobalScope(cfg, reset); err != nil {
		t.Fatal(err)
	}
	cfg.NATS.Embedded.InterRegion = &natscell.InterRegion{GlobalHome: "sjc", Peers: []string{"sjc"}}
	if err := verifyIdentityRekeyGlobalScope(cfg, reset); err == nil {
		t.Fatal("non-home was authorized to replace global authority")
	}
	reset.GlobalLease = nil
	if err := verifyIdentityRekeyGlobalScope(cfg, reset); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityRekeyInstallerRequiresExactV1RoleAndAllPinnedFiles(t *testing.T) {
	accepted, files, _ := identityRekeyConfigFixture(t)
	if _, err := validateIdentityRekeyFiles(accepted, files); err != nil {
		t.Fatalf("valid exact target refused: %v", err)
	}
	for _, fault := range []string{"sidecar absent", "launch absent", "launch changed", "extra", "schema", "role", "binary layout", "region", "shape"} {
		t.Run(fault, func(t *testing.T) {
			identity, wire, cfg := identityRekeyConfigFixture(t)
			switch fault {
			case "sidecar absent":
				delete(wire, "placement.json")
			case "launch absent":
				delete(wire, bootstrapstart.ManagedHostImageReceiptFilename)
			case "launch changed":
				wire[bootstrapstart.HostEnrollmentFilename] = []byte("another cell")
			case "extra":
				wire["controller-manifest.json"] = []byte("retired authority")
			case "schema":
				cfg.Version = ConfigVersion + 1
			case "role":
				cfg.Controller.CandidateID = entityid.Derive("wrong-controller")
			case "binary layout":
				cfg.Controller.SelfUpdateRoot = "/tmp/caller-selected-root"
			case "region", "shape":
				region, err := oci.ParseRegionConfig(wire["oci-region.json"])
				if err != nil {
					t.Fatal(err)
				}
				if fault == "region" {
					region.Region = oci.RegionSJC
				} else {
					region.Shape = "/invalid-shape"
				}
				wire["oci-region.json"], _ = protocol.EncodeJSON(region)
				identity.ConfigSHA256["oci-region.json"] = controllerSHA256(wire["oci-region.json"])
			}
			if fault == "schema" || fault == "role" || fault == "binary layout" {
				wire[controllerConfigFilename], _ = protocol.EncodeJSON(cfg)
				identity.ConfigSHA256[controllerConfigFilename] = controllerSHA256(wire[controllerConfigFilename])
			}
			if _, err := validateIdentityRekeyFiles(identity, wire); err == nil {
				t.Fatal("installer accepted an incomplete or wrong schema/role/layout target")
			}
		})
	}
}

func TestIdentityRekeyInstallerReplacesOnlyRegularFilesAndRecoversExactBytes(t *testing.T) {
	directory := t.TempDir()
	dir, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	files := map[string][]byte{"controller.json": []byte(`{"version":2}`), "placement.json": []byte(`{"environment":"canary"}`)}
	for name := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("opaque retired bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate interruption after the first durable rename, before acceptance.
	if err := replaceIdentityRekeyFile(dir, "placement.json", files["placement.json"], uid, gid); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		for name, wire := range files {
			if err := replaceIdentityRekeyFile(dir, name, wire, uid, gid); err != nil {
				t.Fatal(err)
			}
			stored, err := readExactControllerFile(dir, name, uid, gid, 0o444, len(wire))
			if err != nil || !bytes.Equal(stored, wire) {
				t.Fatalf("exact durable recovery of %s: %v", name, err)
			}
		}
	}
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "escape"} {
		t.Run(kind, func(t *testing.T) {
			name := "refused-" + kind
			path := filepath.Join(directory, name)
			switch kind {
			case "symlink":
				err = os.Symlink("controller.json", path)
			case "hardlink":
				err = os.Link(filepath.Join(directory, "controller.json"), path)
			case "fifo":
				err = unix.Mkfifo(path, 0o600)
			case "directory":
				err = os.Mkdir(path, 0o700)
			case "escape":
				name = "../controller.json"
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := replaceIdentityRekeyFile(dir, name, []byte("must not replace"), uid, gid); err == nil {
				t.Fatal("unsafe destination replaced")
			}
		})
	}
	stored, err := os.ReadFile(filepath.Join(directory, "controller.json"))
	if err != nil || !bytes.Equal(stored, files["controller.json"]) {
		t.Fatal("refused destinations changed unrelated accepted config")
	}
}

func TestIdentityRekeyInstallerProvesStoppedServiceAndNoRemainingProcesses(t *testing.T) {
	stopped := []byte("LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nKillMode=control-group\n")
	if err := validateIdentityRekeyStoppedState(stopped); err != nil {
		t.Fatal(err)
	}
	for old, replacement := range map[string]string{"ActiveState=inactive": "ActiveState=active", "SubState=dead": "SubState=running", "MainPID=0": "MainPID=123", "ControlPID=0": "ControlPID=321", "KillMode=control-group": "KillMode=process"} {
		if err := validateIdentityRekeyStoppedState(bytes.Replace(stopped, []byte(old), []byte(replacement), 1)); err == nil {
			t.Fatalf("accepted non-stopped process observation: %s", replacement)
		}
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "123"), 0o700); err != nil {
		t.Fatal(err)
	}
	status := filepath.Join(root, "123", "status")
	if err := os.WriteFile(status, []byte("Name:\tts-orch\nUid:\t1001\t1001\t1001\t1001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyIdentityRekeyNoServiceProcesses(root, 1001); err == nil {
		t.Fatal("accepted stopped unit while its untracked service process remained")
	}
	if err := verifyIdentityRekeyNoServiceProcesses(root, 1002); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(status, []byte("Name:\tunreadable-owner\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyIdentityRekeyNoServiceProcesses(root, 1002); err == nil {
		t.Fatal("missing UID became proof of absence")
	}
}

func TestIdentityRekeyInstallerMeasuresOnlyTrustedActiveInvocationNode(t *testing.T) {
	service := identityRekeyActiveService{PID: 536312, Invocation: "df6c6e6bd1644f1b8611a5bf169a899b"}
	row := map[string]string{"_PID": "536312", "_SYSTEMD_INVOCATION_ID": service.Invocation, "_SYSTEMD_UNIT": selfupdate.ControllerUnit,
		"MESSAGE": "[536312] [INF]   Node:     Q4vu3bZy", "__REALTIME_TIMESTAMP": strconv.FormatInt(time.Now().Add(-time.Hour).UnixMicro(), 10)}
	encode := func(value any) []byte {
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	if node, err := identityRekeyJournalNode(encode(row), service); err != nil || node != "Q4vu3bZy" {
		t.Fatalf("independent advertised node: %q %v", node, err)
	}
	for _, field := range []string{"_PID", "_SYSTEMD_INVOCATION_ID", "_SYSTEMD_UNIT", "MESSAGE", "__REALTIME_TIMESTAMP"} {
		changed := maps.Clone(row)
		changed[field] = "forged"
		if _, err := identityRekeyJournalNode(encode(changed), service); err == nil {
			t.Fatalf("trusted journald metadata %s was ignored", field)
		}
	}
	if _, err := identityRekeyJournalNodeBefore(encode(row), service, time.Now().Add(-2*time.Hour)); err == nil {
		t.Fatal("a later controller invocation authorized abort of an older attempt")
	}
	changed := maps.Clone(row)
	changed["MESSAGE"] = "[536312] [INF]   Node:     OTHER000"
	conflict := append(append(encode(row), '\n'), encode(changed)...)
	if _, err := identityRekeyJournalNode(conflict, service); err == nil {
		t.Fatal("conflicting startup nodes accepted")
	}
	if _, err := identityRekeyJournalNode([]byte(""), service); err == nil {
		t.Fatal("missing node was derived or regenerated")
	}
}

func TestIdentityRekeyInstallerCleanupKeepsCurrentRootsLaunchPinsAndData(t *testing.T) {
	directory := t.TempDir()
	dir, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	retired := []string{"identity.json", "anchor.json", controllerManifestFilename, "initial-formation.json"}
	completed := func() error { return nil }
	current := []string{"identity-rekey.json", "accepted-install.json", "root-chain.json", "001.pem", "node-identity.json"}
	current = append(current, identityRekeyLaunchFiles[:]...)
	for _, name := range append(retired, current...) {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("opaque proof bytes"), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(directory, "jetstream"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range retired {
		for range 2 {
			if err := unlinkRetiredIdentityInput(dir, name, uid, gid, completed); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range append(current, "jetstream") {
		if err := unlinkRetiredIdentityInput(dir, name, uid, gid, completed); err == nil {
			t.Fatalf("cleanup permitted current authority/store/data name %s", name)
		}
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatal("cleanup removed a retained current input")
		}
	}
	if err := os.Symlink("accepted-install.json", filepath.Join(directory, "identity.json")); err != nil {
		t.Fatal(err)
	}
	if err := unlinkRetiredIdentityInput(dir, "identity.json", uid, gid, completed); err == nil {
		t.Fatal("cleanup followed a retired input symlink")
	}
	if _, err := os.Stat(filepath.Join(directory, "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestIdentityRekeyInstallerCleanupRequiresCurrentProofAndSharedCompletion(t *testing.T) {
	directory := t.TempDir()
	dir, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	path := filepath.Join(directory, "anchor.json")
	wire := []byte("opaque retired authority")
	if err := os.WriteFile(path, wire, 0o444); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	currentProofDenied := errors.New("current root authorization denied")
	for _, denied := range []error{currentProofDenied, bootstrapstart.ErrIdentityRekeyPending} {
		if err := unlinkRetiredIdentityInput(dir, "anchor.json", uid, gid, func() error { return denied }); !errors.Is(err, denied) {
			t.Fatalf("cleanup did not enforce authorization/completion gate: %v", err)
		}
		stored, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(stored, wire) {
			t.Fatal("refused cleanup deleted retired authority needed by pending recovery")
		}
	}
	if err := unlinkRetiredIdentityInput(dir, "anchor.json", uid, gid, nil); err == nil {
		t.Fatal("missing gate became proof of completion")
	}
	if err := unlinkRetiredIdentityInput(dir, "anchor.json", uid, gid, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("authorized cleanup retained obsolete authority")
	}
}

func TestIdentityRekeyResponseSignerMatchesHandoffBundleAndVaultPin(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, _, _ := testHostEnrollmentTLSMaterial(t, public)
	bundle.ControllerResponsePublicKey = base64.StdEncoding.EncodeToString(public)
	wire, err := protocol.EncodeJSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	private := []byte(base64.StdEncoding.EncodeToString(key))
	accepted := bootstrapstart.AcceptedIdentity{Slot: "controller-a", MaterialReferences: []bootstrap.SecretReference{{TargetFile: "controller-a-response.key", SHA256: controllerSHA256(private)}}}
	journal := bootstrapstart.IdentityRekeyJournal{HostObservation: identityrekey.HostStateObservation{ResponseKey: bundle.ControllerResponsePublicKey}}
	if err := verifyIdentityRekeyResponseKey(journal, accepted, wire, private); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"plan", "private", "pin", "inconsistent private public"} {
		t.Run(fault, func(t *testing.T) {
			observation, record, secret := journal, accepted.Clone(), bytes.Clone(private)
			switch fault {
			case "plan":
				observation.HostObservation.ResponseKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
			case "private":
				_, other, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				secret = []byte(base64.StdEncoding.EncodeToString(other))
				record.MaterialReferences[0].SHA256 = controllerSHA256(secret)
			case "pin":
				record.MaterialReferences[0].SHA256 = controllerSHA256([]byte("foreign key"))
			case "inconsistent private public":
				damaged := bytes.Clone(key)
				damaged[0] ^= 1
				secret = []byte(base64.StdEncoding.EncodeToString(damaged))
				record.MaterialReferences[0].SHA256 = controllerSHA256(secret)
			}
			if err := verifyIdentityRekeyResponseKey(observation, record, wire, secret); err == nil {
				t.Fatal("response signer mismatch admitted")
			}
		})
	}
}

func TestIdentityRekeyMaterialCleanupErasesAliasedPrivateBuffers(t *testing.T) {
	response, credential := []byte("private response key"), []byte("private NATS credential")
	install := identityRekeyInstall{contents: map[string][]byte{"controller-a-response.key": response, "controller-a.creds": credential},
		generationFiles: map[string][]byte{"controller-a.creds": credential}}
	install.clearMaterial()
	if !bytes.Equal(response, make([]byte, len(response))) || !bytes.Equal(credential, make([]byte, len(credential))) ||
		!bytes.Equal(install.generationFiles["controller-a.creds"], make([]byte, len(credential))) {
		t.Fatal("material cleanup left private bytes in retained or aliased buffers")
	}
}
