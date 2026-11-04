package app

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"

	"github.com/nats-io/nkeys"
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
