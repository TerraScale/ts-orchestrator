//go:build sandboxvm

package vmqualruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

func TestControlDeclarationStoreLoadsPinnedCredentialsAndRejectsReplacement(t *testing.T) {
	server, authority := startDeliveryTestNATS(t)
	root := t.TempDir()
	identity := authority.controller
	files := map[string][]byte{"/etc/terrascale/reader.seed": identity.seed, "/etc/terrascale/reader.ca": authority.ca, "/etc/terrascale/reader.cert": identity.certificate, "/etc/terrascale/reader.key": identity.privateKey}
	refs := map[string]qualificationControlFile{}
	digest := func(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
	for guest, raw := range files {
		path := filepath.Join(root, filepath.Base(guest))
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		refs[guest] = qualificationControlFile{Source: path, SHA256: digest(raw)}
	}
	endpoint, _ := url.Parse(server.ClientURL())
	endpoint.Host = net.JoinHostPort(authority.serverName, endpoint.Port())
	declaration := qualificationControlStoreDeclaration{Reader: nodeauthority.ReaderConfig{Endpoint: endpoint.String(), ServerName: server.Name(), Account: "qualification", NKeySeedFile: "/etc/terrascale/reader.seed", PublicNKey: identity.publicKey, CAFile: "/etc/terrascale/reader.ca", CASHA256: digest(authority.ca), CertificateFile: "/etc/terrascale/reader.cert", CertificateSHA256: digest(identity.certificate), KeyFile: "/etc/terrascale/reader.key"}, Files: refs}
	store, release, err := loadQualificationControlStore(declaration)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	connection, err := nats.Connect(store.URL, append(store.Options, nats.SetCustomDialer(controlDeclarationTestDialer{address: server.Addr().String()}))...)
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if err := os.WriteFile(refs[declaration.Reader.NKeySeedFile].Source, authority.guests["gru-member-1"].seed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadQualificationControlStore(declaration); err == nil {
		t.Fatal("accepted replacement private key despite signed source digest")
	}
}

func TestControlManifestUsesContentAddressedStageAndExactPublishedArtifact(t *testing.T) {
	artifacts := map[string]vmimage.GuestArtifact{}
	manifest := hostmanifest.HostManifest{}
	for _, name := range []string{"orchestrator", "terrabase"} {
		artifact := vmimage.GuestArtifact{Component: name, Version: "release-1", SHA256: hex.EncodeToString(make([]byte, 32)), Source: "https://releases.terrascale.tech/releases/" + name + "/release-1/" + name}
		artifacts[name] = artifact
		spec, err := hostmanifest.NewComponentSpec(hostmanifest.ComponentSpec{Name: name, Version: artifact.Version, ArtifactURL: artifact.Source, SignatureURL: artifact.Source + ".sig", Sha256: artifact.SHA256, User: "terrascale-" + name, DataVolume: "/var/lib/terrascale/" + name, CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100})
		if err != nil {
			t.Fatal(err)
		}
		manifest.Components = append(manifest.Components, spec)
	}
	staged, err := bootstrap.PlanControlLaunchManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateQualificationManifestArtifacts(staged, artifacts); err != nil {
		t.Fatal(err)
	}
	staged.Components[0].ArtifactURL += "-replaced"
	if err := validateQualificationManifestArtifacts(staged, artifacts); err == nil {
		t.Fatal("accepted a source change")
	}
}

func TestCandidateBootstrapRejectsUnadmittedSecondHostAndReservedRegion(t *testing.T) {
	services := &qualificationRuntimeServices{controlAdmission: &qualificationControlAdmission{}, natsAuthority: &qualificationNATSAuthority{}}
	for _, guest := range []vmqual.Guest{{ID: "sfo-member-2", Region: "SFO"}, {ID: "iad-member-1", Region: "IAD"}} {
		if _, _, err := services.bootstrapCandidate(guest); err == nil {
			t.Fatalf("unadmitted host %s bootstrapped", guest.ID)
		}
	}
}

type controlDeclarationTestDialer struct{ address string }

func (d controlDeclarationTestDialer) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, d.address)
}
