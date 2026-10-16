//go:build fixturetest

package runtimefixture_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart/runtimefixture"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
)

// Current authority and foundation reads cross signed OCI SDK HTTP and the
// actual durable selection floor. Replacing the selector revokes the reader.
func TestSignedRuntimeAuthorityHTTP(t *testing.T) {
	material := generationtest.New(t, time.Now().UTC())
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := hostenroll.PublicBundle{SchemaVersion: 1, Cell: "gru", Region: "GRU", Environment: "canary",
		ControllerEndpoints: []string{"10.0.0.1:8443", "10.0.0.3:8443", "10.0.0.4:8443"},
		NATSURLs:            []string{"tls://10.0.0.1:4222", "tls://10.0.0.3:4222", "tls://10.0.0.4:4222"},
		CAPEM:               string(material.Files["ca.pem"]), CellAccountNKey: material.CellID,
		ControllerResponsePublicKey: base64.StdEncoding.EncodeToString(public),
		InstallRoot:                 hostenroll.ImageInstallRoot, StateRoot: hostenroll.ImageStateRoot, ManagedRuntimeRoot: hostenroll.ImageManagedRuntimeRoot,
		WorkloadUID: hostenroll.ImageWorkloadUID, WorkloadGID: hostenroll.ImageWorkloadGID}
	wire, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	fixture := runtimefixture.New(t, "10.0.0.1", wire, material)
	authority, err := fixture.Reader.ReadRuntimeAuthority(t.Context(), fixture.Accepted, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if authority.Identity().PrivateIP != "10.0.0.1" || authority.Identity().Slot != "controller-c" || !authority.Anchor().IsVerified() {
		t.Fatal("signed current authority lost the exact accepted manager")
	}
	foundation, err := fixture.Foundations.Resolve(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	target, err := foundation.VaultTarget()
	if err != nil || target.VaultID != "ocid1.vault.oc1.sa-saopaulo-1.control" {
		t.Fatal("signed foundation did not resolve its actual object record", err)
	}
	changed := fixture.Accepted.Clone()
	changed.ClusterID = changed.DeploymentID
	if _, err := fixture.Reader.ReadRuntimeAuthority(t.Context(), changed, time.Now().UTC()); err == nil {
		t.Fatal("signed authority accepted another cluster")
	}
	fixture.RevokeCurrent()
	if _, err := fixture.Reader.ReadRuntimeAuthority(t.Context(), fixture.Accepted, time.Now().UTC()); err == nil {
		t.Fatal("current reader retained authority after selector replacement")
	}
}
