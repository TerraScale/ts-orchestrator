package app

import (
	"encoding/base64"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// A credential renewal rewrites host.json from the enrollment response; it
// must keep the operator's host-local options, or the next initializer
// restart disables online grow and the next self-update cannot prove its
// activation (#127 11987).
func TestHostEnrollmentRenewalKeepsHostLocalOptions(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	account, _ := nkeys.CreateAccount()
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	seed, _ := user.Seed()
	claims := jwt.NewUserClaims(userID)
	token, err := claims.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	bundle := hostenroll.PublicBundle{Cell: "gru", Environment: "production", NATSURLs: []string{"tls://10.0.0.1:4222"},
		InstallRoot: "/opt/terrascale", StateRoot: "/var/lib/terrascale"}
	pending := pendingHostEnrollment{IdentityKey: "identity", NATSUserSeed: base64.StdEncoding.EncodeToString(seed),
		TLSPrivateKey: "key"}
	install := func(jwtSuffix string) Config {
		t.Helper()
		response := hostenroll.Response{NATSUserJWT: token, TLSCertificatePEM: "cert" + jwtSuffix}
		if err := installHostEnrollment(root, bundle, hostboot.Descriptor{Node: "node-a"}, pending, response, uint32(os.Getuid())); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(root, "host.json"))
		if err != nil {
			t.Fatal(err)
		}
		var cfg Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	first := install("-1")
	if first.Host.ManagedVolumeOnlineGrow || first.Host.SelfUpdateProofFile != "" || first.Host.TerraBaseRoot != "" ||
		first.Host.TSAuthRoot != "" ||
		first.Host.TerraBaseDataVolume {
		t.Fatalf("first enrollment invented host-local options: %+v", first.Host)
	}
	// The operator enables the host-local options.
	first.Host.ManagedVolumeOnlineGrow = true
	first.Host.SelfUpdateProofFile = "/run/terrascale-orchestrator/host-proof.json"
	first.Host.SelfUpdateRoot = "/var/lib/terrascale-orchestrator/releases"
	first.Host.TerraBaseRoot = "/srv/ts-managed/terrabase"
	first.Host.TSAuthRoot = "/srv/ts-managed/ts-auth"
	first.Host.TerraBaseDataVolume = true
	first.Host.TerraBaseDataVolumeID = "ocid1.volume.oc1..first"
	first.Host.RoleMemoryMaxBytes = map[string]uint64{"terrabase": 3 << 30}
	wire, err := protocol.EncodeJSON(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "host.json"), wire, 0o600); err != nil {
		t.Fatal(err)
	}
	renewed := install("-2")
	if !renewed.Host.ManagedVolumeOnlineGrow || renewed.Host.SelfUpdateProofFile != first.Host.SelfUpdateProofFile ||
		renewed.Host.SelfUpdateRoot != first.Host.SelfUpdateRoot || renewed.Host.TerraBaseRoot != first.Host.TerraBaseRoot ||
		renewed.Host.TSAuthRoot != first.Host.TSAuthRoot ||
		!renewed.Host.TerraBaseDataVolume || renewed.Host.TerraBaseDataVolumeID != first.Host.TerraBaseDataVolumeID ||
		renewed.Host.RoleMemoryMaxBytes["terrabase"] != 3<<30 {
		t.Fatalf("renewal dropped host-local options: %+v", renewed.Host)
	}
	if renewed.NATS.TLS.CertFile == first.NATS.TLS.CertFile {
		t.Fatal("renewal did not switch to the new credential directory")
	}
	// An unreadable existing config fails the rewrite instead of dropping
	// the options silently.
	if err := os.WriteFile(filepath.Join(root, "host.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	response := hostenroll.Response{NATSUserJWT: token, TLSCertificatePEM: "cert-3"}
	err = installHostEnrollment(root, bundle, hostboot.Descriptor{Node: "node-a"}, pending, response, uint32(os.Getuid()))
	if err == nil || !strings.Contains(err.Error(), "existing host config") {
		t.Fatalf("corrupt existing host config = %v", err)
	}
}
