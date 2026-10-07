package bootstrapmaterial_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
)

// The role claim keeps the cell account as it was, host signer and
// JetStream included, adds the role signer the controllers derive, and is
// newer than the claim it replaces.
func TestRoleClaimAddsTheControllersRoleSigner(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	record, err := bootstrapmaterial.Generate(directory, bootstrapmaterial.Config{Environment: "production",
		Region: "sa-saopaulo-1", Cell: "gru", DeploymentID: "alpha-20260927", ClusterID: "alpha-gru", SubnetCIDR: "10.251.0.0/24",
		Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.10"}, {Name: "controller-b", PrivateIP: "10.251.0.11"},
			{Name: "controller-c", PrivateIP: "10.251.0.12"}}, ValidityHours: 48}, time.Now().UTC().Add(-time.Minute).Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	current := string(read("cell.jwt"))
	time.Sleep(time.Second) // brokers take only a newer claim
	raw, signer, err := bootstrapmaterial.RoleClaim(directory, current)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := jwt.DecodeAccountClaims(current)
	after, err := jwt.DecodeAccountClaims(raw)
	if err != nil || after.Issuer != record.Public.OperatorNKey || after.IssuedAt <= before.IssuedAt ||
		len(after.SigningKeys) != 2 || !reflect.DeepEqual(after.Limits, before.Limits) || after.Expires != before.Expires {
		t.Fatalf("role claim %+v: %v", after, err)
	}
	if _, host := after.SigningKeys.GetScope(record.Public.HostNATSIssuerNKey); !host {
		t.Fatal("the host signer was dropped")
	}
	time.Sleep(time.Second)
	if again, _, err := bootstrapmaterial.RoleClaim(directory, raw); err != nil || len(mustDecode(t, again).SigningKeys) != 2 {
		t.Fatalf("a second run added another signer: %v", err)
	}
	paths := func(name string) string { return filepath.Join(directory, name) }
	issuer, err := hostenroll.LoadIssuer("gru", record.Public.CellAccountNKey, paths("host-nats-issuer.seed"),
		paths("host-tls-issuer-key.pem"), paths("host-tls-issuer-cert.pem"), read("ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.ValidateRoleScope(raw); err != nil {
		t.Fatalf("the controllers refuse the role claim (signer %s): %v", signer, err)
	}
	if err := issuer.ValidateRoleScope(current); err == nil {
		t.Fatal("the controllers accept a claim without the role signer")
	}
	if _, _, err := bootstrapmaterial.RoleClaim(directory, string(read("system.jwt"))); err == nil {
		t.Fatal("another account's claim was signed")
	}
}

func mustDecode(t *testing.T, raw string) *jwt.AccountClaims {
	t.Helper()
	claim, err := jwt.DecodeAccountClaims(raw)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}
