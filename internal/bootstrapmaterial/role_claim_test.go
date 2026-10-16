package bootstrapmaterial_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/roleidentity"
)

// New material's cell account carries the role signer the controllers
// derive (TS-663), exactly as role-claim adds it: role-claim on it changes
// only the issue time. On a cell founded before, role-claim keeps the cell
// account as it was, host signer and JetStream included, adds the role
// signer, and is newer than the claim it replaces.
func TestRoleClaimAddsTheControllersRoleSigner(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "material")
	record, err := bootstrapmaterial.Generate(directory, bootstrapmaterial.Config{Environment: "production",
		Region: "sa-saopaulo-1", Cell: "gru", DeploymentID: "0000000000XXVM2FA4QBBHZBKD", ClusterID: "00000000000C2KQX35BT9P1FFG", SubnetCIDR: "10.251.0.0/24",
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
	paths := func(name string) string { return filepath.Join(directory, name) }
	issuer, err := hostenroll.LoadIssuer("gru", record.Public.CellAccountNKey, paths("host-nats-issuer.seed"),
		paths("host-tls-issuer-key.pem"), paths("host-tls-issuer-cert.pem"), read("ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	generated := string(read("cell.jwt"))
	if err := issuer.ValidateRoleScope(generated); err != nil {
		t.Fatalf("the controllers refuse new material's cell account: %v", err)
	}
	time.Sleep(time.Second) // brokers take only a newer claim
	claimed, _, err := bootstrapmaterial.RoleClaim(directory, generated)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(withoutIssue(mustDecode(t, claimed)), withoutIssue(mustDecode(t, generated))) {
		t.Fatal("role-claim on new material changed more than the issue time")
	}

	// A cell founded before TS-663: its cell account lacks the role signer.
	operator, err := nkeys.FromSeed(read("issuer-operator.seed"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := mustDecode(t, generated)
	for key := range legacy.SigningKeys {
		if key != record.Public.HostNATSIssuerNKey {
			delete(legacy.SigningKeys, key)
		}
	}
	current, err := legacy.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.ValidateRoleScope(current); err == nil {
		t.Fatal("the controllers accept a claim without the role signer")
	}
	time.Sleep(time.Second)
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
	if !reflect.DeepEqual(after.SigningKeys, mustDecode(t, generated).SigningKeys) {
		t.Fatalf("role-claim added signer %s, not new material's", signer)
	}
	time.Sleep(time.Second)
	if again, _, err := bootstrapmaterial.RoleClaim(directory, raw); err != nil || len(mustDecode(t, again).SigningKeys) != 2 {
		t.Fatalf("a second run added another signer: %v", err)
	}
	if err := issuer.ValidateRoleScope(raw); err != nil {
		t.Fatalf("the controllers refuse the role claim (signer %s): %v", signer, err)
	}

	// A claim whose role signer has an older scope (gru-1 and sfo-1 before
	// TS-668's query grants): the controllers refuse it, and role-claim
	// replaces the scope in place.
	stale := mustDecode(t, raw)
	old := roleidentity.Scope(signer)
	old.Template.Pub.Allow, old.Template.Sub.Allow, old.Template.Resp = old.Template.Pub.Allow[:5], old.Template.Sub.Allow[:1], nil
	stale.SigningKeys.AddScopedSigner(old)
	staleJWT, err := stale.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.ValidateRoleScope(staleJWT); err == nil {
		t.Fatal("the controllers accept a role signer with an older scope")
	}
	time.Sleep(time.Second)
	if replaced, _, err := bootstrapmaterial.RoleClaim(directory, staleJWT); err != nil || issuer.ValidateRoleScope(replaced) != nil ||
		len(mustDecode(t, replaced).SigningKeys) != 2 {
		t.Fatalf("role-claim did not replace the older scope: %v", err)
	}
	if _, _, err := bootstrapmaterial.RoleClaim(directory, string(read("system.jwt"))); err == nil {
		t.Fatal("another account's claim was signed")
	}
}

// withoutIssue clears the issue time and the claim ID, its hash.
func withoutIssue(claim *jwt.AccountClaims) *jwt.AccountClaims {
	claim.IssuedAt, claim.ID = 0, ""
	return claim
}

func mustDecode(t *testing.T, raw string) *jwt.AccountClaims {
	t.Helper()
	claim, err := jwt.DecodeAccountClaims(raw)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}
