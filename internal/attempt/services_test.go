package attempt

import (
	"context"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const fakeVault = "ocid1.vault.oc1..fake"

// fakeLeader answers the services phase's operator commands as the
// authority leader would: a change the applied spec already holds plans
// nothing and writes no candidate.
type fakeLeader struct {
	applied  map[string]bool
	planned  map[string]string // candidate or signed file -> change
	commands [][]string
}

func (l *fakeLeader) run(_ context.Context, c Command) (string, error) {
	l.commands = append(l.commands, c.Args)
	out := flagValue(c.Args, "--out")
	var change string
	switch {
	case slices.Contains(c.Args, "rm"):
		for _, path := range c.Args[slices.Index(c.Args, "--")+1:] {
			os.Remove(path)
		}
		return "", nil
	case slices.Contains(c.Args, "sign-spec-delegation"):
		return "", os.WriteFile(out, []byte("{}"), 0o600)
	case slices.Contains(c.Args, "sign-spec"):
		l.planned[out] = l.planned[flagValue(c.Args, "--candidate")]
		return "", os.WriteFile(out, []byte("{}"), 0o600)
	case slices.Contains(c.Args, "apply"):
		l.applied[l.planned[flagValue(c.Args, "--file")]] = true
		return "", nil
	case slices.Contains(c.Args, "add"):
		change = "service " + flagValue(c.Args, "--role") + " " + flagValue(c.Args, "--profile")
	case slices.Contains(c.Args, "grant-host"):
		change = "grant " + strings.Join(c.Args[slices.Index(c.Args, "--node"):], " ")
	default:
		return "", nil
	}
	if l.applied[change] {
		return `{"status":"unchanged"}`, nil
	}
	l.planned[out] = change
	return `{"status":"planned","root_required":["` + change + `"]}`, os.WriteFile(out, []byte("{}"), 0o600)
}

// count is how many commands contain word.
func (l *fakeLeader) count(word string) int {
	return len(slices.DeleteFunc(slices.Clone(l.commands), func(c []string) bool { return !slices.Contains(c, word) }))
}

// servicesAttempt is an attempt over plan, bound to a fake Vault, with
// memberCA as its material's TerraBase member CA.
func servicesAttempt(t *testing.T, plan, memberCA string) (*Attempt, *fakeLeader) {
	t.Helper()
	a := smallAttempt(t)
	a.Config["trust"] = Object{"root_public": "/keys/root.pub", "root_private": "/keys/root.key",
		"release_leaf_public": "/keys/leaf.pub", "release_leaf_private": "/keys/leaf.key"}
	bound := a.read(plan)
	object(bound["resource_ids"])["vault"] = fakeVault
	a.writeJSON(a.Plan(), bound)
	a.fail(a.WriteNew(a.Path("material", "terrabase-member-ca.pem"), []byte(memberCA)))
	if a.Err() != nil {
		t.Fatal(a.Err())
	}
	leader := &fakeLeader{applied: map[string]bool{}, planned: map[string]string{}}
	a.Runner = leader.run
	return a, leader
}

const testCA = "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"

// A non-home cell's first generations come from its plan alone: sfo-1's
// TerraBase profile is the one its generation 1 had by hand, then ts-auth,
// then a root-signed host grant for every node. A rerun plans nothing.
func TestServicesPhaseDerivesANewCellsFirstGenerations(t *testing.T) {
	a, leader := servicesAttempt(t, "../../deploy/oci-region/sfo-1-plan.json", testCA)
	a.PhaseServices()
	if a.Err() != nil {
		t.Fatal(a.Err())
	}
	terraBase := a.read(a.Path("services", "terrabase.profile.json"))
	want := Object{"resources": Object{"cpu": 1.0, "memory_bytes": float64(4 << 30), "disk_bytes": float64(20 << 30)}, "env": Object{
		"TERRABASE_REGION": "sfo-1", "TERRABASE_PEER_PORT": "9443", "TERRABASE_CLIENT_PORT": "9465",
		"TERRABASE_PEERS":           "ts-sfo-1=10.252.0.11:9443,ts-sfo-2=10.252.0.12:9443,ts-sfo-3=10.252.0.13:9443",
		"TERRABASE_CATALOG_PRIMARY": "ts-sfo-1",
		// gru.auth already serves, so sfo's TerraBase trusts it from the start.
		"TERRABASE_AUTH_ISSUER":   "https://gru.auth.terrascale.tech/terrascale",
		"TERRABASE_AUTH_AUDIENCE": "https://sfo.api.terrascale.tech,https://gru.api.terrascale.tech",
	}}
	if !reflect.DeepEqual(terraBase, want) {
		t.Fatalf("terrabase profile = %v", terraBase)
	}
	auth := a.read(a.Path("services", "ts-auth.profile.json"))
	env, secrets := object(auth["env"]), object(auth["secrets"])
	if env["TS_AUTH_PUBLIC_ORIGIN"] != "https://sfo.auth.terrascale.tech" || env["TS_AUTH_TERRASCALE_API_URL"] != "https://sfo.api.terrascale.tech" ||
		env["TS_AUTH_ACCESS_TOKEN_AUDIENCES"] != "https://sfo.api.terrascale.tech" || env["TS_AUTH_TERRASCALE_API_CA"] != testCA ||
		env["TS_AUTH_TERRASCALE_API_ENDPOINTS"] != "https://10.252.0.11:9465;https://10.252.0.12:9465;https://10.252.0.13:9465" ||
		env["TS_AUTH_SMTP_HOST"] != "smtp.email.us-sanjose-1.oci.oraclecloud.com" || len(secrets) != 8 ||
		!reflect.DeepEqual(secrets["TS_AUTH_MASTER_KEY"], Object{"vault": fakeVault, "name": "sfo-1-ts-auth-master-key"}) {
		t.Fatalf("ts-auth profile = %v", auth)
	}
	// TerraBase first, then ts-auth with its spec, then the grants.
	var order []string
	for _, c := range leader.commands {
		if i := slices.Index(c, "service"); i >= 0 && c[i+1] != "apply" {
			order = append(order, c[i+1]+" "+flagValue(c, "--role")+flagValue(c, "--node"))
		}
	}
	if !slices.Equal(order, []string{"add terrabase", "add ts-auth", "grant-host ts-sfo-1", "grant-host ts-sfo-2", "grant-host ts-sfo-3"}) {
		t.Fatal(order)
	}
	for i, slot := range Slots {
		node, ip := "ts-sfo-"+string(rune('1'+i)), "10.252.0.1"+string(rune('1'+i))
		grant := slices.IndexFunc(leader.commands, func(c []string) bool { return flagValue(c, "--node") == node })
		c, sign := leader.commands[grant], leader.commands[grant+1]
		if flagValue(c, "--private-ip") != ip || flagValue(c, "--roles") != "terrabase,ts-auth" || flagValue(c, "--environment") != "canary" ||
			flagValue(c, "--controller") != slot || !slices.Contains(sign, "--root") || flagValue(sign, "--signing-key") != "/keys/root.key" {
			t.Fatal(c, sign)
		}
	}
	if leader.count("apply") != 5 || leader.count("--root") != 5 {
		t.Fatal(leader.commands)
	}
	// A rerun plans each change again from the cell's spec, which holds
	// them all, and signs and applies nothing.
	leader.commands = nil
	if a.PhaseServices(); a.Err() != nil || leader.count("sign-spec") != 0 || leader.count("apply") != 0 || leader.count("grant-host") != 3 {
		t.Fatal(a.Err(), leader.commands)
	}
}

// The plan derives GRU's bootstrap profiles; the reviewed profile supplies
// the separately provisioned signing publisher identity.
func TestServicesPhaseDerivesGRUsBootstrapProfiles(t *testing.T) {
	committed := func(name string) Object {
		var o Object
		b, err := os.ReadFile(filepath.Join("../../deploy/oci-region", name))
		if err == nil {
			err = json.Unmarshal(b, &o)
		}
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	authProfile := committed("ts-auth-gru-1-profile.json")
	for _, key := range []string{"TS_AUTH_SIGNING_KEY_VAULT", "TS_AUTH_SIGNING_KEY_SECRET", "TS_AUTH_OCI_REGION",
		"TS_AUTH_OCI_TENANCY", "TS_AUTH_OCI_USER", "TS_AUTH_OCI_FINGERPRINT"} {
		delete(object(authProfile["env"]), key)
	}
	delete(object(authProfile["secrets"]), "TS_AUTH_OCI_PRIVATE_KEY")
	a, leader := servicesAttempt(t, "../../deploy/oci-region/plan.json", str(object(authProfile["env"]), "TS_AUTH_TERRASCALE_API_CA"))
	// The committed profile names the live Vault.
	for _, ref := range object(authProfile["secrets"]) {
		object(ref)["vault"] = fakeVault
	}
	a.PhaseServices()
	if a.Err() != nil {
		t.Fatal(a.Err())
	}
	if got := a.read(a.Path("services", "ts-auth.profile.json")); !reflect.DeepEqual(got, authProfile) {
		t.Fatalf("ts-auth profile = %v\nwant %v", got, authProfile)
	}
	if got := a.read(a.Path("services", "ts-auth.service.json")); !reflect.DeepEqual(got, committed("ts-auth-gru-1-service.json")) {
		t.Fatalf("ts-auth service = %v", got)
	}
	terraBase := committed("terrabase-gru-1-profile.json")
	env := object(terraBase["env"])
	delete(env, "TERRABASE_AUTH_ISSUER")
	delete(env, "TERRABASE_AUTH_AUDIENCE")
	env["TERRABASE_CATALOG_PRIMARY"] = "gru-1-db-1"
	if got := a.read(a.Path("services", "terrabase.profile.json")); !reflect.DeepEqual(got, terraBase) {
		t.Fatalf("terrabase profile = %v", got)
	}
	var profile struct {
		Env     map[string]string          `json:"env"`
		Secrets map[string]vaultsecret.Ref `json:"secrets"`
	}
	if b, err := os.ReadFile(a.Path("services", "ts-auth.profile.json")); err != nil || json.Unmarshal(b, &profile) != nil {
		t.Fatal(err)
	}
	if err := tsauth.ValidateProfile("gru", nil, profile.Env, profile.Secrets); err != nil {
		t.Fatal(err)
	}
	if err := tsauth.ValidateMembers(profile.Env, a.profileEnv(a.Path("services", "terrabase.profile.json"))); err != nil {
		t.Fatal(err)
	}
	// The controllers colocate ts-auth; the database hosts run TerraBase and
	// enroll through its profile.
	for _, c := range leader.commands {
		if slices.Contains(c, "grant-host") && (flagValue(c, "--roles") != "ts-auth" || !strings.HasPrefix(flagValue(c, "--node"), "gru-1-ctl-")) {
			t.Fatal(c)
		}
	}
	if leader.count("grant-host") != 3 {
		t.Fatal(leader.commands)
	}
}

func TestServicesPhaseKeepsConfiguredSigningProfiles(t *testing.T) {
	for _, cell := range []string{"gru", "sfo"} {
		t.Run(cell, func(t *testing.T) {
			plan := "plan.json"
			if cell == "sfo" {
				plan = "sfo-1-plan.json"
			}
			a, leader := servicesAttempt(t, filepath.Join("../../deploy/oci-region", plan), testCA)
			profile := filepath.Join("../../deploy/oci-region", "ts-auth-"+cell+"-1-profile.json")
			a.Config["ts_auth_profile"] = profile
			a.Config["ts_auth_service"] = filepath.Join("../../deploy/oci-region", "ts-auth-"+cell+"-1-service.json")
			a.PhaseServices()
			if a.Err() != nil {
				t.Fatal(a.Err())
			}
			if exists(a.derivedProfile(tsauth.Role)) {
				t.Fatal("derived a replacement for the reviewed signing profile")
			}
			applied := 0
			for _, c := range leader.commands {
				if slices.Contains(c, "add") && flagValue(c, "--role") == tsauth.Role {
					if flagValue(c, "--profile") != profile {
						t.Fatal("did not use the reviewed signing profile")
					}
					applied++
				}
			}
			if applied != 1 {
				t.Fatalf("planned %d ts-auth profiles, want 1", applied)
			}
		})
	}
}

// A configured profile wins: the phase applies it as it is, and ts-auth's
// derived storage endpoints follow its members.
func TestServicesPhaseKeepsAConfiguredProfile(t *testing.T) {
	a, leader := servicesAttempt(t, "../../deploy/oci-region/sfo-1-plan.json", testCA)
	profile := a.Path("terrabase-profile.json")
	a.writeJSON(profile, Object{"env": Object{"TERRABASE_PEER_PORT": "9443", "TERRABASE_CLIENT_PORT": "9465",
		"TERRABASE_PEERS": "ts-sfo-2=10.252.0.12:9443"}})
	a.Config["terrabase_profile"] = profile
	services, err := a.cellServices()
	if err != nil || str(object(services[0]), "profile") != profile || exists(a.Path("services", "terrabase.profile.json")) {
		t.Fatal(err, services)
	}
	if got := str(object(a.read(a.Path("services", "ts-auth.profile.json"))["env"]), "TS_AUTH_TERRASCALE_API_ENDPOINTS"); got != "https://10.252.0.12:9465" {
		t.Fatal(got)
	}
	if a.terraBaseProfile() != profile {
		t.Fatal(a.terraBaseProfile())
	}
	// Only the node its profile lists runs TerraBase.
	a.PhaseServices()
	for _, c := range leader.commands {
		if slices.Contains(c, "grant-host") && (flagValue(c, "--roles") == "terrabase,ts-auth") != (flagValue(c, "--node") == "ts-sfo-2") {
			t.Fatal(c)
		}
	}
	if a.Err() != nil || leader.count("grant-host") != 3 {
		t.Fatal(a.Err(), leader.commands)
	}
}
