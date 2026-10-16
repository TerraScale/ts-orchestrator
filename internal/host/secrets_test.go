package host

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// TestDesiredSecretRefs accepts a role's own Vault secret names, and only
// secret files for a TerraBase member, and refuses them on a withdrawal, a
// managed member, for another role's secrets, for a key the environment also
// sets or one the host sets for the role's NATS identity.
func TestDesiredSecretRefs(t *testing.T) {
	registration := Registration{Node: "node-a", Environment: "test", Roles: []string{"billing", "terrabase"}}
	desired := func() Desired {
		return Desired{Cell: "gru", Node: "node-a", Environment: "test", Role: "billing", Digest: strings.Repeat("a", 64),
			Generation: 1, Env: map[string]string{"PORT": "8080"},
			Secrets: map[string]vaultsecret.Ref{"API_TOKEN": {Vault: tsAuthTestVault, Name: "gru-1-billing-token"}}}
	}
	if err := validateDesired(desired(), "gru", registration); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Desired){
		"withdrawn": func(d *Desired) { d.Withdrawn, d.Digest, d.Env = true, "", nil },
		"terrabase": func(d *Desired) {
			d.Role, d.Secrets = "terrabase", map[string]vaultsecret.Ref{"K": {Vault: tsAuthTestVault, Name: "gru-1-terrabase-k"}}
		},
		"other role": func(d *Desired) {
			d.Secrets = map[string]vaultsecret.Ref{"PAT": {Vault: tsAuthTestVault, Name: "gru-1-netbird-admin-pat"}}
		},
		"also in env": func(d *Desired) { d.Env["API_TOKEN"] = "x" },
		"bad vault": func(d *Desired) {
			d.Secrets["API_TOKEN"] = vaultsecret.Ref{Vault: "vault", Name: "gru-1-billing-token"}
		},
	} {
		d := desired()
		change(&d)
		if err := validateDesired(d, "gru", registration); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	files := desired()
	files.Role, files.Env = "terrabase", nil
	files.Secrets = map[string]vaultsecret.Ref{"TERRABASE_BACKUP_SECRET_KEY_FILE": {Vault: tsAuthTestVault, Name: "gru-1-terrabase-backup-secret-key"}}
	if err := validateDesired(files, "gru", registration); err != nil {
		t.Fatalf("a TerraBase secret file was refused: %v", err)
	}
	for name, change := range map[string]func(*Desired){
		"NATS setting in env": func(d *Desired) { d.Env = map[string]string{"TERRABASE_NATS_URL": "tls://x:4222"} },
		"NATS setting as a secret": func(d *Desired) {
			d.Secrets = map[string]vaultsecret.Ref{"TERRABASE_NATS_CREDENTIALS_FILE": {Vault: tsAuthTestVault, Name: "gru-1-terrabase-creds"}}
		},
	} {
		d := files
		change(&d)
		if err := validateDesired(d, "gru", registration); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	d := desired()
	d.Env = nil
	if err := validateManagedMemberLaunch(ManagedMemberLaunch{}, d, registration); err == nil {
		t.Error("managed member accepted Vault secrets")
	}
}

// TestResolveSecretsAtLaunch reads a desired's secrets through the agent's
// resolver and refuses a launch it cannot complete.
func TestResolveSecretsAtLaunch(t *testing.T) {
	refs := map[string]vaultsecret.Ref{"API_TOKEN": {Vault: tsAuthTestVault, Name: "gru-1-billing-token"}}
	d := Desired{Role: "billing", Secrets: refs}
	if values, err := (&Agent{}).resolveSecrets(t.Context(), Desired{Role: "billing"}); values != nil || err != nil {
		t.Fatalf("a desired without secrets read %v: %v", values, err)
	}
	if _, err := (&Agent{}).resolveSecrets(t.Context(), d); err == nil {
		t.Fatal("launched without a secret resolver")
	}
	for name, resolver := range map[string]func(context.Context, map[string]vaultsecret.Ref) (map[string]string, error){
		"failed read": func(context.Context, map[string]vaultsecret.Ref) (map[string]string, error) {
			return nil, errors.New("denied")
		},
		"missing value": func(context.Context, map[string]vaultsecret.Ref) (map[string]string, error) {
			return map[string]string{}, nil
		},
		"extra value": func(context.Context, map[string]vaultsecret.Ref) (map[string]string, error) {
			return map[string]string{"API_TOKEN": "value", "OTHER": "value"}, nil
		},
	} {
		if _, err := (&Agent{cfg: AgentConfig{SecretResolver: resolver}}).resolveSecrets(t.Context(), d); err == nil {
			t.Errorf("%s: launched", name)
		}
	}
	agent := &Agent{cfg: AgentConfig{SecretResolver: func(ctx context.Context, got map[string]vaultsecret.Ref) (map[string]string, error) {
		if _, ok := ctx.Deadline(); !ok || len(got) != 1 || got["API_TOKEN"] != refs["API_TOKEN"] {
			return nil, errors.New("unbounded or wrong refs")
		}
		return map[string]string{"API_TOKEN": "value"}, nil
	}}}
	if values, err := agent.resolveSecrets(t.Context(), d); err != nil || values["API_TOKEN"] != "value" {
		t.Fatalf("resolved %v: %v", values, err)
	}
}
