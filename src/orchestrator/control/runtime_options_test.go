package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
)

func TestCiRunnerNatsIdentityOptionsRequireSecureBoundedSigningFile(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	account := mustRuntimeOptionsAccountSeed(t, filepath.Join(directory, "account.seed"), 0o600)
	identity, err := resolveCiRunnerNatsIdentityForOptions(account, "")
	if err != nil {
		t.Fatalf("resolve identity: %v", err)
	}
	if identity == nil || identity.SigningKeyFile != account || identity.AccountPublicKey != nil {
		t.Fatalf("identity = %#v", identity)
	}

	tooOpen := filepath.Join(directory, "too-open.seed")
	if err := os.WriteFile(tooOpen, []byte("not-a-seed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCiRunnerNatsIdentityForOptions(tooOpen, ""); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("too-open identity error = %v", err)
	}

	tooLarge := filepath.Join(directory, "too-large.seed")
	if err := os.WriteFile(tooLarge, make([]byte, 4097), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCiRunnerNatsIdentityForOptions(tooLarge, ""); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("too-large identity error = %v", err)
	}
}

func TestCiRunnerNatsIdentityOptionsRequireCompleteGroupAndValidateAccount(t *testing.T) {
	t.Parallel()

	if identity, err := resolveCiRunnerNatsIdentityForOptions("", "A123"); err == nil || identity != nil {
		t.Fatalf("account-only identity = %#v, err=%v", identity, err)
	}
	directory := t.TempDir()
	seedPath := mustRuntimeOptionsAccountSeed(t, filepath.Join(directory, "account.seed"), 0o600)
	if identity, err := resolveCiRunnerNatsIdentityForOptions(seedPath, strings.Repeat("A", shared.NatsAccountPublicKeyMaximumCharacters+1)); err == nil || identity != nil {
		t.Fatalf("oversized account identity = %#v, err=%v", identity, err)
	}
	accountPair, err := nkeys.FromSeed([]byte(mustRuntimeOptionsSeed(t, seedPath)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(accountPair.Wipe)
	public, err := accountPair.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := resolveCiRunnerNatsIdentityForOptions(seedPath, public)
	if err != nil || identity == nil || identity.AccountPublicKey == nil || *identity.AccountPublicKey != public {
		t.Fatalf("identity = %#v, err=%v", identity, err)
	}
}

func TestCiRunnerNatsIdentityOptionsRejectUnownedCommands(t *testing.T) {
	t.Parallel()

	for _, command := range []string{"catalog", "provision-journal", "journal-writer"} {
		for _, variable := range []string{
			"TS_ORCH_CI_RUNNER_NATS_ACCOUNT_SIGNING_KEY_FILE",
			"TS_ORCH_CI_RUNNER_NATS_ACCOUNT_PUBLIC_KEY",
		} {
			t.Run(command+"/"+variable, func(t *testing.T) {
				_, err := ParseOrchestratorOptions([]string{command}, optionTestEnvironment(map[string]string{variable: "private-material"}))
				if err == nil || !strings.Contains(err.Error(), "CI runner NATS identity") {
					t.Fatalf("error = %v", err)
				}
			})
		}
	}
}

func TestRuntimeOptionStringsRedactCiRunnerIdentity(t *testing.T) {
	t.Parallel()

	secretPath := "/private/runner-account-seed"
	identity := &CiRunnerNatsIdentityConfiguration{SigningKeyFile: secretPath}
	if rendered := identity.String(); rendered == "" || strings.Contains(rendered, secretPath) {
		t.Fatalf("identity string leaked credential path: %q", rendered)
	}
	options := &OrchestratorOptions{Command: OrchestratorCommandRun, Cell: "gru", NatsURL: "tls://runner:password@nats.example", Replicas: 3, Instance: "one", CiRunnerNatsIdentity: identity}
	if rendered := options.String(); strings.Contains(rendered, secretPath) || strings.Contains(rendered, "password") || !strings.Contains(rendered, "ci_runner_identity=true") {
		t.Fatalf("options string = %q", rendered)
	}
}

func mustRuntimeOptionsAccountSeed(t *testing.T, path string, mode os.FileMode) string {
	t.Helper()
	pair, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pair.Wipe)
	seed, err := pair.Seed()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(seed) })
	if err := os.WriteFile(path, seed, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustRuntimeOptionsSeed(t *testing.T, path string) string {
	t.Helper()
	seed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(seed) })
	return string(seed)
}
