package control

import (
	"strings"
	"testing"
)

func optionTestEnvironment(values map[string]string) EnvironmentLookup {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestOrchestratorOptionsCatalogAndDefaults(t *testing.T) {
	options, err := ParseOrchestratorOptions([]string{"catalog"}, optionTestEnvironment(nil))
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	if options.Command != OrchestratorCommandCatalog || options.Cell != "local" ||
		options.NatsURL != "nats://127.0.0.1:4222" || options.Replicas != 1 || options.Instance != "local" {
		t.Fatalf("unexpected defaults: %+v", options)
	}
	if _, err := ParseOrchestratorOptions([]string{"catalog", "extra"}, optionTestEnvironment(nil)); err == nil {
		t.Fatal("catalog accepted an argument")
	}
}

func TestOrchestratorOptionsCommandVocabulary(t *testing.T) {
	for _, test := range []struct {
		name    string
		command OrchestratorCommand
	}{
		{"run", OrchestratorCommandRun},
		{"check", OrchestratorCommandCheck},
		{"catalog", OrchestratorCommandCatalog},
		{"provision-journal", OrchestratorCommandProvisionJournal},
		{"journal-writer", OrchestratorCommandJournalWriter},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, err := ParseOrchestratorOptions([]string{test.name}, optionTestEnvironment(nil))
			if test.command == OrchestratorCommandRun || test.command == OrchestratorCommandProvisionJournal || test.command == OrchestratorCommandJournalWriter {
				if err == nil {
					t.Fatal("expected role-specific credentials error")
				}
				return
			}
			if err != nil || options.Command != test.command {
				t.Fatalf("command=%v err=%v", options, err)
			}
		})
	}
	if _, err := ParseOrchestratorOptions([]string{"lab"}, optionTestEnvironment(nil)); err == nil || !strings.Contains(err.Error(), "Unknown command 'lab'") {
		t.Fatalf("unexpected unknown command error: %v", err)
	}
}

func TestOrchestratorOptionsValidatesTokensURLAndReplicas(t *testing.T) {
	checks := []struct {
		name  string
		value map[string]string
		want  string
	}{
		{"cell", map[string]string{"TS_ORCH_CELL": "Bad"}, "TS_ORCH_CELL"},
		{"instance", map[string]string{"TS_ORCH_INSTANCE": "controller/2"}, "TS_ORCH_INSTANCE"},
		{"url", map[string]string{"TS_ORCH_NATS_URL": "http://127.0.0.1:4222"}, "TS_ORCH_NATS_URL"},
		{"replicas", map[string]string{"TS_ORCH_REPLICAS": "2"}, "TS_ORCH_REPLICAS"},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			_, err := ParseOrchestratorOptions([]string{"check"}, optionTestEnvironment(check.value))
			if err == nil || !strings.Contains(err.Error(), check.want) {
				t.Fatalf("error=%v, want %q", err, check.want)
			}
		})
	}
}

func TestOrchestratorOptionsRejectsUnownedCredentialFamilies(t *testing.T) {
	for _, test := range []struct {
		command  string
		name     string
		variable string
		value    string
		want     string
	}{
		{"run", "infrastructure", "TS_ORCH_INFRA_NATS_NKEY_FILE", "private-seed", "infrastructure"},
		{"run", "journal", "TS_ORCH_JOURNAL_NATS_NKEY_FILE", "private-seed", "journal-writer"},
		{"catalog", "global", "TS_ORCH_GLOBAL_NATS_NKEY_FILE", "private-seed", "controller"},
		{"provision-journal", "controller", "TS_ORCH_NATS_NKEY_FILE", "private-seed", "controller"},
		{"journal-writer", "global", "TS_ORCH_GLOBAL_NATS_NKEY_FILE", "private-seed", "controller"},
	} {
		t.Run(test.command+"-"+test.name, func(t *testing.T) {
			_, err := ParseOrchestratorOptions([]string{test.command}, optionTestEnvironment(map[string]string{
				test.variable: test.value,
			}))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestOrchestratorOptionsRejectsEveryUnownedCredentialVariable(t *testing.T) {
	variables := []struct {
		name  string
		owner string
		want  string
	}{
		{"TS_ORCH_NATS_NKEY_FILE", "controller", "controller"},
		{"TS_ORCH_NATS_TLS_CA_FILE", "controller", "controller"},
		{"TS_ORCH_NATS_TLS_CERT_FILE", "controller", "controller"},
		{"TS_ORCH_NATS_TLS_KEY_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_NATS_URL", "controller", "controller"},
		{"TS_ORCH_GLOBAL_NATS_NKEY_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_NATS_CREDENTIALS_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_NATS_TLS_CA_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_NATS_TLS_CERT_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_NATS_TLS_KEY_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_DIRECTORY_NATS_URL", "controller", "controller"},
		{"TS_ORCH_GLOBAL_DIRECTORY_NATS_NKEY_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_DIRECTORY_NATS_CREDENTIALS_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CA_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CERT_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_KEY_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_URL", "controller", "controller"},
		{"TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_NKEY_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_CREDENTIALS_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CA_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CERT_FILE", "controller", "controller"},
		{"TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_KEY_FILE", "controller", "controller"},
		{"TS_ORCH_INFRA_NATS_NKEY_FILE", "infrastructure", "infrastructure"},
		{"TS_ORCH_INFRA_NATS_TLS_CA_FILE", "infrastructure", "infrastructure"},
		{"TS_ORCH_INFRA_NATS_TLS_CERT_FILE", "infrastructure", "infrastructure"},
		{"TS_ORCH_INFRA_NATS_TLS_KEY_FILE", "infrastructure", "infrastructure"},
		{"TS_ORCH_JOURNAL_NATS_NKEY_FILE", "journal-writer", "journal-writer"},
		{"TS_ORCH_JOURNAL_NATS_TLS_CA_FILE", "journal-writer", "journal-writer"},
		{"TS_ORCH_JOURNAL_NATS_TLS_CERT_FILE", "journal-writer", "journal-writer"},
		{"TS_ORCH_JOURNAL_NATS_TLS_KEY_FILE", "journal-writer", "journal-writer"},
		{"TS_ORCH_JOURNAL_AUTHORITY_PUBLIC_KEY_FILE", "journal-writer", "journal-writer"},
		{"TS_ORCH_JOURNAL_REPLY_SIGNING_KEY_FILE", "journal-writer", "journal-writer"},
		{"TS_ORCH_JOURNAL_CONTROLLER_NKEYS", "journal-writer", "journal-writer"},
	}
	commands := []string{"run", "check", "catalog", "provision-journal", "journal-writer"}
	for _, variable := range variables {
		for _, command := range commands {
			if (variable.owner == "controller" && (command == "run" || command == "check")) ||
				(variable.owner == "infrastructure" && command == "provision-journal") ||
				(variable.owner == "journal-writer" && command == "journal-writer") ||
				(variable.owner == "ci-runner" && (command == "run" || command == "check")) {
				continue
			}
			t.Run(variable.name+"/"+command, func(t *testing.T) {
				_, err := ParseOrchestratorOptions([]string{command}, optionTestEnvironment(map[string]string{
					variable.name: "private-material",
				}))
				if err == nil || !strings.Contains(err.Error(), variable.want) {
					t.Fatalf("error=%v, want %q", err, variable.want)
				}
			})
		}
	}
}

func TestOrchestratorOptionsRejectsArgumentsBeforeEnvironmentResolution(t *testing.T) {
	lookups := 0
	_, err := ParseOrchestratorOptions([]string{"catalog", "extra"}, func(string) (string, bool) {
		lookups++
		return "", false
	})
	if err == nil || !strings.Contains(err.Error(), "does not accept arguments") {
		t.Fatalf("error=%v", err)
	}
	if lookups != 0 {
		t.Fatalf("argument rejection performed %d environment lookups", lookups)
	}
}

func TestOrchestratorOptionsDoesNotReadEnvironmentImplicitly(t *testing.T) {
	if _, err := ParseOrchestratorOptions([]string{"catalog"}, nil); err == nil {
		t.Fatal("nil lookup unexpectedly accepted")
	}
}
