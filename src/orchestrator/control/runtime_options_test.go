package control

import (
	"strings"
	"testing"
)

func TestRuntimeOptionStringsRedactCredentials(t *testing.T) {
	options := &OrchestratorOptions{Command: OrchestratorCommandRun, Cell: "gru", NatsURL: "tls://controller:password@nats.example", Replicas: 3, Instance: "one"}
	if rendered := options.String(); strings.Contains(rendered, "password") || !strings.Contains(rendered, "command_identity=false") {
		t.Fatalf("options string = %q", rendered)
	}
}
