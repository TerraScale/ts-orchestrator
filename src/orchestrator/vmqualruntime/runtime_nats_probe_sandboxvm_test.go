//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"testing"
)

func TestNATSReadinessRequiresAuthenticatedController(t *testing.T) {
	server, authority := startDeliveryTestNATS(t)
	services := &qualificationRuntimeServices{natsAuthority: authority}
	if err := services.probeNATSController(context.Background(), server.ClientURL()); err != nil {
		t.Fatal(err)
	}
	authority.controller.publicKey = "invalid"
	if err := services.probeNATSController(context.Background(), server.ClientURL()); err == nil {
		t.Fatal("unauthenticated readiness accepted")
	}
}
