//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"errors"
	"fmt"
	"github.com/nats-io/nats.go"
	"net"
	"os"
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

func TestActivationStatusRetainsNoRespondersBeforeDeadline(t *testing.T) {
	var failures activationStatusFailures
	previous := failures.record(fmt.Errorf("status request: %w", nats.ErrNoResponders), nil)
	previous = failures.record(context.DeadlineExceeded, previous)
	previous = failures.record(&net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, previous)
	if !errors.Is(previous, nats.ErrNoResponders) {
		t.Fatal("terminal timeout masked earlier no-responder failure")
	}
	if failures.noResponders != 1 || failures.timeout != 2 || failures.authentication != 0 || failures.other != 0 {
		t.Fatalf("failure categories = %+v", failures)
	}
}
