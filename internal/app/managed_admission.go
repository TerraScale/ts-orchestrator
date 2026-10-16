package app

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

// Operator-signed managed TerraBase requests share one admission subject.
// Production controller credentials grant a subscription to this subject and
// operator credentials grant a publish to it, so a new managed request kind
// never needs re-minted NATS credentials. The signed envelope kind, which
// every handler verifies again, selects the handler.
const (
	managedKindPlacement        = "placement.intent"
	managedKindPlacementStatus  = "placement.status"
	managedKindMaterialPrepare  = "material.prepare"
	managedKindCredentials      = "material.credentials"
	managedKindCredentialStatus = "material.credentials.status"
)

// maxManagedAdmissionWireBytes bounds every managed request before its
// handler applies the kind's own tighter limit.
const maxManagedAdmissionWireBytes = 64 << 10

func managedAdmissionSubject(cell string) string { return protocol.PlacementApplySubject(cell) }

// serveManagedAdmissionKind subscribes one handler to the shared subject. Each
// kind keeps its own subscription, so NATS delivers kinds concurrently while
// messages of one kind stay sequential, as with a dedicated subject.
func serveManagedAdmissionKind(ctx context.Context, conn *nats.Conn, cell, kind string,
	handle func(context.Context, *nats.Msg),
) (*nats.Subscription, error) {
	return conn.Subscribe(managedAdmissionSubject(cell), func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > maxManagedAdmissionWireBytes ||
			managedAdmissionKind(message.Data) != kind {
			return
		}
		handle(ctx, message)
	})
}

func managedAdmissionKind(wire []byte) string {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxManagedAdmissionWireBytes); err != nil {
		return ""
	}
	return envelope.Kind
}
