package app

import (
	"context"
	"encoding/json/v2"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/nats-io/nats.go"
)

// serveArtifactAdmission accepts signed source claims from operator clients.
// The controller verifies the signature, role grant and stored bytes before
// creating the durable admission. Every controller observes the request, but
// only the live leader replies, so a standby cannot win with a stale result.
func serveArtifactAdmission(ctx context.Context, conn *nats.Conn, cell string, fencer authority.Fencer, service *delivery.Service) (*nats.Subscription, error) {
	return conn.Subscribe(delivery.ArtifactClaimSubject(cell), func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > delivery.MaxArtifactClaimBytes || !fencer.Current().CanMutate() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := fencer.Guard(requestCtx, fencer.Current().Epoch); err != nil {
			return
		}
		record, err := service.AcceptArtifactClaim(requestCtx, message.Data)
		if !fencer.Current().CanMutate() || fencer.Guard(requestCtx, fencer.Current().Epoch) != nil {
			return
		}
		response := artifactAdmissionResponse{Record: record}
		if err != nil {
			response.Record = delivery.ArtifactRecord{}
			response.Error = err.Error()
		}
		wire, err := json.Marshal(response)
		if err == nil {
			_ = message.Respond(wire)
		}
	})
}
