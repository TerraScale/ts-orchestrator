package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

// serializedReplacer runs one founder replacement at a time on the seed,
// whether its own reconciler or a routed leader request asked for it.
type serializedReplacer struct {
	mu    sync.Mutex
	inner membership.Replacer
}

func (replacer *serializedReplacer) Replace(ctx context.Context, action membership.Action) error {
	replacer.mu.Lock()
	defer replacer.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return replacer.inner.Replace(ctx, action)
}

// seedRequestMaxBytes bounds one inbound routed replacement request.
const seedRequestMaxBytes = 128 << 10

// natsSeedRequester sends a routed replacement request to the seed over the
// controller's in-process connection.
func natsSeedRequester(conn *nats.Conn, subject string) membership.SeedRequester {
	return func(ctx context.Context, payload []byte) ([]byte, error) {
		if conn == nil || subject == "" {
			return nil, membership.ErrReplacerUnavailable
		}
		reply, err := conn.RequestWithContext(ctx, subject, payload)
		if err != nil {
			if errors.Is(err, nats.ErrNoResponders) {
				return nil, fmt.Errorf("no seed controller serves %s (seed down, route_to_seed off on the seed, or controller credentials without the membership.replace grant): %w", subject, err)
			}
			return nil, err
		}
		return reply.Data, nil
	}
}

// seedReplacementService answers routed replacement requests on the seed.
type seedReplacementService struct {
	conn    *nats.Conn
	subject string
	server  *membership.SeedServer
}

// Run serves until ctx ends, then cancels and joins any running routed
// replacement so no founder OCI call outlives the controller.
func (service *seedReplacementService) Run(ctx context.Context) error {
	defer service.server.Close()
	subscription, err := service.conn.Subscribe(service.subject, func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > seedRequestMaxBytes {
			return
		}
		// The reply must leave within the credential's five-second
		// response grant; the replacement itself runs in the background.
		requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		reply := service.server.Handle(requestCtx, message.Data)
		wire, err := protocol.EncodeJSON(reply)
		if err == nil {
			_ = message.Respond(wire)
		}
	})
	if err != nil {
		return fmt.Errorf("serve controller slot replacement requests: %w", err)
	}
	slog.Info("seed serves routed controller slot replacement requests", "component", "membership",
		"subject", service.subject)
	<-ctx.Done()
	_ = subscription.Unsubscribe()
	return nil
}
