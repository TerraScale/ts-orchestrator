//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

// Called under services.mu before publishing startup success. Socket binding
// alone does not prove TLS, client authentication or a working NATS session.
func (services *qualificationRuntimeServices) probeNATSController(ctx context.Context, address string) error {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := probeCtx.Err(); err != nil {
		return err
	}
	options, err := services.natsAuthority.options(services.natsAuthority.controller)
	if err != nil {
		return err
	}
	deadline, _ := probeCtx.Deadline()
	options = append(options, nats.Timeout(time.Until(deadline)), nats.Name("vmqual-controller-readiness"), nats.ReconnectBufSize(0))
	connection, err := nats.Connect(address, options...)
	if err != nil {
		return fmt.Errorf("vmqual: authenticate embedded NATS readiness: %w", err)
	}
	defer connection.Close()
	state, err := connection.TLSConnectionState()
	if err != nil || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		return errors.New("vmqual: embedded NATS readiness lacks verified TLS1.3")
	}
	if err := connection.FlushWithContext(probeCtx); err != nil {
		return fmt.Errorf("vmqual: embedded NATS readiness round trip: %w", err)
	}
	return nil
}
