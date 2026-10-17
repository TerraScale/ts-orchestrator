package rootsecret

import (
	"context"
	"net"
	"os"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
)

// OpenNetBirdReaderFromJournal resolves mesh locators only after enrollment,
// retaining the journal client's original CURRENT and readonly signer alone.
func OpenNetBirdReaderFromJournal(ctx context.Context, client *NetBirdJournalClient) (*NetBirdReader, error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil || client == nil {
		return nil, ErrDelivery
	}
	inputs, err := client.brokerReaderInputs(ctx)
	if err != nil {
		return nil, ErrDelivery
	}
	material, source := inputs.material, inputs.source
	retained := false
	defer func() {
		if !retained {
			clear(material.Credentials)
			clear(material.Key)
		}
	}()
	if inputs.ctx == nil || inputs.guard == nil || inputs.currentID == "" || inputs.currentVersion <= 0 || inputs.currentSHA256 == "" ||
		material.Schema != 1 || len(material.Endpoints) != 0 || !source.startup.IsVerified() {
		return nil, ErrDelivery
	}
	deadline := minDeadline(inputs.expires, minDeadline(material.ExpiresAt, minDeadline(source.ExpiresAt(), inputs.recipient.ExpiresAt())))
	if !inputs.currentExpiry.IsZero() {
		deadline = minDeadline(deadline, inputs.currentExpiry)
	}
	readerCtx, cancel := context.WithDeadline(inputs.ctx, deadline)
	ctx, stop := netBirdReadContext(ctx, readerCtx, minDeadline(deadline, time.Now().Add(30*time.Second)))
	defer stop()
	if inputs.guard(ctx) != nil || source.guardPublicSource(ctx) != nil {
		cancel()
		return nil, ErrDelivery
	}
	for _, slot := range source.source.Manifest().ControllerSlots {
		ip, err := netbird.BrokerRoute(ctx, netBirdControllerPeerName(material.Cell, slot))
		if err != nil {
			cancel()
			return nil, ErrDelivery
		}
		source.endpoints = append(source.endpoints, NetBirdBrokerEndpoint{Address: "tls://" + net.JoinHostPort(ip.String(), "4222"), ServerName: slot})
	}
	material.Endpoints = slices.Clone(source.endpoints)
	tlsConfig, _, err := CheckNetBirdBrokerMaterial(material, source, inputs.recipient, time.Now().UTC())
	if err != nil || len(material.Endpoints) == 0 || source.Guard(ctx) != nil || inputs.guard(ctx) != nil {
		cancel()
		return nil, ErrDelivery
	}
	r := &NetBirdReader{ctx: readerCtx, cancel: cancel, material: material, source: source}
	r.guard = func(check context.Context) error {
		if check == nil || readerCtx.Err() != nil {
			return ErrDelivery
		}
		check, stop := netBirdReadContext(check, readerCtx, deadline)
		defer stop()
		if inputs.guard(check) != nil || source.Guard(check) != nil || inputs.recipient.Check(check) != nil {
			return ErrDelivery
		}
		if _, _, err := CheckNetBirdBrokerMaterial(material, source, inputs.recipient, time.Now().UTC()); err != nil || inputs.guard(check) != nil {
			return ErrDelivery
		}
		return check.Err()
	}
	connected, err := connectNetBirdReader(ctx, r, tlsConfig)
	if err != nil {
		return nil, err
	}
	retained = true
	return connected, nil
}
