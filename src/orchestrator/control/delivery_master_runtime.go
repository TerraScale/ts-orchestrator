package control

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// MasterDeliveryRuntimeConfig supplies real external adapters and signing trust.
// GlobalNatsRuntime owns authority, the global connection, and the subscription;
// the caller owns regional connections and signer lifetime.
type MasterDeliveryRuntimeConfig struct {
	Fetcher        delivery.ArtifactFetcher
	Trust          func() *delivery.TrustSet
	Mirror         *delivery.ArtifactMirror
	Signer         *security.CommandSignatureSigner
	IntentVerifier *security.CommandSignatureVerifier
	Regions        map[string]RegionalDeliveryRoute
	RequestTimeout time.Duration
}

// Validate checks that the root supplied every required master adapter.
// Live transport and journal validation happen when the runtime starts.
func (c *MasterDeliveryRuntimeConfig) Validate() error {
	if c == nil || deliveryNil(c.Fetcher) || c.Trust == nil || c.Trust() == nil || c.Mirror == nil || c.Signer == nil || c.IntentVerifier == nil || len(c.Regions) == 0 || c.RequestTimeout <= 0 || c.RequestTimeout > 10*time.Minute {
		return errors.New("global delivery requires complete master preparation, signing, and regional route configuration")
	}
	return nil
}

// MasterDeliveryResponse returns only durable progress. A failed response or
// missing reply requires retrying the same signed intent lineage.
type MasterDeliveryResponse struct {
	Code    CommandIngressCode     `json:"code"`
	Receipt *MasterDeliveryReceipt `json:"receipt,omitempty"`
}

type masterDeliveryRuntime struct {
	master       *MasterDelivery
	subscription *nats.Subscription
	lifetime     context.Context
	cancel       context.CancelFunc
	complete     chan struct{}
	closeOnce    sync.Once
}

func (r *GlobalNatsRuntime) startMasterDelivery(config *MasterDeliveryRuntimeConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	journal, err := r.state.js.KeyValue(r.lifetime, messaging.GlobalNatsTopologyMasterDeliveriesBucket)
	if err != nil {
		return err
	}
	// The adapter checks durability and size; the global composition additionally
	// requires the exact R3 profile provisioned by the global topology.
	stream, err := r.state.js.Stream(r.lifetime, "KV_"+journal.Bucket())
	if err != nil {
		return err
	}
	info, err := stream.Info(r.lifetime)
	if err != nil {
		return err
	}
	if err := NatsOperationJournalStore.ValidateExactStreamConfiguration(info.Config, NatsOperationJournalStore.CanonicalKeyValueStream(r.topology.MasterDeliveries())); err != nil {
		return err
	}
	component, err := startMasterDeliveryRuntime(r.lifetime, MasterDeliveryConfig{
		Cell: r.cell, Instance: r.instance, Connection: r.client, Leaders: r.state.leaders,
		Journal: journal, Authority: r.authority.Snapshot, Fetcher: config.Fetcher,
		Trust: config.Trust, Mirror: config.Mirror, Signer: config.Signer,
		IntentVerifier: config.IntentVerifier, Regions: config.Regions, RequestTimeout: config.RequestTimeout,
	})
	if err != nil {
		return err
	}
	r.delivery = component
	return nil
}

func startMasterDeliveryRuntime(ctx context.Context, config MasterDeliveryConfig) (*masterDeliveryRuntime, error) {
	master, err := NewMasterDelivery(ctx, config)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	sub, err := config.Connection.SubscribeSync(protocol.NatsSubjectTaxonomy.GlobalDeliverySubject())
	if err != nil {
		cancel()
		return nil, err
	}
	if err := sub.SetPendingLimits(16, 16*MasterDeliveryMaximumEnvelopeBytes); err != nil {
		cancel()
		_ = sub.Unsubscribe()
		return nil, err
	}
	if err := config.Connection.FlushTimeout(5 * time.Second); err != nil {
		cancel()
		_ = sub.Unsubscribe()
		return nil, err
	}
	runtime := &masterDeliveryRuntime{master: master, subscription: sub, lifetime: lifetime, cancel: cancel, complete: make(chan struct{})}
	go runtime.run()
	return runtime, nil
}

func (r *masterDeliveryRuntime) run() {
	defer close(r.complete)
	defer r.subscription.Unsubscribe()
	for {
		message, err := r.subscription.NextMsgWithContext(r.lifetime)
		if err != nil {
			return
		}
		if message == nil || message.Reply == "" {
			continue
		}
		snapshot := r.master.config.Authority()
		// Broadcast subscriptions allow every GRU replica to follow leadership.
		// Followers stay silent so they cannot race the writer's durable response.
		if err := r.master.checkGlobal(r.lifetime, snapshot.Epoch); err != nil {
			continue
		}
		receipt, err := r.master.Submit(r.lifetime, message.Data)
		response := MasterDeliveryResponse{Code: CommandIngressCodeDispatchFailed, Receipt: receipt}
		if err == nil && receipt != nil && receipt.Complete {
			response.Code = CommandIngressCodeAccepted
		}
		raw, err := json.Marshal(response)
		if err != nil || len(raw) > 16*1024 {
			raw = []byte(`{"code":"dispatch-failed"}`)
		}
		_ = message.Respond(raw)
	}
}

func (r *masterDeliveryRuntime) Completion() <-chan struct{} { return r.complete }
func (r *masterDeliveryRuntime) Close() error {
	r.closeOnce.Do(func() { r.cancel(); _ = r.subscription.Unsubscribe() })
	<-r.complete
	return nil
}
