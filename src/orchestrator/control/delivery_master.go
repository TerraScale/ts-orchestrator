package control

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/contracts"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// MasterDeliveryMaximumIntentBytes leaves room for the nested signed parent,
// derived request and lease proof within the regional envelope's fixed bound.
const MasterDeliveryMaximumIntentBytes = 256 * 1024
const MasterDeliveryMaximumEnvelopeBytes = 512 * 1024

// RegionalDeliveryRoute binds one admitted cell to its regional account and
// leaders bucket. MasterSignerKeyID must also be installed in that region's
// command trust; it delegates desired commands, not the regional writer lease.
type RegionalDeliveryRoute struct {
	Connection        *nats.Conn
	Leaders           jetstream.KeyValue
	MasterSignerKeyID string
}

type MasterDeliveryConfig struct {
	Cell, Instance   string
	Connection       *nats.Conn
	Leaders, Journal jetstream.KeyValue
	Authority        func() RegionalAuthoritySnapshot
	Fetcher          delivery.ArtifactFetcher
	Trust            func() *delivery.TrustSet
	Mirror           *delivery.ArtifactMirror
	Signer           *security.CommandSignatureSigner
	IntentVerifier   *security.CommandSignatureVerifier
	Regions          map[string]RegionalDeliveryRoute
	RequestTimeout   time.Duration
}

// MasterDelivery prepares global mirrors and durably fans out exact regional
// child commands. Submit consumes original signed wire bytes; see the master
// delivery contract for lineage, authority and recovery semantics.
// Connections belong to the caller and must outlive this adapter.
type MasterDelivery struct {
	config     MasterDeliveryConfig
	store      *natsDeliveryStore
	validation *protocol.CommandValidationContext
	gate       chan struct{}
}

type MasterRegionReceipt struct {
	Cell          string `json:"cell"`
	OperationID   string `json:"operationId"`
	PayloadDigest string `json:"payloadDigest"`
	Accepted      bool   `json:"accepted"`
}
type MasterDeliveryReceipt struct {
	OperationID  string                `json:"operationId"`
	IntentDigest string                `json:"intentDigest"`
	Generation   int64                 `json:"generation"`
	Complete     bool                  `json:"complete"`
	Regions      []MasterRegionReceipt `json:"regions"`
}

func NewMasterDelivery(ctx context.Context, c MasterDeliveryConfig) (*MasterDelivery, error) {
	if ctx == nil || c.Cell != "gru" || c.Instance == "" || c.Authority == nil || c.Leaders == nil || c.Journal == nil || c.Signer == nil || c.IntentVerifier == nil || deliveryNil(c.Fetcher) || c.Trust == nil || c.Trust() == nil || c.Mirror == nil {
		return nil, errors.New("master delivery: complete GRU global configuration is required")
	}
	if _, ok := contracts.CellIdTryCreate(c.Instance); !ok {
		return nil, errors.New("master delivery: instance is invalid")
	}
	if err := masterDeliveryTransport(c.Connection); err != nil {
		return nil, err
	}
	if c.Connection.MaxPayload() < messaging.DeliveryOperationMaxMessageBytes {
		return nil, errors.New("master delivery: NATS payload limit cannot hold the durable journal response")
	}
	if c.RequestTimeout <= 0 || c.RequestTimeout > 10*time.Minute {
		return nil, errors.New("master delivery: bounded regional request timeout is required")
	}
	if _, ok := c.Mirror.Store.(delivery.FencedRegionObjectStore); !ok {
		return nil, errors.New("master delivery: fenced artifact writes are required")
	}
	if _, ok := c.Mirror.Store.(delivery.RegionObjectStoreContentReader); !ok {
		return nil, errors.New("master delivery: verified artifact content reads are required")
	}
	// Capture the estate and route map so callers cannot change admitted scope.
	encoded, err := json.Marshal(c.Mirror.Spec)
	if err != nil {
		return nil, err
	}
	mirror := *c.Mirror
	if err := json.Unmarshal(encoded, &mirror.Spec); err != nil {
		return nil, err
	}
	if err := mirror.Spec.Validate(); err != nil {
		return nil, err
	}
	c.Mirror = &mirror
	regions := make(map[string]RegionalDeliveryRoute, len(c.Regions))
	declared := map[string]bool{}
	for _, region := range mirror.Spec.Regions {
		declared[region.Code] = true
	}
	for cell, route := range c.Regions {
		if !declared[cell] || route.Leaders == nil || route.MasterSignerKeyID != c.Signer.PublicKeyID() {
			return nil, errors.New("master delivery: regional route or delegated signer is not admitted")
		}
		if err := masterDeliveryTransport(route.Connection); err != nil {
			return nil, err
		}
		regions[cell] = route
	}
	if len(regions) == 0 {
		return nil, errors.New("master delivery: explicit regional routes are required")
	}
	c.Regions = regions
	store, err := newNatsDeliveryStore(ctx, c.Journal, c.Connection)
	if err != nil {
		return nil, err
	}
	cell, _ := contracts.CellIdTryCreate("gru")
	aggregate, _ := contracts.AggregateIdTryCreate("delivery-master")
	generation, _ := protocol.DesiredGenerationTryCreate(1)
	epoch, _ := protocol.WriterEpochTryCreate(1)
	version, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
	validation, err := protocol.NewCommandValidationContext(cell, aggregate, generation, epoch, []protocol.ProtocolRevision{version}, 0, masterDeliveryDigestVerifier{}, c.IntentVerifier)
	if err != nil {
		return nil, err
	}
	return &MasterDelivery{config: c, store: store, validation: validation, gate: make(chan struct{}, 1)}, nil
}

func masterDeliveryTransport(connection *nats.Conn) error {
	if connection == nil || !connection.IsConnected() || !connection.AuthRequired() || connection.Opts.TLSConfig == nil || connection.Opts.TLSConfig.InsecureSkipVerify || connection.Opts.TLSConfig.MinVersion < tls.VersionTLS13 || connection.Opts.SignatureCB == nil || (connection.Opts.Nkey == "" && connection.Opts.UserJWT == nil) || (connection.Opts.AllowReconnect && connection.Opts.ReconnectBufSize >= 0) {
		return errors.New("master delivery: authenticated TLS 1.3 NKey transport without reconnect buffering is required")
	}
	if len(connection.Opts.TLSConfig.Certificates) == 0 && connection.Opts.TLSConfig.GetClientCertificate == nil && connection.Opts.TLSCertCB == nil {
		return errors.New("master delivery: client certificate is required")
	}
	state, err := connection.TLSConnectionState()
	if err != nil || state.Version < tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		return errors.New("master delivery: verified transport is unavailable")
	}
	return nil
}
