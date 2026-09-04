package control

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"

	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

// GlobalCellDirectoryServiceRuntime exposes the global cell projection through
// a read-only NATS service with a distinct identity.
type GlobalCellDirectoryServiceRuntime struct {
	client   *nats.Conn
	service  *shared.NatsSvcServer
	disposed int32
}

// GlobalCellDirectoryServiceRuntimeStartAsync starts the GRU read-only
// directory query service.
func GlobalCellDirectoryServiceRuntimeStartAsync(
	ctx context.Context,
	configuration *GlobalDirectoryServiceNatsConfiguration,
	snapshot func() GlobalCellDirectorySnapshot,
) (*GlobalCellDirectoryServiceRuntime, error) {
	if ctx == nil {
		return nil, errors.New("(Parameter 'ctx')")
	}
	if configuration == nil {
		return nil, errors.New("(Parameter 'configuration')")
	}
	if configuration.Authentication == nil || configuration.Tls == nil {
		return nil, errors.New("(Parameter 'configuration')")
	}

	if snapshot == nil {
		return nil, errors.New("(Parameter 'snapshot')")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if configuration.Cell != "gru" {
		return nil, errors.New("The global cell directory service is GRU-only. (Parameter 'configuration')")
	}

	client, err := nats.Connect(configuration.Url,
		append([]nats.Option{
			nats.MaxReconnects(-1),
			nats.ReconnectWait(2 * time.Second),
			nats.Timeout(15 * time.Second),
		},
			append(configuration.Authentication.Options(), configuration.Tls.Options()...)...)...)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		client.Close()
		return nil, err
	}

	service := shared.NewNatsSvcServer(client, shared.NatsSvcConfig{
		Name:        "terrascale-global-cell-directory-gru",
		Version:     "1.0.0",
		Description: "TerraScale read-only global cell directory",
		Metadata:    map[string]string{"cell": "gru", "readOnly": "true"},
		QueueGroup:  "ts-orch-global-cell-directory",
	})

	err = service.AddEndpoint(shared.NatsSvcEndpointConfig{
		Name:    "cells",
		Subject: GlobalNatsTopologyCellDirectorySubject(),
		Metadata: map[string]string{
			"protocol": strconv.Itoa(protocol.ProtocolVersion.Current()),
			"readOnly": "true",
			"source":   GlobalNatsTopologyCellsBucket,
		},
		Handler: func(ctx context.Context, message *nats.Msg) error {
			observedAt := time.Now().UTC()
			identity, messageId, err := NewNatsMessageIdentity()
			if err != nil {
				return err
			}
			subject := GlobalNatsTopologyCellDirectorySubject()
			document, err := protocol.MarshalMessagingEnvelope(&protocol.MessagingEnvelope{
				SchemaVersion: protocol.MessagingSchemaVersionCurrent,
				MessageId:     messageId,
				Source: protocol.MessagingSource{
					Instance: "directory-service",
					Session:  identity,
					Cell:     "gru",
					Cluster:  "orchestrator-control-global",
				},
				Target: protocol.MessagingTargetScope{
					Namespace: protocol.NatsSubjectNamespaceGlobalDirectory,
					Subject:   subject,
				},
				PayloadType: "global-cell-directory-snapshot",
				ObservedAt:  observedAt,
			}, snapshot())
			if err != nil {
				return err
			}

			return message.Respond(document)
		},
	})
	if err != nil {
		service.Stop()
		client.Close()
		return nil, err
	}

	if err := service.Start(ctx); err != nil {
		service.Stop()
		client.Close()
		return nil, err
	}

	return &GlobalCellDirectoryServiceRuntime{client: client, service: service}, nil
}

// Dispose stops the service and closes the connection.
func (r *GlobalCellDirectoryServiceRuntime) Dispose() {
	if r == nil {
		return
	}
	if !atomic.CompareAndSwapInt32(&r.disposed, 0, 1) {
		return
	}

	if r.service != nil {
		r.service.Stop()
	}
	if r.client != nil {
		r.client.Close()
	}
}
