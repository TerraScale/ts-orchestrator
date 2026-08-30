// Port of src/TerraScale.Orchestrator/Messaging/GlobalCellDirectoryServiceRuntime.cs.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
)

// GlobalCellDirectoryServiceRuntime mirrors the C# class: the read-only NATS
// service for the global cell projection with a distinct service identity.
type GlobalCellDirectoryServiceRuntime struct {
	client   *nats.Conn
	service  *natsSvcServer
	disposed int32
}

// GlobalCellDirectoryServiceRuntimeStartAsync mirrors the C# StartAsync.
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

	service := newNatsSvcServer(client, natsSvcConfig{
		Name:        "terrascale-global-cell-directory-gru",
		Version:     "1.0.0",
		Description: "TerraScale read-only global cell directory",
		Metadata:    map[string]string{"cell": "gru", "readOnly": "true"},
		QueueGroup:  "ts-orch-global-cell-directory",
	})

	err = service.AddEndpoint(natsSvcEndpointConfig{
		Name:    "cells",
		Subject: GlobalNatsTopologyCellDirectorySubject(),
		Metadata: map[string]string{
			"protocol": "1",
			"readOnly": "true",
			"source":   GlobalNatsTopologyCellsBucket,
		},
		Handler: func(ctx context.Context, message *nats.Msg) error {
			document, err := json.Marshal(snapshot())
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

// Dispose mirrors the C# DisposeAsync.
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
