package app

import (
	"context"
	"errors"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// These handles are opened in root from its independently verified in-memory
// credentials. No ordinary controller pointer or private credential file enters.
type rootControllerSources struct {
	conn      *nats.Conn
	js        jetstream.JetStream
	specs     *specRegistry
	intents   *delivery.Service
	mutations *authority.Reader
	hosts     *host.Reader
	members   placement.MemberPinReader
}

func openRootControllerSources(ctx context.Context, cfg Config) (_ *rootControllerSources, resultErr error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil {
		return nil, errors.New("regional source readers require the live root runtime")
	}
	conn, err := rootsecret.ConnectControllerReader(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			conn.Close()
		}
	}()
	js, err := jetstream.New(conn)
	if err != nil {
		return nil, err
	}
	specs, policy, err := runtimeRegistryPolicy(ctx, cfg, js)
	if err != nil {
		return nil, err
	}
	intents, err := delivery.ConnectClient(ctx, delivery.Config{Conn: conn, JS: js, Cell: cfg.NATS.Cell,
		Verifier: policy.codec, Authorize: policy.authorizeIntent})
	if err != nil {
		return nil, err
	}
	mutations, err := authority.OpenReader(ctx, js, cfg.NATS.Cell)
	if err != nil {
		return nil, err
	}
	hosts, err := host.NewReader(ctx, host.ReaderConfig{Cell: cfg.NATS.Cell, Conn: conn, JS: js,
		StateReplicas: cfg.NATS.Replicas, HostMutations: mutations})
	if err != nil {
		return nil, err
	}
	members, err := placement.OpenMemberPinReader(ctx, js, cfg.NATS.Cell, cfg.NATS.Replicas)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || conn.IsClosed() {
		return nil, errors.New("root regional source connection ended during admission")
	}
	return &rootControllerSources{conn: conn, js: js, specs: specs, intents: intents,
		mutations: mutations, hosts: hosts, members: members}, nil
}
